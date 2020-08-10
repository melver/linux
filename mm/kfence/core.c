// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) "kfence: " fmt

#include <linux/atomic.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/kcsan-checks.h>
#include <linux/kfence.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/moduleparam.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>

#include <asm/kfence.h>

#include "kfence.h"

/* Disables KFENCE on the first warning assuming an irrecoverable error. */
// clang-format off
#define KFENCE_WARN_ON(cond)                                                   \
	({                                                                     \
		const bool __cond = WARN_ON(cond);                             \
		if (unlikely(__cond))                                          \
			WRITE_ONCE(kfence_enabled, false);                     \
		__cond;                                                        \
	})
// clang-format on

#ifndef CONFIG_KFENCE_FAULT_INJECTION /* Only defined with CONFIG_EXPERT. */
#define CONFIG_KFENCE_FAULT_INJECTION 0
#endif

/* === Data ================================================================= */

static unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;

#ifdef MODULE_PARAM_PREFIX
#undef MODULE_PARAM_PREFIX
#endif
#define MODULE_PARAM_PREFIX "kfence."
module_param_named(sample_interval, kfence_sample_interval, ulong,
		   IS_ENABLED(CONFIG_DEBUG_KERNEL) ? 0600 : 0400);

static bool kfence_enabled __read_mostly;

/*
 * The pool of pages used for guard pages and objects. If supported, allocated
 * statically, so that is_kfence_address() avoids a pointer load, and simply
 * compares against a constant address. Assume that if KFENCE is compiled into
 * the kernel, it is usually enabled, and the space is to be allocated one way
 * or another.
 */
#ifdef CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL
char __kfence_pool[KFENCE_POOL_SIZE] __aligned(KFENCE_POOL_ALIGNMENT);
#else
char *__kfence_pool __read_mostly;
#endif
EXPORT_SYMBOL(__kfence_pool); /* Export for test modules. */

/*
 * Per-object metadata, with one-to-one mapping of object metadata to
 * backing pages (in __kfence_pool).
 */
static_assert(CONFIG_KFENCE_NUM_OBJECTS > 0);
struct kfence_metadata kfence_metadata[CONFIG_KFENCE_NUM_OBJECTS];

/* Freelist with available objects. */
static struct list_head kfence_freelist = LIST_HEAD_INIT(kfence_freelist);
static DEFINE_RAW_SPINLOCK(kfence_freelist_lock); /* Lock protecting freelist. */

/* The static key to set up a KFENCE allocation. */
DEFINE_STATIC_KEY_FALSE(kfence_allocation_key);

/* Gates the allocation, ensuring only one succeeds in a given period. */
static atomic_t allocation_gate = ATOMIC_INIT(1);

/* Wait queue to wake up allocation-gate timer task. */
static DECLARE_WAIT_QUEUE_HEAD(allocation_wait);

/* Statistics counters for debugfs. */
enum kfence_counter_id {
	KFENCE_COUNTER_ALLOCATED,
	KFENCE_COUNTER_ALLOCS,
	KFENCE_COUNTER_FREES,
	KFENCE_COUNTER_BUGS,
	KFENCE_COUNTER_COUNT,
};
static atomic_long_t counters[KFENCE_COUNTER_COUNT];
// clang-format off
static const char *const counter_names[] = {
	[KFENCE_COUNTER_ALLOCATED]	= "currently allocated",
	[KFENCE_COUNTER_ALLOCS]		= "total allocations",
	[KFENCE_COUNTER_FREES]		= "total frees",
	[KFENCE_COUNTER_BUGS]		= "total bugs",
};
// clang-format on
static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);

/* === Internals ============================================================ */

static bool kfence_protect(unsigned long addr)
{
	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), true));
}

static bool kfence_unprotect(unsigned long addr)
{
	return !KFENCE_WARN_ON(!kfence_protect_page(ALIGN_DOWN(addr, PAGE_SIZE), false));
}

static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
{
	long index;

	/* The checks do not affect performance; only called from slow-paths. */

	if (!is_kfence_address((void *)addr))
		return NULL;

	/*
	 * May be an invalid index if called with an address at the edge of
	 * __kfence_pool, in which case we would report an "invalid access"
	 * error.
	 */
	index = ((addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2)) - 1;
	if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
		return NULL;

	return &kfence_metadata[index];
}

static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
{
	unsigned long offset = ((meta - kfence_metadata) + 1) * PAGE_SIZE * 2;
	unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];

	/* The checks do not affect performance; only called from slow-paths. */

	/* Only call with a pointer into kfence_metadata. */
	if (KFENCE_WARN_ON(meta < kfence_metadata ||
			   meta >= kfence_metadata + ARRAY_SIZE(kfence_metadata)))
		return 0;

	/*
	 * This metadata object only ever maps to 1 page; verify the calculation
	 * happens and that the stored address was not corrupted.
	 */
	if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
		return 0;

	return pageaddr;
}

/*
 * Update the object's metadata state, including updating the alloc/free stacks
 * depending on the state transition.
 */
static noinline void metadata_update_state(struct kfence_metadata *meta,
					   enum kfence_object_state next)
{
	unsigned long *entries = next == KFENCE_OBJECT_FREED ? meta->free_stack : meta->alloc_stack;
	/*
	 * Skip over 1 (this) functions; noinline ensures we do not accidentally
	 * skip over the caller by never inlining.
	 */
	const int nentries = stack_trace_save(entries, KFENCE_STACK_DEPTH, 1);

	lockdep_assert_held(&meta->lock);

	if (next == KFENCE_OBJECT_FREED)
		meta->num_free_stack = nentries;
	else
		meta->num_alloc_stack = nentries;

	/*
	 * Pairs with READ_ONCE() in
	 *	kfence_shutdown_cache(),
	 *	kfence_handle_page_fault().
	 */
	WRITE_ONCE(meta->state, next);
}

/* Write canary byte to @addr. */
static inline bool set_canary_byte(u8 *addr)
{
	*addr = KFENCE_CANARY_PATTERN(addr);
	return true;
}

/* Check canary byte at @addr. */
static inline bool check_canary_byte(u8 *addr)
{
	if (*addr == KFENCE_CANARY_PATTERN(addr))
		return true;

	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
	kfence_report_error((unsigned long)addr, addr_to_metadata((unsigned long)addr),
			    KFENCE_ERROR_CORRUPTION);
	return false;
}

static inline void for_each_canary(const struct kfence_metadata *meta, bool (*fn)(u8 *))
{
	const int size = abs(meta->size);
	unsigned long addr;

	lockdep_assert_held(&meta->lock);

	for (addr = ALIGN_DOWN(meta->addr, PAGE_SIZE); addr < meta->addr; addr++) {
		if (!fn((u8 *)addr))
			break;
	}

	for (addr = meta->addr + size; addr < PAGE_ALIGN(meta->addr); addr++) {
		if (!fn((u8 *)addr))
			break;
	}
}

static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t gfp)
{
	/*
	 * Note: for allocations made before RNG initialization, will always
	 * return zero. We still benefit from enabling KFENCE as early as
	 * possible, even when the RNG is not yet available, as this will allow
	 * KFENCE to detect bugs due to earlier allocations. The only downside
	 * is that the out-of-bounds accesses detected are deterministic for
	 * such allocations.
	 */
	const bool right = prandom_u32_max(2);
	unsigned long flags;
	struct kfence_metadata *meta = NULL;
	void *addr = NULL;

	/* Try to obtain a free object. */
	raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
	if (!list_empty(&kfence_freelist)) {
		meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
		list_del_init(&meta->list);
	}
	raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
	if (!meta)
		return NULL;

	if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
		/*
		 * This is extremely unlikely -- we are reporting on a
		 * use-after-free, which locked meta->lock, and the reporting
		 * code via printk calls kmalloc() which ends up in
		 * kfence_alloc() and tries to grab the same object that we're
		 * reporting on. While it has never been observed, lockdep does
		 * report that there is a possibility of deadlock. Fix it by
		 * using trylock and bailing out gracefully.
		 */
		raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
		/* Put the object back on the freelist. */
		list_add_tail(&meta->list, &kfence_freelist);
		raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);

		return NULL;
	}

	meta->addr = metadata_to_pageaddr(meta);
	/* Unprotect if we're reusing this page. */
	if (meta->state == KFENCE_OBJECT_FREED)
		kfence_unprotect(meta->addr);

	/* Calculate address for this allocation. */
	if (right)
		meta->addr += PAGE_SIZE - size;
	meta->addr = ALIGN_DOWN(meta->addr, cache->align);

	/* Update remaining metadata. */
	metadata_update_state(meta, KFENCE_OBJECT_ALLOCATED);
	/* Pairs with READ_ONCE() in kfence_shutdown_cache(). */
	WRITE_ONCE(meta->cache, cache);
	meta->size = right ? -size : size;
	for_each_canary(meta, set_canary_byte);
	virt_to_page(meta->addr)->slab_cache = cache;

	raw_spin_unlock_irqrestore(&meta->lock, flags);

	/* Memory initialization. */

	/*
	 * We check slab_want_init_on_alloc() ourselves, rather than letting
	 * SL*B do the initialization, as otherwise we might overwrite KFENCE's
	 * redzone.
	 */
	addr = (void *)meta->addr;
	if (unlikely(slab_want_init_on_alloc(gfp, cache)))
		memzero_explicit(addr, size);
	if (cache->ctor)
		cache->ctor(addr);

	if (CONFIG_KFENCE_FAULT_INJECTION && !prandom_u32_max(CONFIG_KFENCE_FAULT_INJECTION))
		kfence_protect(meta->addr); /* Random "faults" by protecting the object. */

	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCATED]);
	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCS]);

	return addr;
}

static void kfence_guarded_free(void *addr, struct kfence_metadata *meta)
{
	struct kcsan_scoped_access assert_page_exclusive;
	unsigned long flags;

	raw_spin_lock_irqsave(&meta->lock, flags);

	if (meta->state != KFENCE_OBJECT_ALLOCATED || meta->addr != (unsigned long)addr) {
		/* Invalid or double-free, bail out. */
		atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
		kfence_report_error((unsigned long)addr, meta, KFENCE_ERROR_INVALID_FREE);
		raw_spin_unlock_irqrestore(&meta->lock, flags);
		return;
	}

	/* Detect racy use-after-free, or incorrect reallocation of this page by KFENCE. */
	kcsan_begin_scoped_access((void *)ALIGN_DOWN((unsigned long)addr, PAGE_SIZE), PAGE_SIZE,
				  KCSAN_ACCESS_SCOPED | KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT,
				  &assert_page_exclusive);

	if (CONFIG_KFENCE_FAULT_INJECTION)
		kfence_unprotect((unsigned long)addr); /* To check canary bytes. */

	/* Restore page protection if there was an OOB access. */
	if (meta->unprotected_page) {
		kfence_protect(meta->unprotected_page);
		meta->unprotected_page = 0;
	}

	/* Check canary bytes for memory corruption. */
	for_each_canary(meta, check_canary_byte);

	/*
	 * Clear memory if init-on-free is set. While we protect the page, the
	 * data is still there, and after a use-after-free is detected, we
	 * unprotect the page, so the data is still accessible.
	 */
	if (unlikely(slab_want_init_on_free(meta->cache)))
		memzero_explicit(addr, abs(meta->size));

	/* Mark the object as freed. */
	metadata_update_state(meta, KFENCE_OBJECT_FREED);

	raw_spin_unlock_irqrestore(&meta->lock, flags);

	/* Protect to detect use-after-frees. */
	kfence_protect((unsigned long)addr);

	/* Add it to the tail of the freelist for reuse. */
	raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
	KFENCE_WARN_ON(!list_empty(&meta->list));
	list_add_tail(&meta->list, &kfence_freelist);
	kcsan_end_scoped_access(&assert_page_exclusive);
	raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);

	atomic_long_dec(&counters[KFENCE_COUNTER_ALLOCATED]);
	atomic_long_inc(&counters[KFENCE_COUNTER_FREES]);
}

static void rcu_guarded_free(struct rcu_head *h)
{
	struct kfence_metadata *meta = container_of(h, struct kfence_metadata, rcu_head);

	kfence_guarded_free((void *)meta->addr, meta);
}

static bool __init kfence_initialize_pool(void)
{
	unsigned long addr;
	struct page *pages;
	int i;

	if (!arch_kfence_initialize_pool())
		return false;

	addr = (unsigned long)__kfence_pool;
	pages = virt_to_page(addr);

	/*
	 * Set up non-redzone pages: they must have PG_slab set, to avoid
	 * freeing these as real pages.
	 *
	 * We also want to avoid inserting kfence_free() in the kfree()
	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
	 * enters __slab_free() slow-path.
	 */
	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
		if (!i || (i % 2))
			continue;

		__SetPageSlab(&pages[i]);
	}

	/*
	 * Protect the first 2 pages. The first page is mostly unnecessary, and
	 * merely serves as an extended guard page. However, adding one
	 * additional page in the beginning gives us an even number of pages,
	 * which simplifies the mapping of address to metadata index.
	 */
	for (i = 0; i < 2; i++) {
		if (unlikely(!kfence_protect(addr)))
			return false;

		addr += PAGE_SIZE;
	}

	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
		struct kfence_metadata *meta = &kfence_metadata[i];

		/* Initialize metadata. */
		INIT_LIST_HEAD(&meta->list);
		raw_spin_lock_init(&meta->lock);
		meta->state = KFENCE_OBJECT_UNUSED;
		meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
		list_add_tail(&meta->list, &kfence_freelist);

		/* Protect the right redzone. */
		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
			return false;

		addr += 2 * PAGE_SIZE;
	}

	return true;
}

/* === DebugFS Interface ==================================================== */

static int stats_show(struct seq_file *seq, void *v)
{
	int i;

	seq_printf(seq, "enabled: %i\n", READ_ONCE(kfence_enabled));
	for (i = 0; i < KFENCE_COUNTER_COUNT; i++)
		seq_printf(seq, "%s: %ld\n", counter_names[i], atomic_long_read(&counters[i]));

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(stats);

/*
 * debugfs seq_file operations for /sys/kernel/debug/kfence/objects.
 * start_object() and next_object() return the object index + 1, because NULL is used
 * to stop iteration.
 */
static void *start_object(struct seq_file *seq, loff_t *pos)
{
	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
		return (void *)((long)*pos + 1);
	return NULL;
}

static void stop_object(struct seq_file *seq, void *v)
{
}

static void *next_object(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	if (*pos < CONFIG_KFENCE_NUM_OBJECTS)
		return (void *)((long)*pos + 1);
	return NULL;
}

static int show_object(struct seq_file *seq, void *v)
{
	struct kfence_metadata *meta = &kfence_metadata[(long)v - 1];
	unsigned long flags;

	raw_spin_lock_irqsave(&meta->lock, flags);
	kfence_print_object(seq, meta);
	raw_spin_unlock_irqrestore(&meta->lock, flags);
	seq_puts(seq, "---------------------------------\n");

	return 0;
}

static const struct seq_operations object_seqops = {
	.start = start_object,
	.next = next_object,
	.stop = stop_object,
	.show = show_object,
};

static int open_objects(struct inode *inode, struct file *file)
{
	return seq_open(file, &object_seqops);
}

static const struct file_operations objects_fops = {
	.open = open_objects,
	.read = seq_read,
	.llseek = seq_lseek,
};

static int __init kfence_debugfs_init(void)
{
	struct dentry *kfence_dir = debugfs_create_dir("kfence", NULL);

	debugfs_create_file("stats", 0400, kfence_dir, NULL, &stats_fops);
	debugfs_create_file("objects", 0400, kfence_dir, NULL, &objects_fops);
	return 0;
}

late_initcall(kfence_debugfs_init);

/* === Allocation Gate Timer ================================================ */

/*
 * Set up delayed work, which will enable and disable the static key. We need to
 * use a work queue (rather than a simple timer), since enabling and disabling a
 * static key cannot be done from an interrupt.
 */
static struct delayed_work kfence_timer;
static void toggle_allocation_gate(struct work_struct *work)
{
	if (!READ_ONCE(kfence_enabled))
		return;

	/* Enable static key, and await allocation to happen. */
	atomic_set(&allocation_gate, 0);
	static_branch_enable(&kfence_allocation_key);
	wait_event(allocation_wait, atomic_read(&allocation_gate) != 0);

	/* Disable static key and reset timer. */
	static_branch_disable(&kfence_allocation_key);
	schedule_delayed_work(&kfence_timer, msecs_to_jiffies(kfence_sample_interval));
}
static DECLARE_DELAYED_WORK(kfence_timer, toggle_allocation_gate);

/* === Public interface ===================================================== */

void __init kfence_init(void)
{
	/* Setting kfence_sample_interval to 0 on boot disables KFENCE. */
	if (!kfence_sample_interval)
		return;

	if (!kfence_initialize_pool()) {
		pr_err("%s failed\n", __func__);
		return;
	}

	schedule_delayed_work(&kfence_timer, 0);
	WRITE_ONCE(kfence_enabled, true);
	pr_info("initialized - using %zu bytes for %d objects", KFENCE_POOL_SIZE,
		CONFIG_KFENCE_NUM_OBJECTS);
	if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
		pr_cont(" at 0x%px-0x%px\n", (void *)__kfence_pool,
			(void *)(__kfence_pool + KFENCE_POOL_SIZE));
	else
		pr_cont("\n");
}

bool kfence_shutdown_cache(struct kmem_cache *s)
{
	unsigned long flags;
	struct kfence_metadata *meta;
	int i;

	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
		bool in_use;

		meta = &kfence_metadata[i];

		/*
		 * If we observe some inconsistent cache and state pair where we
		 * should have returned false here, cache destruction is racing
		 * with either kmem_cache_alloc() or kmem_cache_free(). Taking
		 * the lock will not help, as different critical section
		 * serialization will have the same outcome.
		 */
		if (READ_ONCE(meta->cache) != s ||
		    READ_ONCE(meta->state) != KFENCE_OBJECT_ALLOCATED)
			continue;

		raw_spin_lock_irqsave(&meta->lock, flags);
		in_use = meta->cache == s && meta->state == KFENCE_OBJECT_ALLOCATED;
		raw_spin_unlock_irqrestore(&meta->lock, flags);

		if (in_use)
			return false;
	}

	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
		meta = &kfence_metadata[i];

		/* See above. */
		if (READ_ONCE(meta->cache) != s || READ_ONCE(meta->state) != KFENCE_OBJECT_FREED)
			continue;

		raw_spin_lock_irqsave(&meta->lock, flags);
		if (meta->cache == s && meta->state == KFENCE_OBJECT_FREED)
			meta->cache = NULL;
		raw_spin_unlock_irqrestore(&meta->lock, flags);
	}

	return true;
}

void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
{
	/*
	 * allocation_gate only needs to become non-zero, so it doesn't make
	 * sense to continue writing to it and pay the associated contention
	 * cost, in case we have a large number of concurrent allocations.
	 */
	if (atomic_read(&allocation_gate) || atomic_inc_return(&allocation_gate) > 1)
		return NULL;
	wake_up(&allocation_wait);

	if (!READ_ONCE(kfence_enabled))
		return NULL;

	if (size > PAGE_SIZE)
		return NULL;

	return kfence_guarded_alloc(s, size, flags);
}

size_t kfence_ksize(const void *addr)
{
	const struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);

	/*
	 * Read locklessly -- if there is a race with __kfence_alloc(), this
	 * most certainly is either a use-after-free, or invalid access.
	 */
	return meta ? abs(meta->size) : 0;
}

void *kfence_object_start(const void *addr)
{
	const struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);

	/*
	 * Read locklessly -- if there is a race with __kfence_alloc(), this
	 * most certainly is either a use-after-free, or invalid access.
	 */
	return meta ? (void *)meta->addr : NULL;
}

void __kfence_free(void *addr)
{
	struct kfence_metadata *meta = addr_to_metadata((unsigned long)addr);

	if (unlikely(meta->cache->flags & SLAB_TYPESAFE_BY_RCU))
		call_rcu(&meta->rcu_head, rcu_guarded_free);
	else
		kfence_guarded_free(addr, meta);
}

bool kfence_handle_page_fault(unsigned long addr)
{
	const int page_index = (addr - (unsigned long)__kfence_pool) / PAGE_SIZE;
	struct kfence_metadata *to_report = NULL;
	enum kfence_error_type error_type;
	unsigned long flags;

	if (!is_kfence_address((void *)addr))
		return false;

	if (!READ_ONCE(kfence_enabled)) /* If disabled at runtime ... */
		return kfence_unprotect(addr); /* ... unprotect and proceed. */

	atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);

	if (page_index % 2) {
		/* This is a redzone, report a buffer overflow. */
		struct kfence_metadata *meta = NULL;
		int distance = 0;

		meta = addr_to_metadata(addr - PAGE_SIZE);
		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
			to_report = meta;
			/* Data race ok; distance calculation approximate. */
			distance = addr - data_race(meta->addr + abs(meta->size));
		}

		meta = addr_to_metadata(addr + PAGE_SIZE);
		if (meta && READ_ONCE(meta->state) == KFENCE_OBJECT_ALLOCATED) {
			/* Data race ok; distance calculation approximate. */
			if (!to_report || distance > data_race(meta->addr) - addr)
				to_report = meta;
		}

		if (!to_report)
			goto out;

		raw_spin_lock_irqsave(&to_report->lock, flags);
		to_report->unprotected_page = addr;
		error_type = KFENCE_ERROR_OOB;

		/*
		 * If the object was freed before we took the look we can still
		 * report this as an OOB -- the report will simply show the
		 * stacktrace of the free as well.
		 */
	} else {
		to_report = addr_to_metadata(addr);
		if (!to_report)
			goto out;

		raw_spin_lock_irqsave(&to_report->lock, flags);
		error_type = KFENCE_ERROR_UAF;
		/*
		 * We may race with __kfence_alloc(), and it is possible that a
		 * freed object may be reallocated. We simply report this as a
		 * use-after-free, with the stack trace showing the place where
		 * the object was re-allocated.
		 */
	}

out:
	if (to_report) {
		kfence_report_error(addr, to_report, error_type);
		raw_spin_unlock_irqrestore(&to_report->lock, flags);
	} else {
		/* This may be a UAF or OOB access, but we can't be sure. */
		kfence_report_error(addr, NULL, KFENCE_ERROR_INVALID);
	}

	return kfence_unprotect(addr); /* Unprotect and let access proceed. */
}

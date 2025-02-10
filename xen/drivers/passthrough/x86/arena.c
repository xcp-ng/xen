/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Simple arena-based page allocator.
 *
 * Allocate a large block using alloc_domheam_pages and allocate single pages
 * using iommu_arena_allocate_page and iommu_arena_free_page functions.
 *
 * Concurrent {allocate/free}_page is thread-safe
 * iommu_arena_teardown during {allocate/free}_page is not thread-safe.
 *
 * Written by Teddy Astie <teddy.astie@vates.tech>
 */

#include <asm/bitops.h>
#include <asm/page.h>
#include <xen/atomic.h>
#include <xen/bug.h>
#include <xen/config.h>
#include <xen/mm-frame.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>

#include <asm/arena.h>

/* Maximum of scan tries if the bit found not available */
#define ARENA_TSL_MAX_TRIES 5

int iommu_arena_initialize(struct iommu_arena *arena, struct domain *d,
                           unsigned int order, unsigned int memflags)
{
    struct page_info *page;

    /* TODO: Maybe allocate differently ? */
    page = alloc_domheap_pages(d, order, memflags);

    if ( !page )
        return -ENOMEM;

    arena->map = xzalloc_array(unsigned long, BITS_TO_LONGS(1LLU << order));
    arena->order = order;
    arena->region_start = page_to_mfn(page);

    _atomic_set(&arena->used_pages, 0);
    bitmap_zero(arena->map, iommu_arena_size(arena));

    printk(XENLOG_DEBUG "IOMMU: Allocated arena (%llu pages, start=%"PRI_mfn")\n",
           iommu_arena_size(arena), mfn_x(arena->region_start));
    return 0;
}

int iommu_arena_teardown(struct iommu_arena *arena, bool check)
{
    BUG_ON(mfn_x(arena->region_start) == 0);

    /* Check for allocations if check is specified */
    if ( check && (atomic_read(&arena->used_pages) > 0) )
        return -EBUSY;

    free_domheap_pages(mfn_to_page(arena->region_start), arena->order);

    arena->region_start = _mfn(0);
    _atomic_set(&arena->used_pages, 0);
    xfree(arena->map);
    arena->map = NULL;

    return 0;
}

struct page_info *iommu_arena_allocate_page(struct iommu_arena *arena)
{
    unsigned int index;
    unsigned int tsl_tries = 0;

    BUG_ON(mfn_x(arena->region_start) == 0);

    if ( atomic_read(&arena->used_pages) == iommu_arena_size(arena) )
        /* All pages used */
        return NULL;

    do
    {
        index = find_first_zero_bit(arena->map, iommu_arena_size(arena));

        if ( index >= iommu_arena_size(arena) )
            /* No more free pages */
            return NULL;

        /*
         * While there shouldn't be a lot of retries in practice, this loop
         * *may* run indefinetly if the found bit is never free due to being
         * overwriten by another CPU core right after. Add a safeguard for
         * such very rare cases.
         */
        tsl_tries++;

        if ( unlikely(tsl_tries == ARENA_TSL_MAX_TRIES) )
        {
            printk(XENLOG_ERR "ARENA: Too many TSL retries !");
            return NULL;
        }

        /* Make sure that the bit we found is still free */
    } while ( test_and_set_bit(index, arena->map) );

    atomic_inc(&arena->used_pages);

    return mfn_to_page(mfn_add(arena->region_start, index));
}

bool iommu_arena_free_page(struct iommu_arena *arena, struct page_info *page)
{
    unsigned long index;
    mfn_t frame;

    if ( !page )
    {
        printk(XENLOG_WARNING "IOMMU: Trying to free NULL page");
        WARN();
        return false;
    }

    frame = page_to_mfn(page);

    /* Check if page belongs to our arena */
    if ( (mfn_x(frame) < mfn_x(arena->region_start))
        || (mfn_x(frame) >= (mfn_x(arena->region_start) + iommu_arena_size(arena))) )
    {
        printk(XENLOG_WARNING
               "IOMMU: Trying to free outside arena region [mfn=%"PRI_mfn"]",
               mfn_x(frame));
        WARN();
        return false;
    }

    index = mfn_x(frame) - mfn_x(arena->region_start);

    /* Sanity check in case of underflow. */
    ASSERT(index < iommu_arena_size(arena));

    if ( !test_and_clear_bit(index, arena->map) )
    {
        /*
         * Bit was free during our arena_free_page, which means that
         * either this page was never allocated, or we are in a double-free
         * situation.
         */
        printk(XENLOG_WARNING
               "IOMMU: Freeing non-allocated region (double-free?) [mfn=%"PRI_mfn"]",
               mfn_x(frame));
        WARN();
        return false;
    }

    atomic_dec(&arena->used_pages);

    return true;
}
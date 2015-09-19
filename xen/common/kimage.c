/*
 * Kexec Image
 *
 * Copyright (C) 2013 Citrix Systems R&D Ltd.
 *
 * Derived from kernel/kexec.c from Linux:
 *
 *   Copyright (C) 2002-2004 Eric Biederman  <ebiederm@xmission.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#include <xen/types.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/errno.h>
#include <xen/spinlock.h>
#include <xen/guest_access.h>
#include <xen/mm.h>
#include <xen/kexec.h>
#include <xen/x86-linux.h>
#include <xen/kimage.h>
#include <xen/elfstructs.h>
#include <xen/sha2.h>
#include <xen/lib.h>

#include <asm/page.h>

#define KIMAGE_SHA256_REGIONS 16

typedef struct
{
    uint64_t start;
    uint64_t len;
}
sha256_region_t;

/*
 * When kexec transitions to the new kernel there is a one-to-one
 * mapping between physical and virtual addresses.  On processors
 * where you can disable the MMU this is trivial, and easy.  For
 * others it is still a simple predictable page table to setup.
 *
 * The code for the transition from the current kernel to the the new
 * kernel is placed in the page-size control_code_buffer.  This memory
 * must be identity mapped in the transition from virtual to physical
 * addresses.
 *
 * The assembly stub in the control code buffer is passed a linked list
 * of descriptor pages detailing the source pages of the new kernel,
 * and the destination addresses of those source pages.  As this data
 * structure is not used in the context of the current OS, it must
 * be self-contained.
 *
 * The code has been made to work with highmem pages and will use a
 * destination page in its final resting place (if it happens
 * to allocate it).  The end product of this is that most of the
 * physical address space, and most of RAM can be used.
 *
 * Future directions include:
 *  - allocating a page table with the control code buffer identity
 *    mapped, to simplify machine_kexec and make kexec_on_panic more
 *    reliable.
 */

/*
 * KIMAGE_NO_DEST is an impossible destination address..., for
 * allocating pages whose destination address we do not care about.
 */
#define KIMAGE_NO_DEST (-1UL)

/*
 * Offset of the last entry in an indirection page.
 */
#define KIMAGE_LAST_ENTRY (PAGE_SIZE/sizeof(kimage_entry_t) - 1)


static int kimage_is_destination_range(struct kexec_image *image,
                                       paddr_t start, paddr_t end);
static struct page_info *kimage_alloc_page(struct kexec_image *image,
                                           paddr_t dest);

static struct page_info *kimage_alloc_zeroed_page(unsigned memflags)
{
    struct page_info *page;

    page = alloc_domheap_page(NULL, memflags);
    if ( !page )
        return NULL;

    clear_domain_page(page_to_mfn(page));

    return page;
}

static int do_kimage_alloc(struct kexec_image **rimage, paddr_t entry,
                           unsigned long nr_segments,
                           struct kimage_segment *segments, uint8_t type)
{
    struct kexec_image *image;
    unsigned long i;
    int result;

    /* Allocate a controlling structure */
    result = -ENOMEM;
    image = xzalloc(typeof(*image));
    if ( !image )
        goto out;

    image->entry_maddr = entry;
    image->type = type;
    image->nr_segments = nr_segments;
    image->segments = segments;

    image->next_crash_page = kexec_crash_area.start;

    INIT_PAGE_LIST_HEAD(&image->control_pages);
    INIT_PAGE_LIST_HEAD(&image->dest_pages);
    INIT_PAGE_LIST_HEAD(&image->unusable_pages);

    /*
     * Verify our destination addresses do not overlap.  If we allowed
     * overlapping destination addresses through very weird things can
     * happen with no easy explanation as one segment stops on
     * another.
     */
    result = -EINVAL;
    for ( i = 0; i < nr_segments; i++ )
    {
        paddr_t mstart, mend;
        unsigned long j;

        mstart = image->segments[i].dest_maddr;
        mend   = mstart + image->segments[i].dest_size;
        for (j = 0; j < i; j++ )
        {
            paddr_t pstart, pend;
            pstart = image->segments[j].dest_maddr;
            pend   = pstart + image->segments[j].dest_size;
            /* Do the segments overlap? */
            if ( (mend > pstart) && (mstart < pend) )
                goto out;
        }
    }

    /*
     * Ensure our buffer sizes are strictly less than our memory
     * sizes.  This should always be the case, and it is easier to
     * check up front than to be surprised later on.
     */
    result = -EINVAL;
    for ( i = 0; i < nr_segments; i++ )
    {
        if ( image->segments[i].buf_size > image->segments[i].dest_size )
            goto out;
    }

    /* 
     * Page for the relocation code must still be accessible after the
     * processor has switched to 32-bit mode.
     */
    result = -ENOMEM;
    image->control_code_page = kimage_alloc_control_page(image, MEMF_bits(32));
    if ( !image->control_code_page )
        goto out;
    result = machine_kexec_add_page(image,
                                    page_to_maddr(image->control_code_page),
                                    page_to_maddr(image->control_code_page));
    if ( result < 0 )
        goto out;

    /* Add an empty indirection page. */
    result = -ENOMEM;
    image->entry_page = kimage_alloc_control_page(image, 0);
    if ( !image->entry_page )
        goto out;
    result = machine_kexec_add_page(image, page_to_maddr(image->entry_page),
                                    page_to_maddr(image->entry_page));
    if ( result < 0 )
        goto out;

    image->head = page_to_maddr(image->entry_page);

    result = 0;
out:
    if ( result == 0 )
        *rimage = image;
    else if ( image )
    {
        image->segments = NULL; /* caller frees segments after an error */
        kimage_free(image);
    }

    return result;

}

static int kimage_normal_alloc(struct kexec_image **rimage, paddr_t entry,
                               unsigned long nr_segments,
                               struct kimage_segment *segments)
{
    return do_kimage_alloc(rimage, entry, nr_segments, segments,
                           KEXEC_TYPE_DEFAULT);
}

static int do_kimage_crash_alloc(struct kexec_image **rimage, paddr_t entry,
                                 unsigned long nr_segments,
                                 struct kimage_segment *segments)
{
    unsigned long i;

    /*
     * Verify we have good destination addresses.  Normally
     * the caller is responsible for making certain we don't
     * attempt to load the new image into invalid or reserved
     * areas of RAM.  But crash kernels are preloaded into a
     * reserved area of ram.  We must ensure the addresses
     * are in the reserved area otherwise preloading the
     * kernel could corrupt things.
     */
    for ( i = 0; i < nr_segments; i++ )
    {
        paddr_t mstart, mend;

        if ( guest_handle_is_null(segments[i].buf.h) )
            continue;

        mstart = segments[i].dest_maddr;
        mend = mstart + segments[i].dest_size;
        /* Ensure we are within the crash kernel limits. */
        if ( (mstart < kexec_crash_area.start )
             || (mend > kexec_crash_area.start + kexec_crash_area.size))
            return -EADDRNOTAVAIL;
    }

    /* Allocate and initialize a controlling structure. */
    return do_kimage_alloc(rimage, entry, nr_segments, segments,
                           KEXEC_TYPE_CRASH);
}

static int kimage_crash_alloc(struct kexec_image **rimage, paddr_t entry,
                              unsigned long nr_segments,
                              struct kimage_segment *segments)
{
    /* Verify we have a valid entry point */
    if ( (entry < kexec_crash_area.start)
         || (entry > kexec_crash_area.start + kexec_crash_area.size))
        return -EADDRNOTAVAIL;

    return do_kimage_crash_alloc(rimage, entry, nr_segments, segments);
}

static int kimage_crash_alloc_efi(struct kexec_image **rimage, paddr_t entry,
                                  unsigned long nr_segments,
                                  struct kimage_segment *segments)
{
    return do_kimage_crash_alloc(rimage, entry, nr_segments, segments);
}

static int kimage_is_destination_range(struct kexec_image *image,
                                       paddr_t start,
                                       paddr_t end)
{
    unsigned long i;

    for ( i = 0; i < image->nr_segments; i++ )
    {
        paddr_t mstart, mend;

        mstart = image->segments[i].dest_maddr;
        mend = mstart + image->segments[i].dest_size;
        if ( (end > mstart) && (start < mend) )
            return 1;
    }

    return 0;
}

static void kimage_free_page_list(struct page_list_head *list)
{
    struct page_info *page, *next;

    page_list_for_each_safe(page, next, list)
    {
        page_list_del(page, list);
        free_domheap_page(page);
    }
}

static struct page_info *kimage_alloc_normal_control_page(
    struct kexec_image *image, unsigned memflags)
{
    /*
     * Control pages are special, they are the intermediaries that are
     * needed while we copy the rest of the pages to their final
     * resting place.  As such they must not conflict with either the
     * destination addresses or memory the kernel is already using.
     *
     * The only case where we really need more than one of these are
     * for architectures where we cannot disable the MMU and must
     * instead generate an identity mapped page table for all of the
     * memory.
     *
     * At worst this runs in O(N) of the image size.
     */
    struct page_list_head extra_pages;
    struct page_info *page = NULL;

    INIT_PAGE_LIST_HEAD(&extra_pages);

    /*
     * Loop while I can allocate a page and the page allocated is a
     * destination page.
     */
    do {
        paddr_t addr, eaddr;

        page = kimage_alloc_zeroed_page(memflags);
        if ( !page )
            break;
        addr  = page_to_maddr(page);
        eaddr = addr + PAGE_SIZE;
        if ( kimage_is_destination_range(image, addr, eaddr) )
        {
            page_list_add(page, &extra_pages);
            page = NULL;
        }
    } while ( !page );

    if ( page )
    {
        /* Remember the allocated page... */
        page_list_add(page, &image->control_pages);

        /*
         * Because the page is already in it's destination location we
         * will never allocate another page at that address.
         * Therefore kimage_alloc_page will not return it (again) and
         * we don't need to give it an entry in image->segments[].
         */
    }
    /*
     * Deal with the destination pages I have inadvertently allocated.
     *
     * Ideally I would convert multi-page allocations into single page
     * allocations, and add everything to image->dest_pages.
     *
     * For now it is simpler to just free the pages.
     */
    kimage_free_page_list(&extra_pages);

    return page;
}

static struct page_info *kimage_alloc_crash_control_page(struct kexec_image *image)
{
    /*
     * Control pages are special, they are the intermediaries that are
     * needed while we copy the rest of the pages to their final
     * resting place.  As such they must not conflict with either the
     * destination addresses or memory the kernel is already using.
     *
     * Control pages are also the only pags we must allocate when
     * loading a crash kernel.  All of the other pages are specified
     * by the segments and we just memcpy into them directly.
     *
     * The only case where we really need more than one of these are
     * for architectures where we cannot disable the MMU and must
     * instead generate an identity mapped page table for all of the
     * memory.
     *
     * Given the low demand this implements a very simple allocator
     * that finds the first hole of the appropriate size in the
     * reserved memory region, and allocates all of the memory up to
     * and including the hole.
     */
    paddr_t hole_start, hole_end;
    struct page_info *page = NULL;

    hole_start = PAGE_ALIGN(image->next_crash_page);
    hole_end   = hole_start + PAGE_SIZE;
    while ( hole_end <= kexec_crash_area.start + kexec_crash_area.size )
    {
        unsigned long i;

        /* See if I overlap any of the segments. */
        for ( i = 0; i < image->nr_segments; i++ )
        {
            paddr_t mstart, mend;

            mstart = image->segments[i].dest_maddr;
            mend   = mstart + image->segments[i].dest_size;
            if ( (hole_end > mstart) && (hole_start < mend) )
            {
                /* Advance the hole to the end of the segment. */
                hole_start = PAGE_ALIGN(mend);
                hole_end   = hole_start + PAGE_SIZE;
                break;
            }
        }
        /* If I don't overlap any segments I have found my hole! */
        if ( i == image->nr_segments )
        {
            page = maddr_to_page(hole_start);
            break;
        }
    }
    if ( page )
    {
        image->next_crash_page = hole_end;
        clear_domain_page(page_to_mfn(page));
    }

    return page;
}


struct page_info *kimage_alloc_control_page(struct kexec_image *image,
                                            unsigned memflags)
{
    struct page_info *pages = NULL;

    switch ( image->type )
    {
    case KEXEC_TYPE_DEFAULT:
        pages = kimage_alloc_normal_control_page(image, memflags);
        break;
    case KEXEC_TYPE_CRASH:
        pages = kimage_alloc_crash_control_page(image);
        break;
    }
    return pages;
}

static int kimage_add_entry(struct kexec_image *image, kimage_entry_t entry)
{
    kimage_entry_t *entries;

    if ( image->next_entry == KIMAGE_LAST_ENTRY )
    {
        struct page_info *page;

        page = kimage_alloc_page(image, KIMAGE_NO_DEST);
        if ( !page )
            return -ENOMEM;

        entries = __map_domain_page(image->entry_page);
        entries[image->next_entry] = page_to_maddr(page) | IND_INDIRECTION;
        unmap_domain_page(entries);

        image->entry_page = page;
        image->next_entry = 0;
    }

    entries = __map_domain_page(image->entry_page);
    entries[image->next_entry] = entry;
    image->next_entry++;
    unmap_domain_page(entries);

    return 0;
}

static int kimage_set_destination(struct kexec_image *image,
                                  paddr_t destination)
{
    return kimage_add_entry(image, (destination & PAGE_MASK) | IND_DESTINATION);
}


static int kimage_add_page(struct kexec_image *image, paddr_t maddr)
{
    return kimage_add_entry(image, (maddr & PAGE_MASK) | IND_SOURCE);
}


static void kimage_free_extra_pages(struct kexec_image *image)
{
    kimage_free_page_list(&image->dest_pages);
    kimage_free_page_list(&image->unusable_pages);
}

void kimage_terminate(struct kexec_image *image)
{
    kimage_entry_t *entries;

    entries = __map_domain_page(image->entry_page);
    entries[image->next_entry] = IND_DONE;
    unmap_domain_page(entries);
}

/*
 * Iterate over all the entries in the indirection pages.
 *
 * Call unmap_domain_page(ptr) after the loop exits.
 */
#define for_each_kimage_entry(image, ptr, entry)                        \
    for ( ptr = map_domain_page(_mfn(paddr_to_pfn(image->head)));       \
          (entry = *ptr) && !(entry & IND_DONE);                        \
          ptr = (entry & IND_INDIRECTION) ?                             \
              (unmap_domain_page(ptr), map_domain_page(_mfn(paddr_to_pfn(entry)))) \
              : ptr + 1 )

static void kimage_free_entry(kimage_entry_t entry)
{
    struct page_info *page;

    page = maddr_to_page(entry);
    free_domheap_page(page);
}

static void kimage_free_all_entries(struct kexec_image *image)
{
    kimage_entry_t *ptr, entry;
    kimage_entry_t ind = 0;

    if ( !image->head )
        return;

    for_each_kimage_entry(image, ptr, entry)
    {
        if ( entry & IND_INDIRECTION )
        {
            /* Free the previous indirection page */
            if ( ind & IND_INDIRECTION )
                kimage_free_entry(ind);
            /* Save this indirection page until we are done with it. */
            ind = entry;
        }
        else if ( entry & IND_SOURCE )
            kimage_free_entry(entry);
    }
    unmap_domain_page(ptr);

    /* Free the final indirection page. */
    if ( ind & IND_INDIRECTION )
        kimage_free_entry(ind);
}

void kimage_free(struct kexec_image *image)
{
    if ( !image )
        return;

    kimage_free_extra_pages(image);
    kimage_free_all_entries(image);
    kimage_free_page_list(&image->control_pages);
    xfree(image->segments);
    xfree(image->pi.buffer);
    xfree(image->pi.sechdrs);
    xfree(image);
}

static kimage_entry_t *kimage_dst_used(struct kexec_image *image,
                                       paddr_t maddr)
{
    kimage_entry_t *ptr, entry;
    unsigned long destination = 0;

    for_each_kimage_entry(image, ptr, entry)
    {
        if ( entry & IND_DESTINATION )
            destination = entry & PAGE_MASK;
        else if ( entry & IND_SOURCE )
        {
            if ( maddr == destination )
                return ptr;
            destination += PAGE_SIZE;
        }
    }
    unmap_domain_page(ptr);

    return NULL;
}

static struct page_info *kimage_alloc_page(struct kexec_image *image,
                                           paddr_t destination)
{
    /*
     * Here we implement safeguards to ensure that a source page is
     * not copied to its destination page before the data on the
     * destination page is no longer useful.
     *
     * To do this we maintain the invariant that a source page is
     * either its own destination page, or it is not a destination
     * page at all.
     *
     * That is slightly stronger than required, but the proof that no
     * problems will not occur is trivial, and the implementation is
     * simply to verify.
     *
     * When allocating all pages normally this algorithm will run in
     * O(N) time, but in the worst case it will run in O(N^2) time.
     * If the runtime is a problem the data structures can be fixed.
     */
    struct page_info *page;
    paddr_t addr;
    int ret;

    /*
     * Walk through the list of destination pages, and see if I have a
     * match.
     */
    page_list_for_each(page, &image->dest_pages)
    {
        addr = page_to_maddr(page);
        if ( addr == destination )
        {
            page_list_del(page, &image->dest_pages);
            goto found;
        }
    }
    page = NULL;
    for (;;)
    {
        kimage_entry_t *old;

        /* Allocate a page, if we run out of memory give up. */
        page = kimage_alloc_zeroed_page(0);
        if ( !page )
            return NULL;
        addr = page_to_maddr(page);

        /* If it is the destination page we want use it. */
        if ( addr == destination )
            break;

        /* If the page is not a destination page use it. */
        if ( !kimage_is_destination_range(image, addr,
                                          addr + PAGE_SIZE) )
            break;

        /*
         * I know that the page is someones destination page.  See if
         * there is already a source page for this destination page.
         * And if so swap the source pages.
         */
        old = kimage_dst_used(image, addr);
        if ( old )
        {
            /* If so move it. */
            mfn_t old_mfn = maddr_to_mfn(*old);
            mfn_t mfn = maddr_to_mfn(addr);

            copy_domain_page(mfn, old_mfn);
            clear_domain_page(old_mfn);
            *old = (addr & ~PAGE_MASK) | IND_SOURCE;
            unmap_domain_page(old);

            page = mfn_to_page(old_mfn);
            break;
        }
        else
        {
            /*
             * Place the page on the destination list; I will use it
             * later.
             */
            page_list_add(page, &image->dest_pages);
        }
    }
found:
    ret = machine_kexec_add_page(image, page_to_maddr(page),
                                 page_to_maddr(page));
    if ( ret < 0 )
    {
        free_domheap_page(page);
        return NULL;
    }
    return page;
}

static int kimage_load_normal_segment(struct kexec_image *image,
                                      struct kimage_segment *segment)
{
    unsigned long to_copy;
    unsigned long src_offset;
    unsigned int dest_offset;
    paddr_t dest, end;
    int ret;

    to_copy = segment->buf_size;
    src_offset = 0;
    dest = segment->dest_maddr;
    dest_offset = segment->dest_offset;

    ret = kimage_set_destination(image, dest);
    if ( ret < 0 )
        return ret;

    while ( to_copy )
    {
        unsigned long dest_mfn;
        struct page_info *page;
        void *dest_va;
        size_t size;

        dest_mfn = dest >> PAGE_SHIFT;

        size = min_t(unsigned long, PAGE_SIZE - dest_offset, to_copy);

        page = kimage_alloc_page(image, dest);
        if ( !page )
            return -ENOMEM;
        ret = kimage_add_page(image, page_to_maddr(page));
        if ( ret < 0 )
            return ret;

        dest_va = __map_domain_page(page);
        ret = copy_from_guest_offset(dest_va + dest_offset, segment->buf.h, src_offset, size);
        unmap_domain_page(dest_va);
        if ( ret )
            return -EFAULT;

        to_copy -= size;
        src_offset += size;
        dest += PAGE_SIZE;
        dest_offset = 0;
    }

    /* Remainder of the destination should be zeroed. */
    end = segment->dest_maddr + segment->dest_size;
    for ( ; dest < end; dest += PAGE_SIZE )
        kimage_add_entry(image, IND_ZERO);

    return 0;
}

static int kimage_load_crash_segment(struct kexec_image *image,
                                     struct kimage_segment *segment)
{
    /*
     * For crash dumps kernels we simply copy the data from user space
     * to it's destination.
     */
    paddr_t dest;
    unsigned long sbytes, dbytes;
    unsigned int dest_offset;
    int ret = 0;
    unsigned long src_offset = 0;

    sbytes = segment->buf_size;
    dbytes = segment->dest_size;
    dest = segment->dest_maddr;
    dest_offset = segment->dest_offset;

    while ( dbytes )
    {
        unsigned long dest_mfn;
        void *dest_va;
        size_t schunk, dchunk;

        dest_mfn = dest >> PAGE_SHIFT;

        dchunk = PAGE_SIZE - dest_offset;
        schunk = min(dchunk, sbytes);

        dest_va = map_domain_page(_mfn(dest_mfn));
        if ( !dest_va )
            return -EINVAL;

        if ( dest_offset )
            memset(dest_va, 0, dest_offset);
        ret = copy_from_guest_offset(dest_va + dest_offset, segment->buf.h,
                                     src_offset, schunk);
        memset(dest_va + schunk, 0, dchunk - schunk);

        unmap_domain_page(dest_va);
        if ( ret )
            return -EFAULT;

        dbytes -= dchunk + dest_offset;
        sbytes -= schunk;
        dest += dchunk + dest_offset;
        src_offset += schunk;
        dest_offset = 0;
    }

    return 0;
}

static int kimage_load_segment(struct kexec_image *image,
                               struct kimage_segment *segment)
{
    int result = -ENOMEM;
    paddr_t addr;

    if ( !guest_handle_is_null(segment->buf.h) )
    {
        switch ( image->type )
        {
        case KEXEC_TYPE_DEFAULT:
            result = kimage_load_normal_segment(image, segment);
            break;
        case KEXEC_TYPE_CRASH:
            result = kimage_load_crash_segment(image, segment);
            break;
        }
    }

    for ( addr = segment->dest_maddr & PAGE_MASK;
          addr < segment->dest_maddr + segment->dest_size; addr += PAGE_SIZE )
    {
        result = machine_kexec_add_page(image, addr, addr);
        if ( result < 0 )
            break;
    }

    return result;
}

int kimage_alloc(struct kexec_image **rimage, uint8_t type, uint16_t arch,
                 uint64_t entry_maddr,
                     uint32_t nr_segments, struct kimage_segment *segment)
{
    int result;
    unsigned int i;

    for ( i = 0; i < nr_segments; i++ )
    {
        paddr_t mend;

        /*
         * Stash the destination offset-in-page for use when copying the
         * buffer later.
         */
        segment[i].dest_offset = PAGE_OFFSET(segment[i].dest_maddr);

        /*
         * Align down the start address to page size and align up the end
         * address to page size.
         */
        mend = segment[i].dest_maddr + segment[i].dest_size;
        segment[i].dest_maddr &= PAGE_MASK;
        segment[i].dest_size = ROUNDUP(mend, PAGE_SIZE) - segment[i].dest_maddr;
    }

    switch( type )
    {
    case KEXEC_TYPE_DEFAULT:
    case KEXEC_TYPE_DEFAULT_EFI:
        result = kimage_normal_alloc(rimage, entry_maddr, nr_segments, segment);
        break;
    case KEXEC_TYPE_CRASH:
        result = kimage_crash_alloc(rimage, entry_maddr, nr_segments, segment);
        break;
    case KEXEC_TYPE_CRASH_EFI:
        result = kimage_crash_alloc_efi(rimage, entry_maddr,
                                        nr_segments, segment);
        break;
    default:
        result = -EINVAL;
        break;
    }
    if ( result < 0 )
        return result;

    (*rimage)->arch = arch;

    return result;
}

int kimage_load_segments(struct kexec_image *image)
{
    int s;
    int result;

    for ( s = 0; s < image->nr_segments; s++ ) {
        result = kimage_load_segment(image, &image->segments[s]);
        if ( result < 0 )
            return result;
    }
    return 0;
}

kimage_entry_t *kimage_entry_next(kimage_entry_t *entry, bool compat)
{
    if ( compat )
        return (kimage_entry_t *)((uint32_t *)entry + 1);
    return entry + 1;
}

mfn_t kimage_entry_mfn(kimage_entry_t *entry, bool compat)
{
    if ( compat )
        return maddr_to_mfn(*(uint32_t *)entry);
    return maddr_to_mfn(*entry);
}

unsigned long kimage_entry_ind(kimage_entry_t *entry, bool compat)
{
    if ( compat )
        return *(uint32_t *)entry & 0xf;
    return *entry & 0xf;
}

int kimage_build_ind(struct kexec_image *image, mfn_t ind_mfn,
                     bool compat)
{
    void *page;
    kimage_entry_t *entry;
    int ret = 0;
    paddr_t dest = KIMAGE_NO_DEST;

    page = map_domain_page(ind_mfn);
    if ( !page )
        return -ENOMEM;

    /*
     * Walk the guest-supplied indirection pages, adding entries to
     * the image's indirection pages.
     */
    for ( entry = page; ;  )
    {
        unsigned long ind;
        mfn_t mfn;

        ind = kimage_entry_ind(entry, compat);
        mfn = kimage_entry_mfn(entry, compat);

        switch ( ind )
        {
        case IND_DESTINATION:
            dest = mfn_to_maddr(mfn);
            ret = kimage_set_destination(image, dest);
            if ( ret < 0 )
                goto done;
            break;
        case IND_INDIRECTION:
            unmap_domain_page(page);
            page = map_domain_page(mfn);
            entry = page;
            continue;
        case IND_DONE:
            kimage_terminate(image);
            goto done;
        case IND_SOURCE:
        {
            struct page_info *guest_page, *xen_page;

            guest_page = mfn_to_page(mfn);
            if ( !get_page(guest_page, current->domain) )
            {
                ret = -EFAULT;
                goto done;
            }

            xen_page = kimage_alloc_page(image, dest);
            if ( !xen_page )
            {
                put_page(guest_page);
                ret = -ENOMEM;
                goto done;
            }

            copy_domain_page(page_to_mfn(xen_page), mfn);
            put_page(guest_page);

            ret = kimage_add_page(image, page_to_maddr(xen_page));
            if ( ret < 0 )
                goto done;

            ret = machine_kexec_add_page(image, dest, dest);
            if ( ret < 0 )
                goto done;

            dest += PAGE_SIZE;
            break;
        }
        default:
            ret = -EINVAL;
            goto done;
        }
        entry = kimage_entry_next(entry, compat);
    }
done:
    unmap_domain_page(page);
    return ret;
}

static int kimage_purgatory_alloc(struct kexec_image *image)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)kexec_purgatory;
    const Elf_Shdr *sechdrs;
    unsigned long bss_align;
    unsigned long bss_sz;
    unsigned long align;
    int i;
    struct purgatory_info *pi = &image->pi;

    dprintk(XENLOG_DEBUG, "purgatory_alloc 0x%lx 0x%lx %u\n",
            (unsigned long)kexec_purgatory, (unsigned long)ehdr,
            kexec_purgatory_size);

    sechdrs = (void *)ehdr + ehdr->e_shoff;
    pi->buf_align = bss_align = 1;
    pi->bufsz = bss_sz = 0;

    for ( i = 0; i < ehdr->e_shnum; i++ ) {
        if ( !(sechdrs[i].sh_flags & SHF_ALLOC) )
            continue;

        align = sechdrs[i].sh_addralign;
        if ( sechdrs[i].sh_type != SHT_NOBITS ) {
            if ( pi->buf_align < align )
                pi->buf_align = align;
            pi->bufsz = ROUNDUP(pi->bufsz, align);
            pi->bufsz += sechdrs[i].sh_size;
        } else {
            if ( bss_align < align )
                bss_align = align;
            bss_sz = ROUNDUP(bss_sz, align);
            bss_sz += sechdrs[i].sh_size;
        }
    }
    pi->bufsz = ROUNDUP(pi->bufsz, bss_align);
    pi->memsz = pi->bufsz + bss_sz;
    if ( pi->buf_align < bss_align )
        pi->buf_align = bss_align;

    pi->buffer = xzalloc_bytes(pi->bufsz);
    if ( !pi->buffer )
        return -ENOMEM;

    return 0;
}

static int kimage_purgatory_copy(struct kexec_image *image)
{
    unsigned long bss_addr;
    unsigned long offset;
    unsigned long align;
    size_t sechdrs_size;
    Elf_Shdr *sechdrs;
    int i;
    struct purgatory_info *pi = &image->pi;
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)kexec_purgatory;
    const char *shstrtab;

    /*
     * The section headers in kexec_purgatory are read-only. In order to
     * have them modifiable make a temporary copy.
     */
    sechdrs_size = sizeof(Elf_Shdr) * ehdr->e_shnum;
    sechdrs = xmalloc_bytes(sechdrs_size);
    if ( !sechdrs )
        return -ENOMEM;

    memcpy(sechdrs, (void *)ehdr + ehdr->e_shoff, sechdrs_size);
    pi->sechdrs = sechdrs;

    shstrtab = (char *)ehdr + sechdrs[ehdr->e_shstrndx].sh_offset;

    offset = 0;
    bss_addr = pi->dest + pi->bufsz;
    image->entry_maddr = ehdr->e_entry;

    for ( i = 0; i < ehdr->e_shnum; i++ ) {
        if ( !(sechdrs[i].sh_flags & SHF_ALLOC) )
            continue;

        align = sechdrs[i].sh_addralign;
        if ( sechdrs[i].sh_type == SHT_NOBITS ) {
            bss_addr = ROUNDUP(bss_addr, align);
            sechdrs[i].sh_addr = bss_addr;
            bss_addr += sechdrs[i].sh_size;
            continue;
        }

        offset = ROUNDUP(offset, align);

        if ( sechdrs[i].sh_flags & SHF_EXECINSTR &&
                ehdr->e_entry >= sechdrs[i].sh_addr &&
                ehdr->e_entry < (sechdrs[i].sh_addr + sechdrs[i].sh_size) ) {
            BUG_ON(image->entry_maddr != ehdr->e_entry);
            image->entry_maddr -= sechdrs[i].sh_addr;
            image->entry_maddr += pi->dest + offset;
        }

        memcpy(pi->buffer + offset,
               (void *)ehdr + sechdrs[i].sh_offset,
               sechdrs[i].sh_size);

        sechdrs[i].sh_addr = pi->dest + offset;
        sechdrs[i].sh_offset = offset;
        offset += sechdrs[i].sh_size;

        dprintk(XENLOG_DEBUG, "Load %s at 0x%08lx\n",
                shstrtab + sechdrs[i].sh_name, sechdrs[i].sh_addr);
    }

    dprintk(XENLOG_DEBUG, "image entry maddr 0x%lx\n", image->entry_maddr);

    return 0;
}

static int kimage_purgatory_apply_relocations(struct kexec_image *image)
{
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)kexec_purgatory;
    int i, ret;
    struct purgatory_info *pi = &image->pi;
    const Elf_Shdr *sechdrs;

    sechdrs = (void *)ehdr + ehdr->e_shoff;

    for ( i = 0; i < ehdr->e_shnum; i++ ) {
        const Elf_Shdr *relsec;
        const Elf_Shdr *symtab;
        Elf_Shdr *section;

        relsec = sechdrs + i;

        if ( relsec->sh_type != SHT_RELA &&
                relsec->sh_type != SHT_REL )
            continue;

        /*
         * For section of type SHT_RELA/SHT_REL,
         * ->sh_link contains section header index of associated
         * symbol table. And ->sh_info contains section header
         * index of section to which relocations apply.
         */
        if ( relsec->sh_info >= ehdr->e_shnum ||
                relsec->sh_link >= ehdr->e_shnum )
            return -ENOEXEC;

        section = pi->sechdrs + relsec->sh_info;
        symtab = sechdrs + relsec->sh_link;

        if ( !(section->sh_flags & SHF_ALLOC) )
            continue;

        /*
         * symtab->sh_link contain section header index of associated
         * string table.
         */
        if ( symtab->sh_link >= ehdr->e_shnum )
            /* Invalid section number? */
            continue;

        /*
         * Respective architecture needs to provide support for applying
         * relocations of type SHT_RELA.
         */
        if ( relsec->sh_type == SHT_RELA )
            ret = arch_kexec_apply_relocations_add(pi, section,
                    relsec, symtab);
        else if ( relsec->sh_type == SHT_REL )
            ret = -ENOEXEC;
        if ( ret )
            return ret;
    }

    return 0;
}

static const Elf_Sym *kimage_purgatory_find_symbol(const char *name)
{
    const Elf_Shdr *sechdrs;
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)kexec_purgatory;
    const Elf_Sym *syms;
    const char *strtab;
    int i, k;

    sechdrs = (void *)ehdr + ehdr->e_shoff;

    for ( i = 0; i < ehdr->e_shnum; i++ ) {
        if ( sechdrs[i].sh_type != SHT_SYMTAB )
            continue;

        if ( sechdrs[i].sh_link >= ehdr->e_shnum )
            /* Invalid strtab section number */
            continue;

        strtab = (void *)ehdr + sechdrs[sechdrs[i].sh_link].sh_offset;
        syms = (void *)ehdr + sechdrs[i].sh_offset;

        /* Go through symbols for a match */
        for ( k = 0; k < sechdrs[i].sh_size/sizeof(Elf_Sym); k++ ) {
            if ( ELF_ST_BIND(syms[k].st_info) != STB_GLOBAL )
                continue;

            if ( strcmp(strtab + syms[k].st_name, name) != 0 )
                continue;

            if ( syms[k].st_shndx == SHN_UNDEF ||
                    syms[k].st_shndx >= ehdr->e_shnum ) {
                printk("Symbol: %s has bad section index %d.\n",
                        name, syms[k].st_shndx);
                return NULL;
            }

            /* Found the symbol we are looking for */
            return &syms[k];
        }
    }

    return NULL;
}

static int kimage_purgatory_get_symbol_addr(struct kexec_image *image,
                                            const char *name, void **addr)
{
    struct purgatory_info *pi = &image->pi;
    const Elf_Sym *sym;
    Elf_Shdr *sechdr;

    sym = kimage_purgatory_find_symbol(name);
    if ( !sym )
        return -EINVAL;

    sechdr = &pi->sechdrs[sym->st_shndx];

    /*
     * Update addr with the address where symbol will finally be loaded after
     * kimage_purgatory_move()
     */
    *addr = (void *)(sechdr->sh_addr + sym->st_value);
    return 0;
}

/*
 * Get or set value of a symbol. If "get_value" is true, symbol value is
 * returned in buf otherwise symbol value is set based on value in buf.
 */
static int kimage_purgatory_get_set_symbol(struct kexec_image *image, const char *name,
				   void *buf, unsigned int size, bool get_value)
{
    struct purgatory_info *pi = &image->pi;
    const Elf_Sym *sym;
    Elf_Shdr *sec;
    char *sym_buf;

    sym = kimage_purgatory_find_symbol(name);
    if ( !sym )
        return -EINVAL;

    if ( sym->st_size != size ) {
        printk("symbol %s size mismatch: expected %lu actual %u\n",
                name, (unsigned long)sym->st_size, size);
        return -EINVAL;
    }

    sec = pi->sechdrs + sym->st_shndx;

    if ( sec->sh_type == SHT_NOBITS ) {
        printk("symbol %s is in a bss section. Cannot %s\n", name,
                get_value ? "get" : "set");
        return -EINVAL;
    }

    sym_buf = (char *)pi->buffer + sec->sh_offset + sym->st_value;

    if ( get_value )
        memcpy((void *)buf, sym_buf, size);
    else
        memcpy((void *)sym_buf, buf, size);

    return 0;
}

static int kimage_purgatory_find_hole(struct kexec_image *image)
{
    paddr_t hole_start, hole_end, mstart, mend;
    struct purgatory_info *pi = &image->pi;
    unsigned long i;

    pi->dest = 0;
    hole_start = PAGE_ALIGN(image->next_crash_page);
    hole_end = hole_start + pi->memsz;
    while ( hole_end <= kexec_crash_area.start + kexec_crash_area.size )
    {
        /* See if the hole overlaps any of the segments. */
        for ( i = 0; i < image->nr_segments; i++ )
        {
            mstart = image->segments[i].dest_maddr;
            mend   = mstart + image->segments[i].dest_size;
            if ( (hole_end > mstart) && (hole_start < mend) )
            {
                /* Advance the hole to the end of the segment. */
                hole_start = PAGE_ALIGN(mend);
                hole_end = hole_start + pi->memsz;
                break;
            }
        }

        /* If the hole doesn't overlap any segments I have found my hole! */
        if ( i == image->nr_segments &&
             hole_end <= kexec_crash_area.start + kexec_crash_area.size )
        {
            pi->dest = hole_start;
            image->next_crash_page = PAGE_ALIGN(hole_end);
            break;
        }
    }

    return pi->dest;
}

/* Load purgatory as an ELF binary and relocate it. */
static int kimage_load_purgatory_image(struct kexec_image *image)
{
    int ret;

    ret = kimage_purgatory_alloc(image);
    if ( ret )
        return ret;

    ret = kimage_purgatory_find_hole(image);
    if ( !ret )
        return -ENOMEM;

    ret = kimage_purgatory_copy(image);
    if ( ret )
        return ret;

    ret = kimage_purgatory_apply_relocations(image);
    if ( ret )
        return ret;

    return 0;
}

/*
 * Update the loaded purgatory with the digest and locations of the segments.
 */
static int kimage_purgatory_calc_one_digest(struct sha2_256_state *ctx,
                                            struct kimage_segment *segment)
{
    paddr_t dest;
    unsigned long sbytes;
    unsigned int dest_offset;
    int ret = 0;

    sbytes = segment->buf_size;
    dest = segment->dest_maddr + segment->dest_offset;
    dest_offset = segment->dest_offset;

    while ( sbytes )
    {
        unsigned long dest_mfn;
        void *dest_va;
        size_t schunk, dchunk;

        dest_mfn = dest >> PAGE_SHIFT;

        dchunk = PAGE_SIZE - dest_offset;
        schunk = min(dchunk, sbytes);

        dest_va = map_domain_page(_mfn(dest_mfn));
        if ( !dest_va )
            return -EINVAL;

        sha2_256_update(ctx, dest_va + dest_offset, schunk);

        unmap_domain_page(dest_va);
        if ( ret )
            return -EFAULT;

        sbytes -= schunk;
        dest += dchunk;
        dest_offset = 0;
    }
    return 0;
}

static int kimage_purgatory_calc_digest(struct kexec_image *image)
{
    int ret;
    sha256_region_t regions[KIMAGE_SHA256_REGIONS] = {{0}};
    struct sha2_256_state ctx;
    uint8_t digest[SHA2_256_DIGEST_SIZE];
    unsigned int s;

    if ( image->nr_segments > KIMAGE_SHA256_REGIONS )
    {
        dprintk(XENLOG_DEBUG, "More segments than allocated SHA256 regions\n");
        return -E2BIG;
    }


    sha2_256_init(&ctx);

    for ( s = 0; s < image->nr_segments; s++ ) {
        ret = kimage_purgatory_calc_one_digest(&ctx, &image->segments[s]);
        if ( ret )
            return ret;

        regions[s].start = image->segments[s].dest_maddr +
                           image->segments[s].dest_offset;
        regions[s].len = image->segments[s].buf_size;
    }

    sha2_256_final(&ctx, digest);

    ret = kimage_purgatory_get_set_symbol(image, "sha256_regions",
                                          regions, sizeof(regions), 0);
    if ( ret )
        return ret;

    ret = kimage_purgatory_get_set_symbol(image, "sha256_digest",
                                          digest, sizeof(digest), 0);
    if ( ret )
        return ret;

    return 0;
}

/*
 * Find the entry point to the new kernel, we need to map the crash region into
 * memory in order to read the kernel header.
 */
#define KERNEL_SEGMENT_IDX 0
static uint64_t kimage_find_kernel_entry_maddr(struct kexec_image *image)
{
    uint64_t alignment_addr;
    uint32_t alignment;
    unsigned long dest_mfn;
    void *dest_va;

    alignment_addr = image->segments[KERNEL_SEGMENT_IDX].dest_maddr +
                         image->segments[KERNEL_SEGMENT_IDX].dest_offset +
                         offsetof(struct setup_header, kernel_alignment);

    dest_mfn = alignment_addr >> PAGE_SHIFT;
    dest_va = map_domain_page(_mfn(dest_mfn));
    if ( !dest_va )
        return -EINVAL;

    alignment = *((uint32_t *) ((uint8_t *) dest_va +
                                                PAGE_OFFSET(alignment_addr)));

    unmap_domain_page(dest_va);

    /*
     * Ensure the kernel alignment is a valid LOAD_PHYSICAL_ADDR,
     * which ranges from 0x200000 (2MiB) to 0x1000000 (16Mib) on 64-bit systems
     * as defined in the kernel x86 Kconfig
     */
    if ( alignment % 0x200000 != 0 ||
         alignment < 0x200000 ||
         alignment > 0x1000000 )
        return -EINVAL;

    return ROUNDUP(image->segments[KERNEL_SEGMENT_IDX].dest_maddr +
                       image->segments[KERNEL_SEGMENT_IDX].dest_offset,
                   alignment) +
                   0x200;
}

/*
 * Configure purgatory with the register values that will be set before jumping
 * into the new kernel.
 */
static int kimage_purgatory_set_register_block(struct kexec_image *image, uint64_t parameters)
{
    int ret;
    uint64_t rip;
    void *stack;

    rip = kimage_find_kernel_entry_maddr(image);
    if ( rip < 0 )
        return -EINVAL;

    ret = kimage_purgatory_get_symbol_addr(image, "stack_end", &stack);
    BUG_ON(ret < 0);

    /* Clear the registers */
    memset(&image->regs, 0, sizeof(image->regs));

    image->regs.rsp = (uint64_t)stack;
    image->regs.rsi = parameters;  // Kernel parameters
    image->regs.rip = rip;

    return kimage_purgatory_get_set_symbol(image, "entry64_regs",
                                           &image->regs, sizeof(image->regs),
                                           0);
}

/*
 * Move the loaded purgatory into its final destination as an additional kimage
 * segment.
 */
static int kimage_purgatory_move(struct kexec_image *image)
{
    struct purgatory_info *pi = &image->pi;
    paddr_t dest;
    unsigned long sbytes;
    unsigned long src_offset = 0;
    int result = 0;
    paddr_t addr;

    sbytes = pi->bufsz;
    dest = pi->dest;

    while ( dest < (pi->dest + pi->memsz) )
    {
        unsigned long dest_mfn;
        void *dest_va;
        size_t schunk, dchunk;

        dest_mfn = dest >> PAGE_SHIFT;

        dchunk = PAGE_SIZE;
        schunk = min(dchunk, sbytes);

        dest_va = map_domain_page(_mfn(dest_mfn));
        if ( !dest_va )
            return -EINVAL;

        memcpy(dest_va, pi->buffer + src_offset, schunk);
        memset(dest_va + schunk, 0, dchunk - schunk);

        unmap_domain_page(dest_va);

        sbytes -= schunk;
        dest += dchunk;
        src_offset += schunk;
    }

    for ( addr = pi->dest & PAGE_MASK;
          addr < pi->dest + pi->memsz; addr += PAGE_SIZE ) {
        result = machine_kexec_add_page(image, addr, addr);
        if ( result < 0 )
            break;
    }

    return result;
}

int kimage_setup_purgatory(struct kexec_image *image, uint64_t parameters)
{
    int ret;

    ret = kimage_load_purgatory_image(image);
    if ( ret )
        return ret;

    ret = kimage_purgatory_calc_digest(image);
    if ( ret )
        return ret;

    ret = kimage_purgatory_set_register_block(image, parameters);
    if ( ret )
        return ret;

    ret = kimage_purgatory_move(image);
    if ( ret )
        return ret;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

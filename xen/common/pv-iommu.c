/* SPDX-License-Identifier: GPL-2.0 */
/*
 * xen/common/pv_iommu.c
 *
 * PV-IOMMU hypercall interface.
 */

#include <xen/errno.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/iocap.h>
#include <xen/iommu.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/mm-frame.h>
#include <xen/pci.h>
#include <xen/sched.h>
#include <asm/iommu.h>
#include <asm/mm.h>
#include <asm/p2m.h>

#include <public/pv-iommu.h>

#define PVIOMMU_PREFIX "[PV-IOMMU] "

static int get_paged_frame(struct domain *d, gfn_t gfn, mfn_t *mfn,
                           struct page_info **page, bool readonly)
{
    int ret = 0;
    p2m_type_t p2mt = p2m_invalid;

    #ifdef CONFIG_X86
    p2m_query_t query = P2M_ALLOC;

    if ( !readonly )
        query |= P2M_UNSHARE;

    *mfn = get_gfn_type(d, gfn_x(gfn), &p2mt, query);
    #else
    *mfn = p2m_lookup(d, gfn, &p2mt);
    #endif

    if ( mfn_eq(*mfn, INVALID_MFN) )
    {
        /* No mapping ? */
        gprintk(XENLOG_G_WARNING, PVIOMMU_PREFIX
                "Trying to map to non-backed page frame (gfn=%"PRI_gfn" p2mt=%d)\n",
                gfn_x(gfn), p2mt);

        ret = -ENOENT;
    }
    else if ( p2m_is_any_ram(p2mt) && mfn_valid(*mfn) )
    {
        struct domain *owner;

        *page = mfn_to_page(*mfn);
        owner = page_get_owner_and_reference(*page);
        if ( !owner || (owner != d && !is_hardware_domain(d)) )
        {
            /* TODO: foreign mappings when d is not privileged ? */
            put_page(*page);
            *page = NULL;
            return -EPERM;
        }
        ret = 0;
    }
    else if ( p2m_is_mmio(p2mt) ||
              iomem_access_permitted(d, mfn_x(*mfn),mfn_x(*mfn)) )
    {
        *page = NULL;
        ret = 0;
    }
    else
    {
        gprintk(XENLOG_WARNING, PVIOMMU_PREFIX
                "Unexpected p2mt %d (gfn=%"PRI_gfn" mfn=%"PRI_mfn")\n",
                p2mt, gfn_x(gfn), mfn_x(*mfn));

        ret = -EPERM;
    }

    put_gfn(d, gfn_x(gfn));
    return ret;
}

static bool can_use_iommu_check(struct domain *d)
{
    if ( !is_iommu_enabled(d) )
    {
        gprintk(XENLOG_WARNING, PVIOMMU_PREFIX "IOMMU disabled for this domain\n");
        return false;
    }

    if ( !dom_iommu(d)->allow_pv_iommu )
    {
        gprintk(XENLOG_WARNING, PVIOMMU_PREFIX "PV-IOMMU disabled for this domain\n");
        return false;
    }

    return true;
}

static long capabilities_op(struct pv_iommu_capabilities *cap, struct domain *d)
{
    cap->max_ctx_no = d->iommu.other_contexts.count;
    cap->max_iova_addr = iommu_get_max_iova(d);

    cap->max_pasid = 0; /* TODO */
    cap->cap_flags = 0;

    cap->pgsize_mask = PAGE_SIZE_4K;

    return 0;
}

static long init_op(struct pv_iommu_init *init, struct domain *d)
{
    if (init->max_ctx_no == UINT32_MAX)
        return -E2BIG;

    return iommu_domain_pviommu_init(d, init->max_ctx_no + 1, init->arena_order);
}

static long alloc_context_op(struct pv_iommu_alloc *alloc, struct domain *d)
{
    uint16_t ctx_no = 0;
    int status = 0;

    status = iommu_context_alloc(d, &ctx_no, 0);

    if ( status )
        return status;

    gprintk(XENLOG_INFO, PVIOMMU_PREFIX "Created IOMMU context %hu\n", ctx_no);

    alloc->ctx_no = ctx_no;
    return 0;
}

static long free_context_op(struct pv_iommu_free *free, struct domain *d)
{
    int flags = IOMMU_TEARDOWN_PREEMPT;

    if ( !free->ctx_no )
        return -EINVAL;

    if ( free->free_flags & IOMMU_FREE_reattach_default )
        flags |= IOMMU_TEARDOWN_REATTACH_DEFAULT;

    return iommu_context_free(d, free->ctx_no, flags);
}

static long reattach_device_op(struct pv_iommu_reattach_device *reattach,
                               struct domain *d)
{
    int ret;
    device_t *pdev;
    struct physdev_pci_device dev = reattach->dev;

    pcidevs_lock();
    pdev = pci_get_pdev(d, PCI_SBDF(dev.seg, dev.bus, dev.devfn));

    if ( !pdev )
    {
        pcidevs_unlock();
        return -ENODEV;
    }

    ret = iommu_reattach_context(d, d, pdev, reattach->ctx_no);

    pcidevs_unlock();
    return ret;
}

static long map_pages_op(struct pv_iommu_map_pages *map, struct domain *d)
{
    struct iommu_context *ctx;
    int ret = 0, flush_ret;
    struct page_info *page = NULL;
    mfn_t mfn, mfn_lookup;
    unsigned int lookup_flags, flags = 0, flush_flags = 0;
    size_t i = 0;
    dfn_t dfn0 = _dfn(map->dfn); /* original map->dfn */

    if ( !map->ctx_no || !(ctx = iommu_get_context(d, map->ctx_no)) )
        return -EINVAL;

    if ( map->map_flags & IOMMU_MAP_readable )
        flags |= IOMMUF_readable;

    if ( map->map_flags & IOMMU_MAP_writeable )
        flags |= IOMMUF_writable;

    for (i = 0; i < map->nr_pages; i++)
    {
        gfn_t gfn = _gfn(map->gfn + i);
        dfn_t dfn = _dfn(map->dfn + i);

#ifdef CONFIG_X86
        if ( iommu_identity_map_check(d, ctx, _mfn(map->dfn)) )
        {
            ret = -EADDRNOTAVAIL;
            break;
        }
#endif

        ret = get_paged_frame(d, gfn, &mfn, &page, 0);

        if ( ret )
            break;

        /* Check for conflict with existing mappings */
        if ( !iommu_lookup_page(d, ctx, dfn, &mfn_lookup, &lookup_flags) )
        {
            if ( page && mfn_valid(mfn) )
                put_page(page);

            ret = -EADDRINUSE;
            break;
        }

        ret = iommu_map(d, ctx, dfn, mfn, 1, flags, &flush_flags);

        if ( ret )
        {
            if ( page && mfn_valid(mfn) )
                put_page(page);

            break;
        }

        map->mapped++;

        if ( (i & 0xff) && hypercall_preempt_check() )
        {
            i++;

            map->gfn += i;
            map->dfn += i;
            map->nr_pages -= i;

            ret = -ERESTART;
            break;
        }
    }

    flush_ret = iommu_iotlb_flush(d, ctx, dfn0, i, flush_flags);

    iommu_put_context(ctx);

    if ( flush_ret )
        gprintk(XENLOG_G_WARNING, PVIOMMU_PREFIX
                "Flush operation failed for %d (%d)\n", ctx->id, flush_ret);

    return ret;
}

static long unmap_pages_op(struct pv_iommu_unmap_pages *unmap, struct domain *d)
{
    struct iommu_context *ctx;
    mfn_t mfn;
    int ret = 0, flush_ret;
    unsigned int flags, flush_flags = 0;
    size_t i = 0;
    dfn_t dfn0 = _dfn(unmap->dfn); /* original unmap->dfn */

    if ( !unmap->ctx_no || !(ctx = iommu_get_context(d, unmap->ctx_no)) )
        return -EINVAL;

    for (i = 0; i < unmap->nr_pages; i++)
    {
        dfn_t dfn = _dfn(unmap->dfn + i);

#ifdef CONFIG_X86
        if ( iommu_identity_map_check(d, ctx, _mfn(dfn_x(dfn))) )
        {
            ret = -EADDRNOTAVAIL;
            break;
        }
#endif

        /* Check if there is a valid mapping for this domain */
        if ( iommu_lookup_page(d, ctx, dfn, &mfn, &flags) ) {
            ret = -ENOENT;
            break;
        }

        ret = iommu_unmap(d, ctx, dfn, 1, 0, &flush_flags);

        if ( ret )
            break;

        unmap->unmapped++;

        /* Decrement reference counter (if needed) */
        if ( mfn_valid(mfn) )
            put_page(mfn_to_page(mfn));

        if ( (i & 0xff) && hypercall_preempt_check() )
        {
            i++;

            unmap->dfn += i;
            unmap->nr_pages -= i;

            ret = -ERESTART;
            break;
        }
    }

    flush_ret = iommu_iotlb_flush(d, ctx, dfn0, i, flush_flags);

    iommu_put_context(ctx);

    if ( flush_ret )
        printk(XENLOG_WARNING PVIOMMU_PREFIX
               "Flush operation failed for c%d (%d)\n", ctx->id, flush_ret);

    return ret;
}

static long do_iommu_subop(int subop, XEN_GUEST_HANDLE_PARAM(void) arg,
                           struct domain *d, bool remote);

static long remote_cmd_op(struct pv_iommu_remote_cmd *remote_cmd,
                          struct domain *current_domain)
{
    long ret = 0;
    struct domain *d;

    /* TODO: use a better permission logic */
    if ( !is_hardware_domain(current_domain) )
        return -EPERM;

    d = get_domain_by_id(remote_cmd->domid);

    if ( !d )
        return -ENOENT;

    ret = do_iommu_subop(remote_cmd->subop, remote_cmd->arg, d, true);

    put_domain(d);

    return ret;
}

static long do_iommu_subop(int subop, XEN_GUEST_HANDLE_PARAM(void) arg,
                           struct domain *d, bool remote)
{
    long ret = 0;

    switch ( subop )
    {
        case IOMMU_noop:
            break;

        case IOMMU_query_capabilities:
        {
            struct pv_iommu_capabilities cap;

            ret = capabilities_op(&cap, d);

            if ( unlikely(copy_to_guest(arg, &cap, 1)) )
                ret = -EFAULT;

            break;
        }

        case IOMMU_init:
        {
            struct pv_iommu_init init;

            if ( unlikely(copy_from_guest(&init, arg, 1)) )
            {
                ret = -EFAULT;
                break;
            }

            ret = init_op(&init, d);
            gdprintk(XENLOG_INFO, PVIOMMU_PREFIX "init -> %ld\n", ret);
        }

        case IOMMU_alloc_context:
        {
            struct pv_iommu_alloc alloc;

            if ( unlikely(copy_from_guest(&alloc, arg, 1)) )
            {
                ret = -EFAULT;
                break;
            }

            ret = alloc_context_op(&alloc, d);

            if ( unlikely(copy_to_guest(arg, &alloc, 1)) )
                ret = -EFAULT;

            gdprintk(XENLOG_INFO, PVIOMMU_PREFIX
                     "alloc_context(flags:%x) -> ctx_no: %d, ret=%ld\n",
                     alloc.alloc_flags, alloc.ctx_no, ret);
            break;
        }

        case IOMMU_free_context:
        {
            struct pv_iommu_free free;

            if ( unlikely(copy_from_guest(&free, arg, 1)) )
            {
                ret = -EFAULT;
                break;
            }

            ret = free_context_op(&free, d);
            gdprintk(XENLOG_INFO, PVIOMMU_PREFIX
                     "free_context(ctx_no:%d) -> %ld\n", free.ctx_no, ret);
            break;
        }

        case IOMMU_reattach_device:
        {
            struct pv_iommu_reattach_device reattach;

            if ( unlikely(copy_from_guest(&reattach, arg, 1)) )
            {
                ret = -EFAULT;
                break;
            }

            ret = reattach_device_op(&reattach, d);
            gdprintk(XENLOG_INFO, PVIOMMU_PREFIX
                     "reattach(ctx_no:%d, bus:%02x, devfn:%2x) -> %ld\n",
                     reattach.ctx_no, reattach.dev.bus, reattach.dev.devfn, ret);
            break;
        }

        case IOMMU_map_pages:
        {
            struct pv_iommu_map_pages map;

            if ( unlikely(copy_from_guest(&map, arg, 1)) )
            {
                ret = -EFAULT;
                break;
            }

            ret = map_pages_op(&map, d);

            if ( unlikely(copy_to_guest(arg, &map, 1)) )
                ret = -EFAULT;

            break;
        }

        case IOMMU_unmap_pages:
        {
            struct pv_iommu_unmap_pages unmap;

            if ( unlikely(copy_from_guest(&unmap, arg, 1)) )
            {
                ret = -EFAULT;
                break;
            }

            ret = unmap_pages_op(&unmap, d);

            if ( unlikely(copy_to_guest(arg, &unmap, 1)) )
                ret = -EFAULT;

            break;
        }

        case IOMMU_remote_cmd:
        {
            struct pv_iommu_remote_cmd remote_cmd;

            if ( remote )
            {
                /* Prevent remote_cmd from being called recursively */
                ret = -EINVAL;
                break;
            }

            if ( unlikely(copy_from_guest(&remote_cmd, arg, 1)) )
            {
                ret = -EFAULT;
                break;
            }

            ret = remote_cmd_op(&remote_cmd, d);
            break;
        }

        /*
         * TODO
         */
        case IOMMU_alloc_nested:
        {
            ret = -EOPNOTSUPP;
            break;
        }

        case IOMMU_flush_nested:
        {
            ret = -EOPNOTSUPP;
            break;
        }

        case IOMMU_attach_pasid:
        {
            ret = -EOPNOTSUPP;
            break;
        }

        case IOMMU_detach_pasid:
        {
            ret = -EOPNOTSUPP;
            break;
        }

        default:
            return -EOPNOTSUPP;
    }

    return ret;
}

long do_iommu_op(unsigned int subop, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long ret = 0;
    struct domain *d = current->domain;

    if ( !can_use_iommu_check(d) )
        return -ENODEV;

    ret = do_iommu_subop(subop, arg, d, false);

    if ( ret == -ERESTART )
        return hypercall_create_continuation(__HYPERVISOR_iommu_op, "ih", subop, arg);

    return ret;
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

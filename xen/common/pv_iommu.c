/******************************************************************************
 * common/pv_iommu.c
 * 
 * Paravirtualised IOMMU functionality
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/p2m.h>
#include <asm/event.h>
#include <xen/guest_access.h>
#include <public/pv-iommu.h>
#include <xsm/xsm.h>

#ifdef CONFIG_X86
#include <asm/setup.h>
#endif
#define ret_t long

static uint64_t **hwdom_premap_m2b;

#define PREMAP_M2B_PAGE(x) ( pfn_to_pdx(x) / (PAGE_SIZE/sizeof(uint64_t) ) )
#define PREMAP_M2B_IDX(x) ( pfn_to_pdx(x) % (PAGE_SIZE/sizeof(uint64_t) ) )
#define PREMAP_M2B(x) hwdom_premap_m2b[PREMAP_M2B_PAGE(x)][PREMAP_M2B_IDX(x)]

static int get_paged_frame(unsigned long gfn, unsigned long *frame,
                           struct page_info **page, int readonly,
                           struct domain *rd)
{
    int rc = 0;
#if defined(P2M_PAGED_TYPES) || defined(P2M_SHARED_TYPES)
    p2m_type_t p2mt;

    *page = get_page_from_gfn(rd, gfn, &p2mt,
                             (readonly) ? P2M_ALLOC : P2M_UNSHARE);
    if ( !(*page) )
    {
        *frame = mfn_x(INVALID_MFN);
        if ( p2m_is_shared(p2mt) )
            return -EIO;
        if ( p2m_is_paging(p2mt) )
        {
            p2m_mem_paging_populate(rd, gfn);
            return -EIO;
        }
        return -EIO;
    }
    *frame = mfn_x(page_to_mfn(*page));
#else
    *frame = gmfn_to_mfn(rd, gfn);
    *page = mfn_valid(_mfn(*frame)) ? mfn_to_page(*frame) : NULL;
    if ( (!(page)) || (!get_page*page, rd) )
    {
        *frame = mfn_x(INVALID_MFN);
        *page = NULL;
        rc = -EIO;
    }
#endif

    return rc;
}

int can_use_iommu_check(struct domain *d)
{
    if ( !iommu_enabled || (!is_hardware_domain(d) && !need_iommu(d)) )
        return 0;

    if ( is_hardware_domain(d) && iommu_passthrough )
        return 0;

    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        return 0;

    return 1;
}

void do_iommu_sub_op(struct pv_iommu_op *op)
{
    struct domain *d = current->domain;
    struct domain *rd = NULL;

    /* Only order 0 pages supported */
    if ( IOMMU_get_page_order(op->flags) != 0 )
    {
        op->status = -ENOSPC;
        goto finish;
    }

    switch ( op->subop_id )
    {
        case IOMMUOP_query_caps:
        {
            op->flags = 0;
            op->status = 0;
            if ( can_use_iommu_check(d) )
                op->flags |= IOMMU_QUERY_map_cap;

            if ( is_hardware_domain(d) && !d->need_iommu )
            {
                op->flags |= IOMMU_QUERY_map_all_mfns;

                if ( unlikely(!hwdom_premap_m2b) )
                    hwdom_premap_m2b = xzalloc_array(
                        unsigned long *,
                        ((sizeof(unsigned long) * max_pdx) / PAGE_SIZE) + 1);
            }
            break;
        }
        case IOMMUOP_map_page:
        {
            unsigned long mfn, tmp;
            unsigned int flags = 0;
            struct page_info *page = NULL;

            /* Check if calling domain can create IOMMU mappings */
            if ( !can_use_iommu_check(d) )
            {
                op->status = -EPERM;
                goto finish;
            }

            /* Check we are the owner of the page */
            if ( !is_hardware_domain(d) &&
                 ( maddr_get_owner(op->u.map_page.gfn) != d ) )
            {
                op->status = -EPERM;
                goto finish;
            }

            /* Lookup page struct backing gfn */
            if ( (op->flags & IOMMU_MAP_OP_no_ref_cnt) )
            {
                mfn = op->u.map_page.gfn;
                page = mfn_to_page(_mfn(mfn));
                if (!page)
                {
                    op->status = -EPERM; // Should this be something else?
                    goto finish;
                }
            } else if ( get_paged_frame(op->u.map_page.gfn, &mfn, &page, 0, d) )
            {
                op->status = -EPERM; // Should this be something else?
                goto finish;
            }

            /* Check for conflict with existing BFN mappings */
            if ( !iommu_lookup_page(d, op->u.map_page.bfn, &tmp) )
            {
                if ( !(op->flags & IOMMU_MAP_OP_no_ref_cnt) )
                    put_page(page);
                op->status = -EPERM;
                goto finish;
            }

            if ( op->flags & IOMMU_OP_readable )
                flags |= IOMMUF_readable;

            if ( op->flags & IOMMU_OP_writeable )
                flags |= IOMMUF_writable;

            if ( iommu_legacy_map(d, op->u.map_page.bfn, mfn, 0, flags) )
            {
                if ( !(op->flags & IOMMU_MAP_OP_no_ref_cnt) )
                    put_page(page);
                op->status = -EIO;
                goto finish;
            }

            /* Add to M2B with wildcard ioserver entry */
            if ( is_hardware_domain(d) && (op->flags & IOMMU_MAP_OP_add_m2b ))
            {
                if ( !hwdom_premap_m2b )
                {
                    op->status = -EPERM;
                    goto finish;
                }
                /* Check if tracking page is allocated */
                if ( !hwdom_premap_m2b[PREMAP_M2B_PAGE(mfn)] )
                {
                    hwdom_premap_m2b[PREMAP_M2B_PAGE(mfn)] =
                            alloc_xenheap_page();
                    if ( !hwdom_premap_m2b[PREMAP_M2B_PAGE(mfn)] )
                    {
                        op->status = -ENOMEM;
                        goto finish;
                    }
                    clear_page(hwdom_premap_m2b[PREMAP_M2B_PAGE(mfn)]);
                } else if ( read_atomic(&PREMAP_M2B(mfn)) )
                {
                    op->status = -EPERM;
                    goto finish;
                }

                write_atomic(&PREMAP_M2B(mfn), op->u.map_page.bfn);
            }
            op->status = 0;
            break;
        }

        case IOMMUOP_unmap_page:
        {
            struct page_info *page;
            unsigned long mfn;

            /* Check if there is a valid BFN mapping for this domain */
            if ( iommu_lookup_page(d, op->u.unmap_page.bfn, &mfn) )
            {
                op->status = -ENOENT;
                goto finish;
            }

            if ( iommu_legacy_unmap(d, op->u.unmap_page.bfn, 0) )
            {
                op->status = -EIO;
                goto finish;
            }

            /* Use MFN from B2M mapping to lookup page */
            page = mfn_to_page(_mfn(mfn));

            /* Remove wildcard M2B mapping */
            if ( is_hardware_domain(d) &&
                (op->flags & IOMMU_UNMAP_OP_remove_m2b) &&
                hwdom_premap_m2b &&
                hwdom_premap_m2b[PREMAP_M2B_PAGE(mfn)] &&
                read_atomic(&PREMAP_M2B(mfn)) )
            {
                /* Remove M2B entry */
                write_atomic(&PREMAP_M2B(mfn), 0);
            }
            if ( !(op->flags & IOMMU_MAP_OP_no_ref_cnt) )
                put_page(page);

            op->status = 0;
            break;
        }
#ifdef CONFIG_X86
        case IOMMUOP_map_foreign_page:
        {
            unsigned long mfn, tmp;
            unsigned int flags = 0;
            struct page_info *page = NULL;

            /* Check if calling domain is Dom0 and can create IOMMU mappings */
            if ( !is_hardware_domain(d) || !can_use_iommu_check(d) )
            {
                op->status = -EPERM;
                goto finish;
            }

            rd = rcu_lock_domain_by_any_id(op->u.map_foreign_page.domid);
            if ( !rd )
            {
                op->status = -ENXIO;
                goto finish;
            }

            /* Only HVM domains can have their pages foreign mapped */
            if ( is_pv_domain(rd) )
            {
                op->status = -EPERM;
                goto finish;
            }

            if ( d->domain_id == op->u.map_foreign_page.domid ||
                    op->u.map_foreign_page.domid == DOMID_SELF )
            {
                op->status = -EPERM;
                goto finish;
            }

            /* Check for privilege over remote domain*/
            if ( xsm_iommu_control(XSM_DM_PRIV, rd, op->subop_id) )
            {
                op->status = -EPERM;
                goto finish;
            }

            /* Lookup page struct backing gfn */
            if ( get_paged_frame(op->u.map_foreign_page.gfn, &mfn, &page, 0,
                        rd) )
            {
                op->status = -ENXIO;
                goto finish;
            }

            /* Check for existing mapping */
            if ( test_bit(_PGC_foreign_map, &page->count_info) )
            {
                put_page(page);
                op->status = 0;
                goto finish;
            }

            if ( !mfn_valid(_mfn(mfn)) || xen_in_range(mfn) ||
                 is_xen_heap_page(page)  ||
                 (page->count_info & PGC_allocated) ||
                 ( (page->count_info & PGC_count_mask) < 2 ))
            {
                put_page(page);
                op->status = -EPERM;
                goto finish;
            }

            /* Check for conflict with existing BFN mapping */
            if ( !iommu_lookup_page(d, op->u.map_foreign_page.bfn, &tmp) )
            {
                put_page(page);
                op->status = -EPERM;
                goto finish;
            }

            if ( op->flags & IOMMU_OP_readable )
                flags |= IOMMUF_readable;

            if ( op->flags & IOMMU_OP_writeable )
                flags |= IOMMUF_writable;

            if ( iommu_legacy_map(d, op->u.map_foreign_page.bfn, mfn, 0,
                                  flags) )
            {
                put_page(page);
                op->status = -EIO;
                goto finish;
            }

            set_bit(_PGC_foreign_map, &page->count_info);
            op->status = 0;
            break;
        }
        case IOMMUOP_lookup_foreign_page:
        {
            unsigned long mfn;
            struct page_info *page = NULL;
            int rc;

            /* Check if calling domain is Dom0 */
            if ( !is_hardware_domain(d) )
            {
                op->status = -EPERM;
                goto finish;
            }

            if ( d->domain_id == op->u.lookup_foreign_page.domid ||
                 op->u.lookup_foreign_page.domid == DOMID_SELF )
            {
                op->status = -EPERM;
                goto finish;
            }

            rd = rcu_lock_domain_by_any_id(op->u.lookup_foreign_page.domid);
            if ( !rd )
            {
                op->status = -ENXIO;
                goto finish;
            }

            /* Only HVM domains can have their pages foreign mapped */
            if ( is_pv_domain(rd) )
            {
                op->status = -EPERM;
                goto finish;
            }

            /* Check for privilege */
            if ( xsm_iommu_control(XSM_DM_PRIV, rd, op->subop_id) )
            {
                op->status = -EPERM;
                goto finish;
            }

            /* Lookup page struct backing gfn */
            if ( (rc = get_paged_frame(op->u.lookup_foreign_page.gfn, &mfn, &page, 0,
                                 rd)) )
            {
                op->status = -ENXIO; // Should this be something else?
                goto finish;
            }

            /* Only create BFN mappings for guest mapped memory */
            if ( !(page->count_info & PGC_allocated) ||
                 ( (page->count_info & PGC_count_mask) < 2 ))
            {
                    put_page(page);
                    op->status = -EPERM;
                    goto finish;
            }

            /* Check if IOMMU is disabled/bypassed */
            if ( !can_use_iommu_check(d) )
            {
                if ( test_and_set_bit(_PGC_foreign_map, &page->count_info) )
                    put_page(page);

                op->u.lookup_foreign_page.bfn = mfn;
            }
            else
            {
                uint64_t bfn;
                /* Check if a premap already exists */
                if ( !hwdom_premap_m2b ||
                     !hwdom_premap_m2b[PREMAP_M2B_PAGE(mfn)])
                {
                    put_page(page);
                    op->status = -ENOENT;
                    goto finish;
                }

                bfn = read_atomic(&PREMAP_M2B(mfn));

                /* Check if BFN is non zero */
                if ( !bfn )
                {
                    put_page(page);
                    op->status = -ENOENT;
                    goto finish;
                }

                if ( test_and_set_bit(_PGC_foreign_map, &page->count_info) )
                    put_page(page);

                op->u.lookup_foreign_page.bfn = bfn;
            }

            op->status = 0;
            break;
        }
        case IOMMUOP_unmap_foreign_page:
        {
            struct page_info *page;
            unsigned long mfn;

            /* Check if calling domain is Dom0 */
            if ( !is_hardware_domain(d) )
            {
                op->status = -EPERM;
                goto finish;
            }

            if ( !can_use_iommu_check(d) )
            {
                page = mfn_to_page(_mfn(op->u.unmap_foreign_page.bfn));
            }
            else
            {
                /* Check if there is a valid BFN mapping for this domain */
                if ( iommu_lookup_page(d, op->u.unmap_foreign_page.bfn, &mfn) )
                {
                   op->status = -ENOENT;
                   goto finish;
                }
                /* Use MFN from B2M mapping to lookup page */
                page = mfn_to_page(_mfn(mfn));
            }

            if ( !page )
            {
               op->status = -ENOENT;
               goto finish;
            }

            if ( !test_and_clear_bit(_PGC_foreign_map, &page->count_info) )
            {
               op->status = -ENOENT;
               goto finish;
            }

            if ( !can_use_iommu_check(d) )
                goto foreign_unmap_done;

            /* Check if hwdom IOMMU premap is present */
            if ( hwdom_premap_m2b && hwdom_premap_m2b[PREMAP_M2B_PAGE(mfn)] &&
                 (read_atomic(&PREMAP_M2B(mfn)) == op->u.unmap_foreign_page.bfn) )
                goto foreign_unmap_done;

            if ( iommu_legacy_unmap(d, op->u.unmap_foreign_page.bfn, 0) )
                domain_crash(d);
foreign_unmap_done:
            /* Remove the reference to the page */
            put_page(page);
            op->status = 0;
        break;
        }
#endif
        default:
            op->status = -ENODEV;
            break;
    }

finish:
    if ( rd )
        rcu_unlock_domain(rd);

    return;
}

ret_t do_iommu_op(XEN_GUEST_HANDLE_PARAM(void) arg, unsigned int count)
{
    ret_t ret = 0;
    int i;
    struct pv_iommu_op op;
    struct domain *d = current->domain;

    if ( !is_hardware_domain(d) )
        return -ENOSYS;

    if ( (int)count < 0 )
        return -EINVAL;

    if ( count > 1 )
        this_cpu(iommu_dont_flush_iotlb) = 1;

    for ( i = 0; i < count; i++ )
    {
        if ( i && hypercall_preempt_check() )
        {
            ret =  i;
            goto flush_pages;
        }
        if ( unlikely(__copy_from_guest_offset(&op, arg, i, 1)) )
        {
            ret = -EFAULT;
            goto flush_pages;
        }
        do_iommu_sub_op(&op);
        if ( unlikely(__copy_to_guest_offset(arg, i, &op, 1)) )
        {
            ret = -EFAULT;
            goto flush_pages;
        }
    }

flush_pages:
    if ( count > 1 )
    {
        int rc = 0;

        this_cpu(iommu_dont_flush_iotlb) = 0;
        if ( i )
            rc = iommu_iotlb_flush_all(
                d, IOMMU_FLUSHF_added | IOMMU_FLUSHF_modified);

        if ( rc < 0 )
            ret = rc;
    }
    if ( ret > 0 )
    {
        XEN_GUEST_HANDLE_PARAM(pv_iommu_op_t) op =
            guest_handle_cast(arg, pv_iommu_op_t);
        ASSERT(ret < count);
        guest_handle_add_offset(op, i);
        arg = guest_handle_cast(op, void);
        ret = hypercall_create_continuation(__HYPERVISOR_iommu_op,
                                           "hi", arg, count - i);
    }
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


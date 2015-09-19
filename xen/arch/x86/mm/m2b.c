/*
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <asm/m2b.h>
#include <asm/event.h>

struct pv_iommu_info
{
    struct page_info *pg;
    struct list_head head;
    unsigned int count;
    struct rcu_head rcu_head;
};

DEFINE_RCU_READ_LOCK(m2b_rcu);

struct m2b_entry *lookup_m2b_entry(struct page_info *page, struct domain *d,
                                   ioservid_t ioserver, unsigned long bfn)
{
    struct m2b_entry *m2b_e = NULL;
    struct list_head *entry;
    domid_t domain = d->domain_id;

    if ( !test_bit(_PGC_foreign_map, &page->count_info) )
        return NULL;

    rcu_read_lock(&m2b_rcu);
    list_for_each_rcu(entry, &page->pv_iommu->head)
    {
        m2b_e = list_entry(entry, struct m2b_entry, list);
        if ( m2b_e->domain == domain && m2b_e->ioserver == ioserver &&
                m2b_e->bfn == bfn )
                    goto done;
        else if ( ioserver == IOSERVER_ANY && m2b_e->domain == domain &&
                  m2b_e->bfn == bfn )
                    goto done;
        else if ( bfn == BFN_ANY && m2b_e->domain == domain &&
                  m2b_e->ioserver == ioserver )
                    goto done;
        else if ( bfn == BFN_ANY && ioserver == IOSERVER_ANY &&
                  m2b_e->domain == domain )
                    goto done;
    }
done:
    rcu_read_unlock(&m2b_rcu);

    /* Nothing was found */
    return m2b_e;
}

void notify_m2b_entries(struct page_info *page)
{
    return;
}

/* Called with page_lock held */
int add_m2b_entry(struct page_info *page, struct domain *d,
                  ioservid_t ioserver, uint64_t bfn)
{
    struct m2b_entry *m2b_e;
    int head_allocated = 0;
    domid_t domain = d->domain_id;

    if ( !test_bit(_PGC_foreign_map, &page->count_info) )
    {
        page->pv_iommu = xmalloc(struct pv_iommu_info);
        if ( !page->pv_iommu )
            return -ENOMEM;
        head_allocated = 1;
        INIT_LIST_HEAD(&page->pv_iommu->head);
        INIT_RCU_HEAD(&page->pv_iommu->rcu_head);
        set_bit(_PGC_foreign_map, &page->count_info);
        page->pv_iommu->count = 0;
    }

    m2b_e = xmalloc(struct m2b_entry);
    if ( !m2b_e )
    {
        if ( head_allocated )
            xfree(page->pv_iommu);

        return -ENOMEM;
    }

    m2b_e->domain = domain;
    m2b_e->ioserver = ioserver;
    m2b_e->bfn = bfn;

    INIT_LIST_HEAD(&m2b_e->list);
    INIT_RCU_HEAD(&m2b_e->rcu);
    list_add_rcu(&m2b_e->list, &page->pv_iommu->head);

    atomic_inc(&d->m2b_count);
    page->pv_iommu->count++;
    return 0;
}

void free_m2b_entry(struct rcu_head *rcu)
{
    xfree(container_of(rcu, struct m2b_entry, rcu));
}

/* Called with page_lock held */
int del_m2b_entry(struct page_info *page, struct domain *d, ioservid_t ioserver,
                  unsigned long bfn)
{
    struct m2b_entry *m2b_e;

    m2b_e = lookup_m2b_entry(page, d, ioserver, bfn);
    if ( !m2b_e )
        return -ENOENT;

    list_del_rcu(&m2b_e->list);
    call_rcu(&m2b_e->rcu, free_m2b_entry);
    page->pv_iommu->count--;
    atomic_dec(&d->m2b_count);

    if ( page->pv_iommu->count == 0 )
    {
        clear_bit(_PGC_foreign_map, &page->count_info);
        xfree(page->pv_iommu);
    }
    return 0;
}


/* Remove all M2B entries created by the domain being destroyed */
int m2b_domain_destroy(struct domain *d, unsigned long mfn)
{
    struct m2b_entry *m2b_e, *m2b_e_hwdom;
    struct page_info *page;
    int locked;

    if ( ! atomic_read(&d->m2b_count) )
        return 0;


    for ( ; mfn < max_page; mfn++ )
    {
        /* Check for preemption every 4 MB */
        if ( mfn % 0x1000 == 0 && mfn != d->m2b_destroy_mfn)
        {
            if ( hypercall_preempt_check() )
            {
                d->m2b_destroy_mfn = mfn;
                return -ERESTART;
            }
        }
        if (!mfn_valid(mfn))
            continue;

        page = mfn_to_page(mfn);
        if ( !page || (page_get_owner(page) != d) )
            continue;

        m2b_e = lookup_m2b_entry(page, d,
                        IOSERVER_ANY, BFN_ANY);
        m2b_e_hwdom = lookup_m2b_entry(page, hardware_domain,
                        IOSERVER_ANY, BFN_ANY);
        if ( !m2b_e && !m2b_e_hwdom )
            continue;

        locked = page_lock(page);

        /* Remove all M2B entries for this domain */
        while ( (m2b_e = lookup_m2b_entry(page, d,
                                          IOSERVER_ANY, BFN_ANY)) )
        {
            del_m2b_entry(page, d,
                          m2b_e->ioserver,
                          m2b_e->bfn);
        }
        /* Remove all M2B entries for hwdom */
        while ( (m2b_e = lookup_m2b_entry(page, hardware_domain,
                                          IOSERVER_ANY, BFN_ANY)) )
        {
            del_m2b_entry(page, hardware_domain,
                          m2b_e->ioserver,
                          m2b_e->bfn);
            atomic_dec(&d->m2b_count);
        }

        if ( locked )
            page_unlock(page);
        /* Remove this domains reference */
        put_page(page);
        if ( ! atomic_read(&d->m2b_count) )
            break;
    }

    return 0;
}

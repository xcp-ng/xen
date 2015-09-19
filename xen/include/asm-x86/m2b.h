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

#ifndef __XEN_M2B_H__
#define __XEN_M2B_H__

#include <xen/sched.h>

struct m2b_entry
{
    struct list_head list;
    domid_t domain;
    ioservid_t ioserver;
    uint64_t bfn;
    struct rcu_head rcu;
};

int m2b_domain_destroy(struct domain *d, unsigned long mfn);

void notify_m2b_entries(struct page_info *page);

#define BFN_ANY         ~0UL
#define IOSERVER_ANY    ~0

struct m2b_entry *lookup_m2b_entry(struct page_info *page, struct domain *d,
                                   ioservid_t ioserver, unsigned long bfn);
int add_m2b_entry(struct page_info *page, struct domain *d,
                  ioservid_t ioserver, uint64_t bfn);
int del_m2b_entry(struct page_info *page, struct domain *d, ioservid_t ioserver,
                  unsigned long bfn);

extern uint64_t **hwdom_premap_m2b;

#define PREMAP_M2B_PAGE(x) ( pfn_to_pdx(x) / (PAGE_SIZE/sizeof(uint64_t) ) )
#define PREMAP_M2B_IDX(x) ( pfn_to_pdx(x) % (PAGE_SIZE/sizeof(uint64_t) ) )
#define PREMAP_M2B(x) hwdom_premap_m2b[PREMAP_M2B_PAGE(x)][PREMAP_M2B_IDX(x)]

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

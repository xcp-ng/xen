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

#ifndef __XEN_PUBLIC_PV_IOMMU_H__
#define __XEN_PUBLIC_PV_IOMMU_H__

#include "xen.h"

#define IOMMUOP_query_caps            1
#define IOMMUOP_map_page              2
#define IOMMUOP_unmap_page            3
#define IOMMUOP_map_foreign_page      4
#define IOMMUOP_lookup_foreign_page   5
#define IOMMUOP_unmap_foreign_page    6

struct pv_iommu_op {
    uint16_t subop_id;

#define IOMMU_page_order (0xf1 << 10)
#define IOMMU_get_page_order(flags) ((flags & IOMMU_page_order) >> 10)
#define IOMMU_QUERY_map_cap (1 << 0)
#define IOMMU_QUERY_map_all_mfns (1 << 1)
#define IOMMU_OP_readable (1 << 0)
#define IOMMU_OP_writeable (1 << 1)
#define IOMMU_MAP_OP_no_ref_cnt (1 << 2)
    uint16_t flags;
    int32_t status;

    union {
        struct {
            uint64_t offset;
        } query_caps;

        struct {
            uint64_t bfn;
            uint64_t gfn;
        } map_page;

        struct {
            uint64_t bfn;
        } unmap_page;

        struct {
            uint64_t bfn;
            uint64_t gfn;
            uint16_t domid;
            uint16_t ioserver;
        } map_foreign_page;

        struct {
            uint64_t bfn;
            uint64_t gfn;
            uint16_t domid;
            uint16_t ioserver;
        } lookup_foreign_page;

        struct {
            uint64_t bfn;
            uint16_t ioserver;
        } unmap_foreign_page;
    } u;
};


typedef struct pv_iommu_op pv_iommu_op_t;
DEFINE_XEN_GUEST_HANDLE(pv_iommu_op_t);

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

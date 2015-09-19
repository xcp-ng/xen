/******************************************************************************
 * xc_iommu.c
 *
 * API for PV IOMMU control.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Copyright (C) 2015, Citrix Systems R&D Ltd..
 */

#include "xc_private.h"
#include "xc_core.h"
#include "xg_private.h"
#include <xen/pv-iommu.h>

int xc_iommu_op(xc_interface *xch, struct pv_iommu_op *ops, unsigned int count)
{
    DECLARE_HYPERCALL_BOUNCE(ops, count * sizeof(*ops),
                             XC_HYPERCALL_BUFFER_BOUNCE_BOTH);
    int ret;

    if ( xc_hypercall_bounce_pre(xch, ops) )
    {
        PERROR("Could not bounce memmory for IOMMU hypercall");
        return -1;
    }

    ret = xencall2(xch->xcall, __HYPERVISOR_iommu_op,
                   HYPERCALL_BUFFER_AS_ARG(ops), count);

    xc_hypercall_bounce_post(xch, ops);

    if ( ret < 0 )
    {
        errno = -ret;
        ret = -1;
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

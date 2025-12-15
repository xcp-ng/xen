/*
 * Confidential computing support.
 * Copyright (c) 2024 Teddy Astie <teddy.astie@vates.tech>
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
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xg_private.h"
#include "xenctrl.h"
#include "xg_dom_coco.h"

int xg_dom_coco_encrypt_seg(xc_interface *xch, struct xc_dom_image *dom,
                            struct xc_dom_seg seg, const char *name)
{
    coco_prepare_initial_mem_t cmd;
    DPRINTF("coco: Encrypting pfn:[%"PRI_xen_pfn"-%"PRI_xen_pfn"] (%s)\n",
            seg.pfn, seg.pfn + seg.pages, name);
    
    cmd.domid = dom->guest_domid;
    cmd.gfn = seg.pfn;
    cmd.count = seg.pages;
    
    return xc_coco_prepare_initial_mem(xch, &cmd);
}

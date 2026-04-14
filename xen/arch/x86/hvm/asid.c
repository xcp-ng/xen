/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asid.c: ASID management
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2009, Citrix Systems, Inc.
 */

#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/spinlock.h>
#include <xen/xvmalloc.h>

#include <asm/bitops.h>
#include <asm/hvm/asid.h>

/* Xen command-line option to enable ASIDs */
static bool __read_mostly opt_asid_enabled = true;
boolean_param("asid", opt_asid_enabled);

bool __read_mostly asid_enabled = false;
static unsigned long __ro_after_init *asid_bitmap;
static unsigned long __ro_after_init asid_count;
static DEFINE_SPINLOCK(asid_lock);

/*
 * Sketch of the Implementation:
 * ASIDs are assigned uniquely per domain and doesn't change during the lifecycle of the
 * domain. Once vcpus are initialized and are up, we assign the same ASID to all vcpus
 * of that domain at the first VMRUN. In order to process a TLB flush on a vcpu, we set
 * needs_tlb_flush to schedule a TLB flush for the next VMRUN (e.g using tlb control 
 * field of VMCB).
 *
 * We reserve ASID=1 as being the ASID used when none other is available (or with asid
 * use disabled). Multiples domains may use this ASID, thus we need to systematically
 * flush the TLB for this one when switching between vCPUs with ASID=1.
 */

int __init hvm_asid_init(unsigned long nasids)
{
    ASSERT(nasids);

    asid_count = nasids;
    asid_enabled = opt_asid_enabled && (nasids > 1);

    asid_bitmap = xvzalloc_array(unsigned long, BITS_TO_LONGS(asid_count + 1));
    if ( !asid_bitmap )
        return -ENOMEM;

    printk("HVM: ASIDs %sabled (count=%lu)\n", asid_enabled ? "en" : "dis", asid_count);

    /* ASID 0 and 1 are reserved, mark it as permanently used */
    set_bit(0, asid_bitmap);
    set_bit(1, asid_bitmap);

    return 0;
}

int hvm_asid_alloc(struct hvm_asid *asid)
{
    unsigned long new_asid;

    if ( !asid_enabled )
    {
        asid->asid = 1;
        return 0;
    }

    spin_lock(&asid_lock);
    new_asid = find_first_zero_bit(asid_bitmap, asid_count);
    if ( new_asid > asid_count )
        return -ENOSPC;

    set_bit(new_asid, asid_bitmap);

    asid->asid = new_asid;
    spin_unlock(&asid_lock);
    return 0;
}

int hvm_asid_alloc_range(struct hvm_asid *asid, unsigned long min, unsigned long max)
{
    unsigned long new_asid;
    
    if ( WARN_ON(min >= asid_count) )
        return -EINVAL;

    if ( !asid_enabled )
        return -EOPNOTSUPP;

    spin_lock(&asid_lock);
    new_asid = find_next_zero_bit(asid_bitmap, asid_count, min);
    if ( new_asid > max || new_asid > asid_count )
        return -ENOSPC;

    set_bit(new_asid, asid_bitmap);

    asid->asid = new_asid;
    spin_unlock(&asid_lock);
    return 0;
}

void hvm_asid_free(struct hvm_asid *asid)
{
    ASSERT( asid->asid );

    if ( !asid_enabled || asid->asid == 1 )
        return;

    ASSERT( asid->asid < asid_count );

    spin_lock(&asid_lock);
    WARN_ON(!test_bit(asid->asid, asid_bitmap));
    clear_bit(asid->asid, asid_bitmap);
    spin_unlock(&asid_lock);
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

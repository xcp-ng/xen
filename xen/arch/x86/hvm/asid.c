/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asid.c: ASID management
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2009, Citrix Systems, Inc.
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/param.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/percpu.h>

#include <asm/bitops.h>
#include <asm/hvm/asid.h>

/* Xen command-line option to enable ASIDs */
static bool __read_mostly opt_asid_enabled = true;
boolean_param("asid", opt_asid_enabled);

unsigned long *hvm_asid_bitmap;
unsigned long *hvm_reclaim_asid_bitmap;
static DEFINE_SPINLOCK(hvm_asid_lock);

/*
 * Sketch of the Implementation:
 * ASIDs are assigned in a round-robin scheme per domain as part of
 * global allocator scheme and doesn't change during the lifecycle of
 * the domain. Once vcpus are initialized and are up, we assign the
 * same ASID to all vcpus of that domain at the first VMRUN. With the
 * new scheme, we don't need to assign the new ASID during MOV-TO-{CR3,
 * CR4}. In the case of INVLPG, we flush the TLB entries belonging to
 * the vcpu and do the reassignment of the ASID belonging to the given
 * domain.  Currently we do not do anything special for flushing guest
 * TLBs in flush_area_local as wbinvd() should able to handle this. In
 * the future Xen should be able to take an advantage of TLBSYNC and
 * INVLPGB (AMD SVM) with this scheme.

 * When the domain is destroyed, ASID goes to the reclaimable ASID pool
 * for the reuse. We only go for checking in the reclaimable ASID pool
 * when we run out of ASIDs in the hvm_asid_bitmap.
 */

/* Xen-wide ASID management */
struct hvm_asid_data {
   uint32_t min_asid;
   uint32_t next_asid;
   uint32_t max_asid;
   bool disabled;
};

static struct hvm_asid_data asid_data;

int hvm_asid_init(int nasids)
{
    struct hvm_asid_data *data = &asid_data;
    static int8_t g_disabled = -1;

    /* TODO(vaishali): Once we have SEV Operations, min_asid need to be
    adjusted in SEV specific functions */
    data->min_asid = 1;
    data->max_asid = nasids - data->min_asid;
    data->disabled = !opt_asid_enabled || (nasids <= 1);

    hvm_asid_bitmap = xzalloc_array(unsigned long,
                                    BITS_TO_LONGS(data->max_asid));
    if ( !hvm_asid_bitmap )
        return -ENOMEM;

    hvm_reclaim_asid_bitmap = xzalloc_array(unsigned long,
                                            BITS_TO_LONGS(data->max_asid));
    if ( !hvm_reclaim_asid_bitmap ) {
        xfree(hvm_asid_bitmap);
        hvm_asid_bitmap = NULL;
    }

    if ( g_disabled != data->disabled )
    {
        printk("HVM: ASIDs %sabled.\n", data->disabled ? "dis" : "en");
        if ( g_disabled < 0 )
            g_disabled = data->disabled;
    }

    /* ASID 0 is reserved, so we start the counting from 1 */
    data->next_asid = find_next_zero_bit(hvm_asid_bitmap, data->min_asid,
                                         data->max_asid );

    return 0;
}

void hvm_asid_flush_domain_asid(struct hvm_domain_asid *asid)
{
    write_atomic(&asid->generation, 0);
}

void hvm_asid_flush_domain(struct domain *d)
{
    hvm_asid_flush_domain_asid(&d->arch.hvm.n1asid);
    hvm_asid_flush_domain_asid(&d->arch.hvm.nv_n2asid);
}

/* We still allow flushing on vcpu level for non-SEV domain */
void hvm_asid_flush_vcpu(struct vcpu *v)
{
    hvm_asid_flush_domain_asid(&v->domain->arch.hvm.n1asid);
    hvm_asid_flush_domain_asid(&v->domain->arch.hvm.nv_n2asid);
}

/* This function is called while creating a new domain */
bool hvm_asid_domain_create(struct hvm_domain_asid *asid)
{
    struct hvm_asid_data *data = &asid_data;

    /* On erratum #170 systems we must flush the TLB. 
     * Generation overruns are taken here, too. */
    if ( data->disabled )
        goto disabled;

    spin_lock(&hvm_asid_lock);

    /* We assume that next_asid > max_asid is unlikely at this point*/
    __test_and_set_bit(data->next_asid, hvm_asid_bitmap);

    /* Find the next available asid to assign to the domain*/
    data->next_asid = find_next_zero_bit(hvm_asid_bitmap, data->next_asid,
                                         data->max_asid) + 1;

    /* Check if there are any ASIDs to reclaim */
    if ( data->next_asid > data->max_asid ) {
        data->next_asid = find_next_bit(hvm_reclaim_asid_bitmap, 0,
                                             data->max_asid+1);
        spin_unlock(&hvm_asid_lock);

        if ( data->disabled )
            goto disabled;

        if ( data->next_asid > data->max_asid )
            return -EBUSY;
    }

    spin_unlock(&hvm_asid_lock);

    asid->asid = data->next_asid;

    return 0;

 disabled:
    asid->asid = 0;
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

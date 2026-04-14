/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asid.c: handling ASIDs/VPIDs.
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 */

#include <xen/cpumask.h>

#include <asm/amd.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm.h>
#include <asm/processor.h>

#include "svm.h"
#include "vmcb.h"

void __init svm_asid_init(void)
{
    unsigned int cpu, nasids = cpuid_ebx(0x8000000aU);

    if ( !nasids )
        nasids = 1;

    for_each_present_cpu(cpu)
    {
        /* Check for erratum #170, and leave ASIDs disabled if it's present. */
        if ( cpu_has_amd_erratum(&cpu_data[cpu], AMD_ERRATUM_170) )
        {
            printk(XENLOG_WARNING "Disabling ASID due to errata 170 on CPU%u\n", cpu);
            nasids = 1;
        }
    }

    BUG_ON(hvm_asid_init(nasids));
}

/*
 * Called directly at the first VMRUN/VMENTER of a vcpu to assign the ASID/VPID.
 */
void svm_vcpu_assign_asid(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct hvm_asid *p_asid = &v->domain->arch.hvm.asid;

    /* ASID 0 indicates that ASIDs are disabled. */
    if ( p_asid->asid == 0 )
    {
        vmcb_set_asid(vmcb, 1);
        vmcb->tlb_control =
            cpu_has_svm_flushbyasid ? TLB_CTRL_FLUSH_ASID : TLB_CTRL_FLUSH_ALL;
        return;
    }

    /* In case ASIDs are disabled, as ASID = 0 is reserved, guest can use 1 instead. */
    vmcb_set_asid(vmcb, asid_enabled ? p_asid->asid : 1);
}

/* Call to make a TLB flush at the next VMRUN. */
void svm_vcpu_set_tlb_control(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    /*
     * If the vcpu is already running, the tlb control flag may not be
     * processed and will be cleared at the next VMEXIT, which will undo
     * what we are trying to do.
     */
    WARN_ON(v != current && v->is_running);

    vmcb->tlb_control =
        cpu_has_svm_flushbyasid ? TLB_CTRL_FLUSH_ASID : TLB_CTRL_FLUSH_ALL;
}

void svm_vcpu_clear_tlb_control(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    vmcb->tlb_control = TLB_CTRL_NO_FLUSH;
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

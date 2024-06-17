/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asid.c: handling ASIDs in SVM.
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 */

#include <xen/cpumask.h>

#include <asm/processor.h>
#include <asm/amd.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/svm.h>

#include "svm.h"

void __init svm_asid_init(void)
{
    unsigned int cpu = smp_processor_id();
    const struct cpuinfo_x86 *c;
    int nasids = 0;

    c = &cpu_data[cpu];

    /* Check for erratum #170, and leave ASIDs disabled if it's present. */
    if ( !cpu_has_amd_erratum(c, AMD_ERRATUM_170) )
        nasids = cpuid_ebx(0x8000000aU);

    hvm_asid_init(nasids);
}

/*
 * Called directly at the VMRUN of a domain to assign
 * the asid to all associated vcpus of that domain
 */
void svm_vcpu_assign_asid(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct hvm_domain_asid *p_asid = &v->domain->arch.hvm.n1asid;

    /* ASID 0 indicates that ASIDs are disabled. */
    if ( p_asid->asid == 0 )
    {
        vmcb_set_asid(vmcb, true);
        vmcb->tlb_control =
            cpu_has_svm_flushbyasid ? TLB_CTRL_FLUSH_ASID :
            TLB_CTRL_FLUSH_ALL;
        return;
    }

    if ( vmcb_get_asid(vmcb) != p_asid->asid ) {
        vmcb_set_asid(vmcb, p_asid->asid);
        vmcb->tlb_control = cpu_has_svm_flushbyasid ? TLB_CTRL_FLUSH_ASID :
                            TLB_CTRL_FLUSH_ALL;
    }
    else
        return;
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

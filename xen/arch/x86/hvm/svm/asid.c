/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asid.c: handling ASIDs in SVM.
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 */

#include <asm/amd.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/asid.h>
#include <asm/hvm/svm/vmcb.h>
#include "svm.h"

void svm_asid_init(const struct cpuinfo_x86 *c)
{
    struct svm_asid_data *data = &this_cpu(svm_asid_data);
    data->nr_asids = 0;
    /* Check for erratum #170, and leave ASIDs disabled if it's present. */
    if ( !cpu_has_amd_erratum(c, AMD_ERRATUM_170) )
        data->nr_asids = cpuid_ebx(0x8000000aU);

    hvm_asid_init(data->nr_asids);

}

/*
 * Called directly before VMRUN.  Checks if the VCPU needs a new ASID,
 * assigns it, and if required, issues required TLB flushes.
 */
void svm_asid_handle_vmrun(void)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm.svm.vmcb;
    struct hvm_vcpu_asid *p_asid =
        nestedhvm_vcpu_in_guestmode(curr)
        ? &vcpu_nestedhvm(curr).nv_n2asid : &curr->arch.hvm.n1asid;
    struct svm_asid_data *data = &this_cpu(svm_asid_data);
    struct vmcb_struct *previous_vmcb = data->last_vmcbs[vmcb->_asid];
    struct svm_vcpu *svm = &curr->arch.hvm.svm;

    bool need_flush = hvm_asid_handle_vmenter(p_asid);
    unsigned int cpu = smp_processor_id();

    /* ASID 0 indicates that ASIDs are disabled. */
    if ( p_asid->asid == 0 )
    {
        vmcb_set_asid(vmcb, true);
        vmcb->tlb_control =
            cpu_has_svm_flushbyasid ? TLB_CTRL_FLUSH_ASID : TLB_CTRL_NO_FLUSH;
        return;
    }

    //If there is no cpu affinity change and no vmcb change, choose fast path
    if ( previous_vmcb == vmcb && cpu == svm->last_cpu ) {
        if ( vmcb_get_asid(previous_vmcb) != p_asid->asid ) {
            p_asid->asid = vmcb_get_asid(previous_vmcb);
            vmcb_set_asid(vmcb, p_asid->asid); // TODO:might need to see if conflicts can happen here?
        }
    return; 
    }

    if ( vmcb_get_asid(vmcb) != p_asid->asid )
        vmcb_set_asid(vmcb, p_asid->asid);

    vmcb->tlb_control =
        !need_flush ? TLB_CTRL_NO_FLUSH :
        cpu_has_svm_flushbyasid ? TLB_CTRL_FLUSH_ASID : TLB_CTRL_FLUSH_ALL;
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

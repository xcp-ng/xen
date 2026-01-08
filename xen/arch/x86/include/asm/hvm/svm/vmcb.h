/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vmcb.h: VMCB related definitions
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc
 * Copyright (c) 2004, Intel Corporation.
 *
 */
#ifndef __ASM_X86_HVM_SVM_VMCB_H__
#define __ASM_X86_HVM_SVM_VMCB_H__

#include <xen/types.h>

#include <asm/psp-sev.h>

struct sev_state {
    uint32_t asp_handle;
    union sev_guest_policy asp_policy;
    uint8_t  measure[48];
    uint32_t measure_len; /* 48 bytes */
    unsigned long flags;
};

struct svm_domain {
    /* OSVW MSRs */
    union {
        uint64_t raw[2];
        struct {
            uint64_t length;
            uint64_t status;
        };
    } osvw;

#ifdef CONFIG_COCO_AMD_SEV
    struct sev_state sev;
#endif
};

struct ghcb;

struct sev_vcpu {
    struct page_info *vmsa_page;
    struct page_info *ghcb_page;
    uint64_t ghcb_gfn;
    struct ghcb *ghcb_map;

    /*
     * Track if vCPU is in NMI, only used for SEV-ES.
     * This is used to implement GHCB Non-Maskable Interrupts.
     */
    bool in_nmi;
};

struct svm_vcpu {
    struct vmcb_struct *vmcb;
    u64    vmcb_pa;
    unsigned long *msrpm;
    int    launch_core;

    struct sev_vcpu sev;

    uint8_t vmcb_sync_state; /* enum vmcb_sync_state */

    /* VMCB has a cached instruction from #PF/#NPF Decode Assist? */
    uint8_t cached_insn_len; /* Zero if no cached instruction. */

    /* Upper four bytes are undefined in the VMCB, therefore we can't
     * use the fields in the VMCB. Write a 64bit value and then read a 64bit
     * value is fine unless there's a VMRUN/VMEXIT in between which clears
     * the upper four bytes.
     */
    uint64_t guest_sysenter_cs;
    uint64_t guest_sysenter_esp;
    uint64_t guest_sysenter_eip;
};

#define MSR_INTERCEPT_NONE    0
#define MSR_INTERCEPT_READ    1
#define MSR_INTERCEPT_WRITE   2
#define MSR_INTERCEPT_RW      (MSR_INTERCEPT_WRITE | MSR_INTERCEPT_READ)
void svm_intercept_msr(struct vcpu *v, uint32_t msr, int flags);
#define svm_disable_intercept_for_msr(v, msr) svm_intercept_msr((v), (msr), MSR_INTERCEPT_NONE)
#define svm_enable_intercept_for_msr(v, msr) svm_intercept_msr((v), (msr), MSR_INTERCEPT_RW)

#endif /* ASM_X86_HVM_SVM_VMCS_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

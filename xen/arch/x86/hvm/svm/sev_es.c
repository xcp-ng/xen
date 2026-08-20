/* SPDX-License-Identifier: GPL-2.0-only */
/*
* sev_es.c: handling SEV-ES specific logic
*
* Copyright (c) 2025 Vates SAS.
*/

#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/fastabi.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/trace.h>

#include <asm/cpuid.h>
#include <asm/cpu-policy.h>
#include <asm/fastabi.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/sev_es.h>
#include <asm/p2m.h>

#include "vmcb.h"
#include "sev_es.h"
#include "xen/coco.h"

#define GHCB_VALID_BIT(field) \
({ \
    const unsigned long _offset_bit = offsetof(struct ghcb_save_area, field) / 8; \
    BUILD_BUG_ON(_offset_bit >= 128); \
    _offset_bit; \
})

#define GHCB_TEST_VALID(ghcb, field) \
    test_bit(GHCB_VALID_BIT(field), (ghcb)->save.valid_bitmap)

#define GHCB_SET_VALID(ghcb, field) \
    __set_bit(GHCB_VALID_BIT(field), (ghcb)->save.valid_bitmap)

#define GHCB_SET_FIELD(ghcb, field, value) do { \
    GHCB_SET_VALID(ghcb, field); \
    ghcb->save.field = value; \
} while (0);

#define GHCB_CLEAR_VALID(ghcb) \
    bitmap_clear((ghcb)->save.valid_bitmap, 0, 128)

static int sev_es_update_vmsa(struct vcpu *v, gfn_t vmsa_gfn, bool start)
{
    p2m_type_t p2mt;
    struct page_info *vmsa_page;
    struct svm_vcpu *svm_v = &v->arch.hvm.svm;
    /* TODO: This needs some work to make it actually safe. */

    gdprintk(XENLOG_DEBUG, "sev-es: GHCB AP Create v%d, vmsa=%"PRI_gfn", start=%d\n",
             v->vcpu_id, gfn_x(vmsa_gfn), start);

    /* If the vCPU is online, bail out. */
    if ( v->is_initialised && is_vcpu_online(v) )
    {
        gdprintk(XENLOG_DEBUG, "sev-es: GHCB AP Create v%d: vCPU is already up\n", v->vcpu_id);
        return -EBUSY;
    }

    /* Get the VMSA page */
    vmsa_page = get_page_from_gfn(v->domain, gfn_x(vmsa_gfn), &p2mt, P2M_ALLOC);

    if ( p2mt != p2m_ram_rw )
    {
        gprintk(XENLOG_WARNING,
                "sev-es: Invalid VMSA page type: gfn=%"PRI_xen_pfn", %d != %d\n",
                gfn_x(vmsa_gfn), p2mt, p2m_ram_rw);

        if ( vmsa_page )
            put_page(vmsa_page);
        return -EINVAL;
    }

    /* If the vCPU already has a VMSA page, unregister it. */
    if ( svm_v->sev.vmsa_page )
    {
        /* TODO: VMSA page is not always get_page()'d */
        //struct page_info *old_vmsa_page = svm_v->sev.vmsa_page;
        svm_v->vmcb->vmsa_pa = 0;
        svm_v->sev.vmsa_page = 0;
        smp_wmb();
        //put_page(old_vmsa_page);
    }

    /* Register the new VMSA page */
    svm_v->sev.vmsa_page = vmsa_page;
    svm_v->vmcb->vmsa_pa = page_to_maddr(vmsa_page);
    smp_wmb();

    /* If the CPU hasn't been initialized, initialize it */
    if ( !v->is_initialised )
    {
        paging_update_paging_modes(v);
        v->is_initialised = 1;
        set_bit(_VPF_down, &v->pause_flags);
    }

    if ( start )
    {
        clear_bit(_VPF_down, &v->pause_flags);
        vcpu_wake(v);
    }

    return 0;
}

static void ghcb_ap_creation(struct vcpu *v, struct ghcb *ghcb)
{
    /*
     * On Xen, for SMP implementation purposes, we implement GHCB v2 "SNP AP Creation"
     * for SEV-ES guests; in this case, rules slightly deviate from specification :
     *  - there is no need to transition the VMSA page with RMPADJUST (since this
     *    mechanism doesn't exist in SEV-ES), any "ram" guest page is accepted
     *  - there is no VMPL support
     *  - SEV_FEATURES is restricted to the ones available to SEV-ES guests (TODO)
     */
    struct domain *currd = v->domain;
    struct vcpu *candidate_v, *target_v = NULL;
    /*
     * SW_EXITINFO1[15:0] = Command
     * SW_EXITINFO1[19:16] = VMPL
     * SW_EXITINFO1[31:20] = 0
     * SW_EXITINFO1[63:32] = APIC
     */
    union snp_ap_creation_param {
        uint64_t raw;
        struct {
            uint16_t cmd;
            unsigned int vmpl:4;
            unsigned int mbz:12;
            uint32_t apic_id;
        };
    };

    uint64_t sev_features = ghcb->save.rax;
    union snp_ap_creation_param param = { .raw = ghcb->save.sw_exitinfo1 };
    uint64_t vmsa = ghcb->save.sw_exitinfo2;
    smp_rmb();

    if ( !GHCB_TEST_VALID(ghcb, rax) )
        sev_features = 0;
    
    if ( param.mbz )
    {
        gdprintk(XENLOG_WARNING, "sev-es: MBZ bit set in SW_EXITINFO1 in AP creation\n");
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
        return;
    }

    if ( sev_features )
    {
        gdprintk(XENLOG_WARNING, "sev-es: TODO: support for SEV_FEATURES\n");
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
    }

    if ( param.vmpl )
    {
        /* TODO: SEV-SNP VMPL support */
        gdprintk(XENLOG_WARNING, "sev-es: Rejecting AP creation with VMPL > 0\n");
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
        return;
    }

    /* Find the matching vCPU */
    for_each_vcpu( currd, candidate_v )
    {
        gdprintk(XENLOG_DEBUG, "sev-es:- %d == %d?\n", VLAPIC_ID(vcpu_vlapic(candidate_v)), param.apic_id);
        if ( VLAPIC_ID(vcpu_vlapic(candidate_v)) == param.apic_id )
        {
            target_v = candidate_v;
            break;
        }
    }

    if ( !target_v )
    {
        gdprintk(XENLOG_WARNING, "sev-es: Unknown APIC ID %"PRIu32"\n", param.apic_id);
        /* No vCPU found. */
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
        return;
    }

    switch ( param.cmd )
    {
        case 0: /* Create/add */
        case 1: /* Create/add then run (VMPL) */
            if ( sev_es_update_vmsa(target_v, gaddr_to_gfn(vmsa), param.cmd == 1) )
            {
                GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
                GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
            }
            break;

        case 2: /* Destroy/remove */
            gprintk(XENLOG_WARNING, "sev-es: TODO: AP Creation cmd=%d\n", param.cmd);
            GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
            GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
            return;
    }

    GHCB_SET_FIELD(ghcb, sw_exitinfo1, 0);
    GHCB_SET_FIELD(ghcb, sw_exitinfo2, 0);
    smp_wmb();
}

int sev_es_build_vmsa(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct cpu_user_regs *regs = &v->arch.user_regs;
    void *vmsa;

    if ( !is_sev_es_domain(v->domain) )
        return -EINVAL;

    if ( !v->arch.hvm.svm.sev.vmsa_page )
        return -EINVAL;

    /* Stash guest CPU registers into VMCB including VMSA fields */
    vmcb->rax = regs->rax;
    vmcb->vmsa_regs.rbx = regs->rbx;
    vmcb->vmsa_regs.rcx = regs->rcx;
    vmcb->vmsa_regs.rdx = regs->rdx;
    vmcb->vmsa_regs.rbp = regs->rbp;
    vmcb->vmsa_regs.rsi = regs->rsi;
    vmcb->vmsa_regs.rdi = regs->rdi;
    vmcb->vmsa_regs.r8 = regs->r8;
    vmcb->vmsa_regs.r9 = regs->r9;
    vmcb->vmsa_regs.r10 = regs->r10;
    vmcb->vmsa_regs.r11 = regs->r11;
    vmcb->vmsa_regs.r12 = regs->r12;
    vmcb->vmsa_regs.r13 = regs->r13;
    vmcb->vmsa_regs.r14 = regs->r14;
    vmcb->vmsa_regs.r15 = regs->r15;
    vmcb->rip = regs->rip;
    vmcb->rsp = regs->rsp;
    vmcb->rflags = regs->rflags | X86_EFLAGS_MBS;

    vmcb->vmsa_regs.xcr0 = v->arch.xcr0 | X86_XCR0_X87;

    /*
     * Copy VMCB Save Area into VMSA page.
     * SEV-ES VMSA uses the same layout as VMCB save area.
     */
    vmsa = __map_domain_page(v->arch.hvm.svm.sev.vmsa_page);
    memcpy(vmsa, &vmcb->vmsa_start,
            sizeof(struct vmcb_struct) - offsetof(struct vmcb_struct, vmsa_start));
    cache_flush(vmsa, PAGE_SIZE);
    unmap_domain_page(vmsa);

    /* Clear VMSA-specific fields from VMCB (marked as reserved). */
    memset(&vmcb->vmsa_regs, 0, sizeof(vmcb->vmsa_regs));

    return 0;
}

static void sev_es_ghcb_call(struct vcpu *v, struct ghcb *ghcb)
{
    #ifdef CONFIG_COCO_SEV_STRICT_GHCB
    if ( !GHCB_TEST_VALID(ghcb, sw_exitcode) ||
         !GHCB_TEST_VALID(ghcb, sw_exitinfo1) ||
         !GHCB_TEST_VALID(ghcb, sw_exitinfo2) )
        goto malformed;
    #endif

    switch ( ghcb->save.sw_exitcode )
    {
    case VMEXIT_CPUID:
    {
        uint32_t leaf, subleaf;
        struct cpuid_leaf res;

        #ifdef CONFIG_COCO_SEV_STRICT_GHCB
        if ( !GHCB_TEST_VALID(ghcb, rax) || !GHCB_TEST_VALID(ghcb, rcx) )
            goto malformed;
        #endif

        leaf = ghcb->save.rax;
        subleaf = ghcb->save.rcx;

        smp_rmb();

        if ( leaf == 0x0d )
        {
            /* XCR0 handling */
            if ( GHCB_VALID_BIT(xcr0) )
                v->arch.xcr0 = ghcb->save.xcr0;
        }

        guest_cpuid(v, leaf, subleaf, &res);
        TRACE(TRC_HVM_CPUID, leaf, subleaf, res.a, res.b, res.c, res.d);

        v->arch.xcr0 = 0;

        GHCB_CLEAR_VALID(ghcb);

        GHCB_SET_FIELD(ghcb, rax, res.a);
        GHCB_SET_FIELD(ghcb, rbx, res.b);
        GHCB_SET_FIELD(ghcb, rcx, res.c);
        GHCB_SET_FIELD(ghcb, rdx, res.d);

        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 0);
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 0);
        smp_wmb();
        break;
    }

    case VMEXIT_MSR:
    {
        int rc;
        bool rdmsr = ghcb->save.sw_exitinfo1 == 0;
        uint32_t ecx = (uint32_t)ghcb->save.rcx;
        uint64_t msr_content = 0;

        #ifdef CONFIG_COCO_SEV_STRICT_GHCB
        if ( !GHCB_TEST_VALID(ghcb, rcx) )
            goto malformed;
        #endif
        smp_rmb();

        if ( rdmsr )
            rc = hvm_msr_read_intercept(ecx, &msr_content);
        else
        {
            #ifdef CONFIG_COCO_SEV_STRICT_GHCB
            if ( !GHCB_TEST_VALID(ghcb, rcx) )
                goto malformed;
            #endif

            msr_content = (ghcb->save.rdx << 32) | (uint32_t)ghcb->save.rax;
            smp_rmb();
            rc = hvm_msr_write_intercept(ecx, msr_content, false);
        }

        GHCB_CLEAR_VALID(ghcb);

        if ( rc == X86EMUL_OKAY )
        {
            if ( rdmsr )
            {
                GHCB_SET_FIELD(ghcb, rdx, (uint32_t)(msr_content >> 32));
                GHCB_SET_FIELD(ghcb, rax, (uint32_t)msr_content);
            }

            GHCB_SET_FIELD(ghcb, sw_exitinfo1, 0);
            GHCB_SET_FIELD(ghcb, sw_exitinfo2, 0);
        }
        else
        {
            /* Inject #GP */
            GHCB_SET_FIELD(ghcb, sw_exitinfo1, 1);
            GHCB_SET_FIELD(ghcb, sw_exitinfo2, X86_EXC_GP);
        }
        break;
    }

    case VMEXIT_VMMCALL:
    {
        /* Only copy FastABI registers */
        struct cpu_user_regs regs;

        /*
         * We avoid here checking for valid_bitmap to avoid excessive branching;
         * the ABI already enforces which registers are actually meaningful, we
         * don't need actually need this extra info.
         */
        #define GHCB_GET_FASTABI_REG(ghcb, regs, n) \
            fastabi_value_n(regs, n) = ghcb->save. fastabi_param_reg##n;

        /*
         * We set all ABI registers as valid in the bitmap. Even though some
         * registers will not be actually meaningful, security-wise, the guest is
         * only expected to honor those described in the hypercall ABI.
         */
        #define GHCB_SET_FASTABI_REG(ghcb, regs, n) \
            GHCB_SET_FIELD(ghcb, fastabi_param_reg##n, fastabi_value_n(regs, n))

        GHCB_GET_FASTABI_REG(ghcb, &regs, 0);
        GHCB_GET_FASTABI_REG(ghcb, &regs, 1);
        GHCB_GET_FASTABI_REG(ghcb, &regs, 2);
        GHCB_GET_FASTABI_REG(ghcb, &regs, 3);
        GHCB_GET_FASTABI_REG(ghcb, &regs, 4);
        GHCB_GET_FASTABI_REG(ghcb, &regs, 5);
        GHCB_GET_FASTABI_REG(ghcb, &regs, 6);
        GHCB_GET_FASTABI_REG(ghcb, &regs, 7);
        smp_rmb();

        HVM_DBG_LOG(DBG_LEVEL_HCALL,
            "ghcb hcall%lu(%lx, %lx, %lx, %lx, %lx, %lx, %lx)\n",
            regs.rax & ~0x40000000U, fastabi_value_n(&regs, 1), fastabi_value_n(&regs, 2),
            fastabi_value_n(&regs, 3), fastabi_value_n(&regs, 4),
            fastabi_value_n(&regs, 5), fastabi_value_n(&regs, 6),
            fastabi_value_n(&regs, 7));

        fastabi_dispatch(regs.rax & ~0x40000000U, &regs);

        GHCB_SET_FASTABI_REG(ghcb, &regs, 0);
        GHCB_SET_FASTABI_REG(ghcb, &regs, 1);
        GHCB_SET_FASTABI_REG(ghcb, &regs, 2);
        GHCB_SET_FASTABI_REG(ghcb, &regs, 3);
        GHCB_SET_FASTABI_REG(ghcb, &regs, 4);
        GHCB_SET_FASTABI_REG(ghcb, &regs, 5);
        GHCB_SET_FASTABI_REG(ghcb, &regs, 6);
        GHCB_SET_FASTABI_REG(ghcb, &regs, 7);

        #undef GHCB_GET_FASTABI_REG
        #undef GHCB_SET_FASTABI_REG
        break;

        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 0);
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 0);
    }

    case VMEXIT_IOIO:
        gdprintk(XENLOG_WARNING,
                 "sev-es: Ignoring IOIO request (exitinfo1=0x%"PRIx64")\n",
                 ghcb->save.sw_exitinfo1);
        GHCB_CLEAR_VALID(ghcb);

        /* Hypervisor must set rax if it is a input request. */
        if ( ghcb->save.sw_exitinfo1 & 0x1 )
            GHCB_SET_FIELD(ghcb, rax, 0);
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 0);
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 0);
        break;

    case VMGEXIT_NMI_COMPLETE:
        v->arch.hvm.svm.sev.in_nmi = false;
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 0);
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 0);
        break;

    case VMGEXIT_AP_CREATION:
        ghcb_ap_creation(v, ghcb);
        break;

    default:
        gprintk(XENLOG_G_WARNING, "sev-es: Got unexpected GHCB call: 0x%"PRIx64"\n",
                ghcb->save.sw_exitcode);
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 6); /* Invalid NAE event */
        break;
    }

    smp_wmb();
    return;

    #ifdef CONFIG_COCO_SEV_STRICT_GHCB
    malformed:
        gdprintk(XENLOG_WARNING, "sev-es: Rejecting malformed GHCB call\n");
        GHCB_CLEAR_VALID(ghcb);
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 4); /* Invalid bitmap */
        smp_wmb();
        return;
    #endif
}

void sev_es_do_vmgexit(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct sev_vcpu *sev = &v->arch.hvm.svm.sev;
    struct page_info *ghcb_page;
    struct ghcb *ghcb_map;

    /* GHCB MSR Protocol (SEV-ES GHCB specification) */
    uint64_t ghcb_info = GHCB_MSR_INFO(vmcb->ghcb_msr);
    uint64_t ghcb_data = GHCB_DATA(vmcb->ghcb_msr);
    p2m_type_t p2mt;

    if ( ghcb_info )
    {
        switch ( ghcb_info )
        {
        case GHCB_MSR_SEV_INFO_REQ:
            vmcb->ghcb_msr = GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX, GHCB_VERSION_MIN,
                                               host_cpu_policy.extd.c_bit_pos);
            break;

        case GHCB_MSR_CPUID_REQ:
        {
            uint32_t reg = GHCB_MSR_CPUID_REG(ghcb_data);
            uint32_t leaf = GHCB_MSR_CPUID_FUNC(ghcb_data);
            uint32_t value = 0;
            struct cpuid_leaf res;

            if ( reg > GHCB_CPUID_REQ_EDX )
                gprintk(XENLOG_WARNING,
                        "sev-es: Invalid GHCB CPUID register requested: 0x%x", reg);
            else
            {
                guest_cpuid(v, leaf, 0, &res);
                TRACE(TRC_HVM_CPUID, leaf, 0, res.a, res.b, res.c, res.d);

                switch (reg)
                {
                case GHCB_CPUID_REQ_EAX:
                    value = res.a;
                    break;
                case GHCB_CPUID_REQ_EBX:
                    value = res.b;
                    break;
                case GHCB_CPUID_REQ_ECX:
                    value = res.c;
                    break;
                case GHCB_CPUID_REQ_EDX:
                    value = res.d;
                    break;
                }
            }

            gdprintk(XENLOG_DEBUG,
                     "sev-es: GHCB MSR CPUID: %08x[reg%u] = %08x\n", leaf, reg, value);
            vmcb->ghcb_msr = GHCB_CPUID_RESP(value, reg);
            break;
        }

        case GHCB_MSR_TERM_REQ:
        {
            gprintk(XENLOG_INFO,
                    "sev-es: GHCB termination requested: data=0x%"PRIx64"\n", ghcb_data);
            domain_shutdown(v->domain, 0);
            break;
        }

        default:
            gprintk(XENLOG_WARNING, "sev-es: Unknown GHCB request %lu\n", ghcb_info);
            break;
        }

        return;
    }

    /* Standard GHCB call */
    if ( likely(sev->ghcb_page && ghcb_data == sev->ghcb_gfn) )
    {
        /* GHCB is already mapped and hasn't moved */
        sev_es_ghcb_call(v, sev->ghcb_map);
        return;
    }

    ghcb_page = get_page_from_gfn(v->domain, ghcb_data, &p2mt, P2M_ALLOC);

    if ( p2mt != p2m_ram_rw )
    {
        gprintk(XENLOG_WARNING,
                "sev-es: Invalid GHCB page type: gfn=%"PRI_xen_pfn", %d != %d\n",
                ghcb_data, p2mt, p2m_ram_rw);

        if ( ghcb_page )
            put_page(ghcb_page);

        return;
    }

    if ( sev->ghcb_page )
    {
        UNMAP_DOMAIN_PAGE(sev->ghcb_map);
        put_page(sev->ghcb_page);
    }

    ghcb_map = __map_domain_page(ghcb_page);
    sev->ghcb_map = ghcb_map;
    sev->ghcb_page = ghcb_page;
    sev->ghcb_gfn = ghcb_data;

    sev_es_ghcb_call(v, ghcb_map);
}

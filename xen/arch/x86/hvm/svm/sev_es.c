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
#include <asm/event.h>
#include <asm/fastabi.h>
#include <asm/mm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/svm/sev_es.h>
#include <asm/hvm/svm/sev_snp.h>
#include <asm/p2m.h>

#include "vmcb.h"
#include "sev_es.h"

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

static int snp_ap_create(struct vcpu *v, gfn_t vmsa_gfn, bool start,
                             uint64_t sev_features, unsigned int vmpl)
{
    p2m_type_t p2mt;
    struct page_info *vmsa_page, *old_vmsa_page;
    struct svm_vcpu *svm_v = &v->arch.hvm.svm;
    struct sev_vmpl_state *vmpl_state;
    /* TODO: This needs some work to make it actually safe. */

    gdprintk(XENLOG_DEBUG,
             "sev-snp: GHCB AP Create v%d, vmsa=%"PRI_gfn", start=%d, vmpl=%u\n",
             v->vcpu_id, gfn_x(vmsa_gfn), start, vmpl);
    
    if ( vmpl > SEV_MAX_VMPL )
    {
        gdprintk(XENLOG_DEBUG,
                "sev-snp: GHCB AP Create v%d: Invalid VMPL %d\n",
                v->vcpu_id, vmpl);
        return -EINVAL;
    }

    vmpl_state = &svm_v->sev.vmpl[vmpl];

    if ( v->is_initialised && is_vcpu_online(v) )
    {
        gdprintk(XENLOG_DEBUG, "sev-snp: GHCB AP Create v%d: vCPU is already up\n", v->vcpu_id);
        return -EBUSY;
    }

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

    if ( !(vmsa_page->count_info & PGC_coco_restrict) )
    {
        gprintk(XENLOG_WARNING,
                "sev-es: Non coco restricted page given: gfn=%"PRI_xen_pfn"\n",
                gfn_x(vmsa_gfn));

        put_page(vmsa_page);
        return -EINVAL;
    }

    old_vmsa_page = xchg(&vmpl_state->vmsa_page, vmsa_page);

    if ( old_vmsa_page )
        put_page(old_vmsa_page);

    svm_v->sev.current_vmpl = vmpl;
    svm_v->vmcb->vmsa_pa = page_to_maddr(vmsa_page);
    smp_mb();

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

static int snp_page_state_change_one(struct domain *d, gfn_t gfn, bool private)
{
    p2m_type_t p2mt;
    struct rmp_entry rmp;
    struct page_info *page = get_page_from_gfn(d, gfn_x(gfn), &p2mt, P2M_ALLOC);
    int rc = 0;

    if ( p2mt != p2m_ram_rw )
    {
        if ( page )
            put_page(page);
        return -EINVAL;
    }

    if ( private == !!(page->count_info & PGC_coco_restrict) )
        /* Nothing to do */
        return 0;

    rmp = (struct rmp_entry){
        .asid = private ? d->arch.hvm.asid.asid : 0,
        .assigned = private,
        .gpa = gfn_to_gaddr(gfn),
    };

    rc = rmpupdate(page, &rmp);

    if ( !rc )
    {
        if ( private )
            page->count_info |= PGC_coco_restrict;
        else
            page->count_info &= ~PGC_coco_restrict;
    }

    return rc;
}

static int snp_page_state_change(struct domain *d, union ghcb_psch_entry *req)
{
    int rc = 0;
    int j = 0;

    if ( req->pagesize > 1 ||
         (req->pagesize == 0 && req->cur_page > 0) ||
         (req->pagesize == 1 && req->cur_page >= 512) ||
         req->reserved || !req->operation || req->operation > 4 )
    {
        gdprintk(XENLOG_WARNING, "sev-snp: Invalid PAGE_STATE_CHANGE request %08lx\n",
                 req->raw);
        return -EINVAL;
    }

    if ( req->operation == 3 || req->operation == 4 )
    {
        gdprintk(XENLOG_DEBUG, "sev-snp: TODO PSMASH/UNSMASH hints requests %08lx\n",
                 req->raw);
        return 0;
    }

    do {
        gfn_t gfn = gfn_add(_gfn(req->gfn), req->cur_page);

        rc = snp_page_state_change_one(d, gfn, req->operation == 1);
        if ( rc )
            break;

        req->cur_page++;

        if ( (++j & 0xf) && hypercall_preempt_check() )
        {
            rc = -EAGAIN;
            break;
        }
    } while ( req->pagesize == 1 && req->cur_page < 512 );

    return rc;
}

static void ghcb_page_state_change(struct vcpu *v, struct ghcb *ghcb)
{
    uint64_t psch_struct_gpa;
    unsigned int psch_struct_offset;
    struct ghcb_psch_header psch_header;
    union ghcb_psch_entry psch_entry;
    struct sev_vcpu *v_sev = &v->arch.hvm.svm.sev;
    gfn_t ghcb_gfn;
    uint64_t exitinfo2 = 0;
    unsigned int j = 0;

    if ( !is_sev_snp_domain(v->domain) )
    {
        gdprintk(XENLOG_WARNING,"sev-es: Rejecting PAGE_STATE_CHANGE on non-SNP guest\n");
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 6); /* Invalid NAE event */
        return;
    }

    ghcb_gfn = _gfn(v_sev->vmpl[v_sev->current_vmpl].ghcb_gfn);

    psch_struct_gpa = ACCESS_ONCE(ghcb->save.sw_scratch);
    psch_struct_offset = psch_struct_gpa & PAGE_MASK;
    
    /* 
     * GHCB specification requires that gpa to reside inside GHCB Save area.
     * That actually allows us to reuse the ghcb mapping we already have,
     * saving us a bit of work.
     */

    if ( !gfn_eq(gaddr_to_gfn(psch_struct_gpa), ghcb_gfn)
         /* Check if sw_scratch points outside of shared buffer. */
         || psch_struct_offset < offsetof(struct ghcb, shared_buffer)
         || psch_struct_offset > (offsetof(struct ghcb, shared_buffer)
                                  + sizeof(ghcb->shared_buffer)) )
    {
        gdprintk(XENLOG_WARNING,
                 "sev-snp: PAGE_STATE_CHANGE scratch points outside of shared buffer\n");
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 3); /* Invalid SW_SCRATCH */
        return;
    }

    /* We're a offset from the ghcb page, normalize into shared_buffer. */
    psch_struct_offset -= offsetof(struct ghcb, shared_buffer);

    if ( psch_struct_offset > sizeof(ghcb->shared_buffer) - sizeof(psch_header) )
    {
        gdprintk(XENLOG_WARNING,
                 "sev-snp: PAGE_STATE_CHANGE header overflows shared buffer\n");
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 1); /* Invalid SW_SCRATCH */
        return;
    }

    memcpy(&psch_header, ghcb->shared_buffer + psch_struct_offset, sizeof(psch_header));
    smp_rmb();

    for (; psch_header.cur_entry < psch_header.end_entry; psch_header.cur_entry++)
    {
        int rc;
        unsigned int psch_entry_offset = psch_struct_offset +
                                         psch_header.cur_entry * sizeof(psch_entry);
        /*
         * GHCB specification allows this request to be interrupted; the guest is
         * expected to retry the operation if it encounters exitinfo2=0 while
         * psch_header.cur_entry != psch_header.end_entry
         */
        if ( (++j & 0xf) && hypercall_preempt_check() )
            break;

        if ( (psch_entry_offset + sizeof(psch_entry)) > sizeof(ghcb->shared_buffer) )
        {
            gdprintk(XENLOG_WARNING,
                     "sev-snp: PAGE_STATE_CHANGE request %hu overflows shared buffer\n",
                     psch_header.cur_entry);
            exitinfo2 = 2ULL | (1ULL << 32); /* Invalid page state change header */
            break;
        }

        memcpy(&psch_entry, ghcb->shared_buffer + psch_entry_offset, sizeof(psch_entry));
        smp_rmb();

        rc = snp_page_state_change(v->domain, &psch_entry);
        memcpy(ghcb->shared_buffer + psch_entry_offset, &psch_entry, sizeof(psch_entry));
        smp_wmb();
        

        if ( rc == -EAGAIN )
            break;
        else if ( rc )
        {
            /* FIXME: Add error handling */
        }
    }

    memcpy(ghcb->shared_buffer + psch_struct_offset, &psch_header, sizeof(psch_header));
    
    GHCB_SET_FIELD(ghcb, sw_exitinfo1, 0);
    GHCB_SET_FIELD(ghcb, sw_exitinfo2, exitinfo2);
    smp_wmb();
}

static void ghcb_ap_creation(struct vcpu *v, struct ghcb *ghcb)
{
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
        gdprintk(XENLOG_WARNING, "sev-snp: MBZ bit set in SW_EXITINFO1 in AP creation\n");
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
        return;
    }

    /* Find the matching vCPU for this APIC ID */
    for_each_vcpu( currd, candidate_v )
    {
        gdprintk(XENLOG_DEBUG, "sev-snp:- %d == %d?\n", VLAPIC_ID(vcpu_vlapic(candidate_v)), param.apic_id);
        if ( VLAPIC_ID(vcpu_vlapic(candidate_v)) == param.apic_id )
        {
            target_v = candidate_v;
            break;
        }
    }

    if ( !target_v )
    {
        gdprintk(XENLOG_WARNING, "sev-snp: Unknown APIC ID %"PRIu32"\n", param.apic_id);
        GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
        GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
        return;
    }

    switch ( param.cmd )
    {
        case 0: /* Create/add */
        case 1: /* Create/add then run (VMPL) */
            if ( snp_ap_create(target_v, gaddr_to_gfn(vmsa), param.cmd == 1,
                               sev_features, param.vmpl) )
            {
                GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
                GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
            }
            break;

        case 2: /* Destroy/remove */
            gprintk(XENLOG_WARNING, "sev-snp: TODO: AP Creation cmd=%d\n", param.cmd);
            GHCB_SET_FIELD(ghcb, sw_exitinfo1, 2); /* Malformed input */
            GHCB_SET_FIELD(ghcb, sw_exitinfo2, 5); /* Invalid input */
            return;
    }

    GHCB_SET_FIELD(ghcb, sw_exitinfo1, 0);
    GHCB_SET_FIELD(ghcb, sw_exitinfo2, 0);
    smp_wmb();
}

uint64_t sev_es_default_ghcb_msr(struct domain *d)
{
    union ghcb_msr_data data = {
        .info_resp = {
            .min_version = 1UL,
            .max_version = is_sev_snp_domain(d) ? 2UL : 1UL,
            .c_bit = host_cpu_policy.extd.c_bit_pos
        }
    };

    return (union ghcb_msr){
        .info = GHCB_MSR_SEV_INFO_RESP,
        .data_raw = data.raw,
    }.raw;
}

int sev_es_build_vmsa(struct vcpu *v, struct page_info *vmsa_page)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct cpu_user_regs *regs = &v->arch.user_regs;
    void *vmsa;

    if ( !is_sev_es_domain(v->domain) )
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

    if ( is_sev_snp_domain(v->domain) )
        vmcb->vmsa_regs.sev_features.snp = true;

    /*
     * Copy VMCB Save Area into VMSA page.
     * SEV-ES VMSA uses the same layout as VMCB save area.
     */
    vmsa = __map_domain_page(vmsa_page);
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
    
    case VMGEXIT_PAGE_STATE_CHANGE:
        ghcb_page_state_change(v, ghcb);
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

static int sev_es_register_ghcb(struct domain *d, struct sev_vmpl_state *vmpl_state,
                                uint64_t ghcb_gfn, bool make_shared)
{
    struct page_info *ghcb_page;
    p2m_type_t p2mt;

    ghcb_page = get_page_from_gfn(d, ghcb_gfn, &p2mt, P2M_ALLOC);

    if ( p2mt != p2m_ram_rw )
    {
        gprintk(XENLOG_WARNING,
                "sev-es: Invalid GHCB page type: gfn=%"PRI_xen_pfn", %d != %d\n",
                ghcb_gfn, p2mt, p2m_ram_rw);

        if ( ghcb_page )
            put_page(ghcb_page);

        return -EINVAL;
    }

    if ( is_sev_snp_domain(d) && make_shared )
    {
        struct rmp_entry rmp = { 0 };
        int rc = rmpupdate(ghcb_page, &rmp);

        if ( rc )
        {
            gprintk(XENLOG_WARNING,
                    "sev-snp: Can't make GHCB page shared: gfn=%"PRI_xen_pfn", rc=%d\n",
                    gfn_x(ghcb_gfn), rc);
            put_page(ghcb_page);
            return rc;
        }

        ghcb_page->count_info &= PGC_coco_restrict;
    }

    if ( !get_page_type(ghcb_page, PGT_writable_page) )
    {
        gprintk(XENLOG_WARNING,
                "sev-es: Can't get writable mapping to GHCB page: gfn=%"PRI_xen_pfn"\n",
                gfn_x(ghcb_gfn));
        put_page(ghcb_page);
        return -EPERM;
    }

    if ( vmpl_state->ghcb_page )
    {
        UNMAP_DOMAIN_PAGE(vmpl_state->ghcb_map);
        put_page(vmpl_state->ghcb_page);
    }

    vmpl_state->ghcb_map = __map_domain_page(ghcb_page);
    vmpl_state->ghcb_page = ghcb_page;
    vmpl_state->ghcb_gfn = ghcb_gfn;
}

void sev_es_do_vmgexit(struct vcpu *v)
{
    struct domain *currd = v->domain;
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct sev_vcpu *sev = &v->arch.hvm.svm.sev;
    struct page_info *ghcb_page;
    struct ghcb *ghcb_map;
    struct sev_vmpl_state *vmpl_state;
    union ghcb_msr ghcb_msr;

    /* GHCB MSR Protocol (SEV-ES GHCB specification) */
    p2m_type_t p2mt;

    /* Only SEV-SNP domains can have VMPL > 0 */
    ASSERT(is_sev_snp_domain(currd) || sev->current_vmpl == 0);
    
    if ( sev->current_vmpl > SEV_MAX_VMPL )
    {
        printk(XENLOG_ERR "sev-es: Invalid guest VMPL %u\n", sev->current_vmpl);
        ASSERT_UNREACHABLE();
        domain_crash(currd);
        return;
    }

    ghcb_msr.raw = vmcb->ghcb_msr;
    vmpl_state = &sev->vmpl[sev->current_vmpl];

    if ( ghcb_msr.info )
    {
        const union ghcb_msr_data ghcb_data = { .raw = ghcb_msr.data_raw };

        switch ( ghcb_msr.info )
        {
        case GHCB_MSR_SEV_INFO_REQ:
            vmcb->ghcb_msr = sev_es_default_ghcb_msr(currd);
            break;

        case GHCB_MSR_CPUID_REQ:
        {
            unsigned int reg = ghcb_data.cpuid_req.reg;
            uint32_t leaf = ghcb_data.cpuid_req.leaf, value = 0;
            struct cpuid_leaf res;

            if ( reg > GHCB_CPUID_REG_EDX )
                gprintk(XENLOG_WARNING,
                        "sev-es: Invalid GHCB CPUID register requested: 0x%x",
                        reg);
            else
            {
                guest_cpuid(v, leaf, 0, &res);
                TRACE(TRC_HVM_CPUID, leaf, 0, res.a, res.b, res.c, res.d);

                switch (reg)
                {
                case GHCB_CPUID_REG_EAX:
                    value = res.a;
                    break;
                case GHCB_CPUID_REG_EBX:
                    value = res.b;
                    break;
                case GHCB_CPUID_REG_ECX:
                    value = res.c;
                    break;
                case GHCB_CPUID_REG_EDX:
                    value = res.d;
                    break;
                }
            }

            gdprintk(XENLOG_DEBUG,
                     "sev-es: GHCB MSR CPUID: %08x[reg%u] = %08x\n", leaf, reg, value);
            
            ghcb_msr.info = 
            ghcb_msr.data_raw = (union ghcb_msr_data){
                .cpuid_resp = {
                    .reg = reg,
                    .rsvd = 0,
                    .value = value,
                }
            }.raw;
            break;
        }

        case GHCB_MSR_PREF_GHCB_GPA_REQ:
            ghcb_msr.info = GHCB_MSR_PREF_GHCB_GPA_RESP;
            ghcb_msr.data_raw = 0xfffffffffffffULL; /* No prefered */
            break;

        case GHCB_MSR_REG_GHCB_GPA_REQ:
            ghcb_msr.info = GHCB_MSR_REG_GHCB_GPA_RESP;

            if ( sev_es_register_ghcb(currd, vmpl_state, ghcb_msr.data_raw, true) )
                ghcb_msr.data_raw = 0xfffffffffffffULL;
            else
                ghcb_msr.data_raw = ghcb_data.raw; /* Untouched */
            break;
        
        case GHCB_MSR_PAGE_STATE_CHG_REQ:
        {
            gfn_t gfn = _gfn(ghcb_data.psc_req.gfn);
            unsigned long op = ghcb_data.psc_req.op;
            int rc = 0;
            unsigned int error_code;

            if ( is_sev_snp_domain(currd) )
                rc = snp_page_state_change_one(currd, gfn, op == 0x0001);
            else
            {
                rc = -EINVAL;
                gprintk(XENLOG_WARNING,
                        "sev-es: Ignoring PSC request on SEV-ES guest\n");
            }
            
            /* FIXME: GHCB specification doesn't specify the behavior in case
             *        of preempting this operation (i.e rc == -EAGAIN).
             */
            if ( rc )
                gprintk(XENLOG_WARNING,
                        "sev-snp: GHCB_MSR_PAGE_STATE_CHG_REQ failure rc=%d",
                        rc);

            ghcb_msr.info = GHCB_MSR_PAGE_STATE_CHG_RESP;
            ghcb_msr.data_raw = (union ghcb_msr_data){
                .psc_resp = {
                    .error_code = rc ? 1 : 0,
                    .rsvd = 0,
                }
            }.raw;
            break;
        }

        case GHCB_MSR_HYP_FEATURE_REQ:
        {
            unsigned long features = 0;

            if ( is_sev_snp_domain(currd) )
            {
                features |= GHCB_FEAT_SNP;
                // features |= GHCB_FEAT_SNP_AP_CREATION;
                /* features |= GHCB_FEAT_SNP_MULTI_VMPL; */
            }

            break;
        }

        case GHCB_MSR_TERM_REQ:
            gprintk(XENLOG_INFO,
                    "sev-es: GHCB termination requested: data=0x%"PRIx64"\n", ghcb_msr.data_raw);
            domain_shutdown(currd, 0);
            break;
        
        default:
            gprintk(XENLOG_WARNING, "sev-es: Unknown GHCB request %u\n", ghcb_msr.info);
            break;
        }

        vmcb->ghcb_msr = ghcb_msr.raw;
        return;
    }

    /* Standard GHCB call */
    if ( likely(vmpl_state->ghcb_page && ghcb_msr.raw == vmpl_state->ghcb_gfn) )
    {
        /* GHCB is already mapped and hasn't moved */
        sev_es_ghcb_call(v, vmpl_state->ghcb_map);
        return;
    }

    if ( sev_es_register_ghcb(currd, vmpl_state, ghcb_msr.raw, false) )
        return;

    sev_es_ghcb_call(v, ghcb_map);
}

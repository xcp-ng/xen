#include <xen/trace.h>
#include <xen/fastabi.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/domain_page.h>

#include <asm/fastabi.h>
#include <asm/cpuid.h>
#include <asm/cpu-policy.h>
#include <asm/guest-msr.h>
#include <asm/p2m.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/sev_es.h>
#include <asm/hvm/support.h>

static void sev_es_ghcb_call(struct vcpu *v, struct ghcb *ghcb)
{
    switch ( ghcb->save.sw_exitcode )
    {
    case VMEXIT_CPUID:
    {
        uint32_t leaf = ghcb->save.rax, subleaf = ghcb->save.rcx;
        struct cpuid_leaf res;
        smp_rmb();

        guest_cpuid(v, leaf, subleaf, &res);
        TRACE(TRC_HVM_CPUID, leaf, subleaf, res.a, res.b, res.c, res.d);

        ghcb->save.rax = res.a;
        ghcb->save.rbx = res.b;
        ghcb->save.rcx = res.c;
        ghcb->save.rdx = res.d;
        ghcb->save.sw_exitinfo1 = 0;
        smp_wmb();
        break;
    }

    case VMEXIT_MSR:
    {
        int rc;
        bool rdmsr = ghcb->save.sw_exitinfo1 == 0;
        uint64_t rcx = ghcb->save.rcx;
        /* Compute msr_content even if we end up performing a rdmsr. */
        uint64_t msr_content = ghcb->save.rdx << 32 | (uint32_t)ghcb->save.rax;
        smp_rmb();

        if ( rdmsr )
            rc = guest_rdmsr(v, rcx, &msr_content);
        else
        {
            rc = guest_wrmsr(v, rcx, msr_content);

            if ( rc == X86EMUL_OKAY )
            {
                ghcb->save.rdx = msr_content >> 32;
                ghcb->save.rax = (uint32_t)msr_content;
                ghcb->save.sw_exitinfo1 = 0;
            }
            else if ( rc == X86EMUL_EXCEPTION )
            {
                /* Inject #GP */
                ghcb->save.sw_exitinfo1 = 1;
                ghcb->save.sw_exitinfo2 = X86_EXC_GP;
            }
            smp_wmb();
        }
        break;
    }

    case VMEXIT_VMMCALL:
    {
        /* Only copy FastABI registers */
        struct cpu_user_regs regs;
        smp_rmb();
        
        #define ghcb_fastabi_reg(ghcb, n) (ghcb)->save. fastabi_param_reg##n
        fastabi_value_n(&regs, 0) = ghcb_fastabi_reg(ghcb, 0);
        fastabi_value_n(&regs, 1) = ghcb_fastabi_reg(ghcb, 1);
        fastabi_value_n(&regs, 2) = ghcb_fastabi_reg(ghcb, 2);
        fastabi_value_n(&regs, 3) = ghcb_fastabi_reg(ghcb, 3);
        fastabi_value_n(&regs, 4) = ghcb_fastabi_reg(ghcb, 4);
        fastabi_value_n(&regs, 5) = ghcb_fastabi_reg(ghcb, 5);
        fastabi_value_n(&regs, 6) = ghcb_fastabi_reg(ghcb, 6);
        fastabi_value_n(&regs, 7) = ghcb_fastabi_reg(ghcb, 7);
        smp_rmb();

        HVM_DBG_LOG(DBG_LEVEL_HCALL,
            "ghcb hcall%lu(%lx, %lx, %lx, %lx, %lx, %lx, %lx)\n",
            regs.rax & ~0x40000000U, fastabi_value_n(&regs, 1), fastabi_value_n(&regs, 2),
            fastabi_value_n(&regs, 3), fastabi_value_n(&regs, 4),
            fastabi_value_n(&regs, 5), fastabi_value_n(&regs, 6),
            fastabi_value_n(&regs, 7));

        fastabi_dispatch(regs.rax & ~0x40000000U, &regs);

        ghcb_fastabi_reg(ghcb, 0) = fastabi_value_n(&regs, 0);
        ghcb_fastabi_reg(ghcb, 1) = fastabi_value_n(&regs, 1);
        ghcb_fastabi_reg(ghcb, 2) = fastabi_value_n(&regs, 2);
        ghcb_fastabi_reg(ghcb, 3) = fastabi_value_n(&regs, 3);
        ghcb_fastabi_reg(ghcb, 4) = fastabi_value_n(&regs, 4);
        ghcb_fastabi_reg(ghcb, 5) = fastabi_value_n(&regs, 5);
        ghcb_fastabi_reg(ghcb, 6) = fastabi_value_n(&regs, 6);
        ghcb_fastabi_reg(ghcb, 7) = fastabi_value_n(&regs, 7);

        ghcb->save.sw_exitinfo1 = 0;
        smp_wmb();

        #undef ghcb_fastabi_reg
        break;
    }

    default:
        gprintk(XENLOG_G_WARNING, "Got unexpected GHCB call: %"PRIx64"\n",
                ghcb->save.sw_exitcode);
        ghcb->save.sw_exitinfo1 = 2; /* Malformed input */
        ghcb->save.sw_exitinfo2 = 6; /* Invalid NAE event */
        break;
    }
}

void sev_es_do_vmgexit(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct page_info *ghcb_page;
    struct ghcb *ghcb_map;
    
    /* GHCB MSR Protocol (SEV-ES GHCB specification) */
    uint64_t ghcb_info = GHCB_MSR_INFO(vmcb->ghcb_msr);
    uint64_t ghcb_data = GHCB_DATA(vmcb->ghcb_msr);
    p2m_type_t p2m_type;

    if ( ghcb_info )
    {
        switch ( ghcb_info )
        {
        case GHCB_MSR_SEV_INFO_REQ:
            vmcb->ghcb_msr = GHCB_MSR_SEV_INFO(GHCB_VERSION_MAX, GHCB_VERSION_MIN,
                raw_cpu_policy.extd.c_bit_pos);
            break;
        
        case GHCB_MSR_CPUID_REQ:
        {
            uint32_t reg = GHCB_MSR_CPUID_REG(ghcb_data);
            uint32_t leaf = GHCB_MSR_CPUID_FUNC(ghcb_data);
            uint32_t value = 0;
            struct cpuid_leaf res;

            if ( reg > GHCB_CPUID_REQ_EDX )
                gprintk(XENLOG_G_WARNING, "Invalid GHCB CPUID register requested: %u", reg);
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

            vmcb->ghcb_msr = GHCB_CPUID_RESP(value, reg);
            break;
        }
        
        case GHCB_MSR_TERM_REQ:
        {
            gprintk(XENLOG_G_INFO, "GHCB termination requested: data=%"PRIx64"\n", ghcb_data);
            domain_shutdown(v->domain, 0);
            break;
        }
        
        default:
            gprintk(XENLOG_G_WARNING, "Unknown GHCB request %lu\n", ghcb_info);
            break;
        }

        return;
    }

    /* Standard GHCB call */
    ghcb_page = get_page_from_gfn(v->domain, ghcb_data, &p2m_type, P2M_ALLOC | P2M_UNSHARE);

    if ( p2m_type != p2m_ram_rw )
    {
        gprintk(XENLOG_G_WARNING, "Rejecting invalid GHCB page location: gfn=%"PRI_xen_pfn"\n", ghcb_data);

        if ( ghcb_page )
            put_page(ghcb_page);

        return;
    }

    if ( ghcb_page != v->arch.hvm.svm.ghcb_page )
    {
        /* GHCB is no longer at the same location, remap it */
        if ( v->arch.hvm.svm.ghcb_page )
        {
            unmap_domain_page(v->arch.hvm.svm.ghcb_map);
            put_page(v->arch.hvm.svm.ghcb_page);
        }

        ghcb_map = __map_domain_page(ghcb_page);
        v->arch.hvm.svm.ghcb_map = ghcb_map;
        v->arch.hvm.svm.ghcb_page = ghcb_page;
    }
    else
        ghcb_map = v->arch.hvm.svm.ghcb_map;

    sev_es_ghcb_call(v, ghcb_map);
}

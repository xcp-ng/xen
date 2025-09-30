/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * svmdebug.c: debug functions
 * Copyright (c) 2011, Advanced Micro Devices, Inc.
 *
 */

#include <xen/sched.h>
#include <asm/processor.h>
#include <asm/msr-index.h>
#include <asm/hvm/svm/svmdebug.h>

#ifdef CONFIG_COCO_AMD_SEV
#include <xen/lib.h>

#include <asm/cpu-user-regs.h>
#include <asm/hvm/svm/sev_es.h>
#endif

static void svm_dump_sel(const char *name, const struct segment_register *s)
{
    printk("%s: %04x %04x %08x %016"PRIx64"\n",
           name, s->sel, s->attr, s->limit, s->base);
}

void svm_vmcb_dump(const char *from, const struct vmcb_struct *vmcb)
{
    struct vcpu *curr = current;

    /*
     * If we are dumping the VMCB currently in context, some guest state may
     * still be cached in hardware.  Retrieve it.
     */
    if ( vmcb == curr->arch.hvm.svm.vmcb )
        svm_sync_vmcb(curr, vmcb_in_sync);

    printk("Dumping guest's current state at %s...\n", from);
    printk("Size of VMCB = %zu, paddr = %"PRIpaddr", vaddr = %p\n",
           sizeof(struct vmcb_struct), virt_to_maddr(vmcb), vmcb);

    printk("cr_intercepts = %#x dr_intercepts = %#x "
           "exception_intercepts = %#x\n",
           vmcb_get_cr_intercepts(vmcb), vmcb_get_dr_intercepts(vmcb),
           vmcb_get_exception_intercepts(vmcb));
    printk("general1_intercepts = %#x general2_intercepts = %#x\n",
           vmcb_get_general1_intercepts(vmcb), vmcb_get_general2_intercepts(vmcb));
    printk("pause_filter_threshold = %u pause_filter_count = %u\n",
           vmcb_get_pause_filter_thresh(vmcb), vmcb_get_pause_filter_count(vmcb));
    printk("iopm_base_pa = %#"PRIx64" msrpm_base_pa = %#"PRIx64" tsc_offset = %#"PRIx64"\n",
           vmcb_get_iopm_base_pa(vmcb), vmcb_get_msrpm_base_pa(vmcb),
           vmcb_get_tsc_offset(vmcb));
    printk("tlb_control = %#x vintr = %#"PRIx64" int_stat = %#"PRIx64"\n",
           vmcb->tlb_control, vmcb_get_vintr(vmcb).bytes,
           vmcb->int_stat.raw);
    printk("event_inj %016"PRIx64", valid? %d, ec? %d, type %u, vector %#x\n",
           vmcb->event_inj.raw, vmcb->event_inj.v,
           vmcb->event_inj.ev, vmcb->event_inj.type,
           vmcb->event_inj.vector);
    printk("exitcode = %#"PRIx64" exit_int_info = %#"PRIx64"\n",
           vmcb->exitcode, vmcb->exit_int_info.raw);
    printk("exitinfo1 = %#"PRIx64" exitinfo2 = %#"PRIx64"\n",
           vmcb->exitinfo1, vmcb->exitinfo2);
    printk("asid = %#x np_ctrl = %#"PRIx64":%s%s%s%s%s%s\n",
           vmcb_get_asid(vmcb), vmcb_get_np_ctrl(vmcb),
           vmcb_get_np(vmcb)     ? " NP"     : "",
           vmcb_get_sev(vmcb)    ? " SEV"    : "",
           vmcb_get_sev_es(vmcb) ? " SEV_ES ": "",
           vmcb_get_gmet(vmcb)   ? " GMET "  : "",
           vmcb_get_np_sss(vmcb) ? " NP_SSS ": "",
           vmcb_get_vte(vmcb)    ? " VTE"    : "");
    printk("vmsa_pa = %#"PRIx64" ghcb_msr = %#"PRIx64"\n",
           vmcb->vmsa_pa, vmcb->ghcb_msr);
    printk("vmgexit_rax = %#"PRIx64" vmgexit_cpl = %u\n",
           vmcb->vmgexit_rax, vmcb->vmgexit_cpl);
    printk("virtual vmload/vmsave = %d, virt_ext = %#"PRIx64"\n",
           vmcb->virt_ext.fields.vloadsave_enable, vmcb->virt_ext.bytes);
    
    if ( is_sev_es_domain(curr->domain) )
    {
        sev_vmsa_dump(curr);
        return;
    }

    printk("cpl = %d efer = %#"PRIx64" star = %#"PRIx64" lstar = %#"PRIx64"\n",
           vmcb_get_cpl(vmcb), vmcb_get_efer(vmcb), vmcb->star, vmcb->lstar);
    printk("CR0 = 0x%016"PRIx64" CR2 = 0x%016"PRIx64"\n",
           vmcb_get_cr0(vmcb), vmcb_get_cr2(vmcb));
    printk("CR3 = 0x%016"PRIx64" CR4 = 0x%016"PRIx64"\n",
           vmcb_get_cr3(vmcb), vmcb_get_cr4(vmcb));
    printk("RSP = 0x%016"PRIx64"  RIP = 0x%016"PRIx64"\n",
           vmcb->rsp, vmcb->rip);
    printk("RAX = 0x%016"PRIx64"  RFLAGS=0x%016"PRIx64"\n",
           vmcb->rax, vmcb->rflags);
    printk("DR6 = 0x%016"PRIx64", DR7 = 0x%016"PRIx64"\n",
           vmcb_get_dr6(vmcb), vmcb_get_dr7(vmcb));
    printk("CSTAR = 0x%016"PRIx64" SFMask = 0x%016"PRIx64"\n",
           vmcb->cstar, vmcb->sfmask);
    printk("KernGSBase = 0x%016"PRIx64" PAT = 0x%016"PRIx64"\n",
           vmcb->kerngsbase, vmcb_get_g_pat(vmcb));
    printk("SSP = 0x%016"PRIx64" S_CET = 0x%016"PRIx64" ISST = 0x%016"PRIx64"\n",
           vmcb->_ssp, vmcb->_msr_s_cet, vmcb->_msr_isst);
    printk("H_CR3 = 0x%016"PRIx64" CleanBits = %#x\n",
           vmcb_get_h_cr3(vmcb), vmcb->cleanbits.raw);
    printk("lbrv: DebugCtl: %"PRIx64" LBFI: %"PRIx64" LBTI: %"PRIx64"\n",
           vmcb_get_debugctlmsr(vmcb), vmcb_get_lastbranchfromip(vmcb),
           vmcb_get_lastbranchtoip(vmcb));
    printk("       LIFI: %"PRIx64" LITI: %"PRIx64"\n",
           vmcb_get_lastintfromip(vmcb), vmcb_get_lastinttoip(vmcb));
    printk("SPEC_CTRL = %"PRIx64"\n", vmcb->spec_ctrl);

    /* print out all the selectors */
    printk("       sel attr  limit   base\n");
    svm_dump_sel("  CS", &vmcb->cs);
    svm_dump_sel("  DS", &vmcb->ds);
    svm_dump_sel("  SS", &vmcb->ss);
    svm_dump_sel("  ES", &vmcb->es);
    svm_dump_sel("  FS", &vmcb->fs);
    svm_dump_sel("  GS", &vmcb->gs);
    svm_dump_sel("GDTR", &vmcb->gdtr);
    svm_dump_sel("LDTR", &vmcb->ldtr);
    svm_dump_sel("IDTR", &vmcb->idtr);
    svm_dump_sel("  TR", &vmcb->tr);
}

bool svm_vmcb_isvalid(const char *from, const struct vmcb_struct *vmcb,
                      const struct vcpu *v, bool verbose)
{
    bool ret = false; /* ok */
    unsigned long cr0 = vmcb_get_cr0(vmcb);
    unsigned long cr3 = vmcb_get_cr3(vmcb);
    unsigned long cr4 = vmcb_get_cr4(vmcb);
    unsigned long valid;
    uint64_t efer = vmcb_get_efer(vmcb);

#define PRINTF(fmt, args...) do { \
    if ( !verbose ) return true; \
    ret = true; \
    printk(XENLOG_GUEST "%pv[%s]: " fmt, v, from, ## args); \
} while (0)

    if ( !(efer & EFER_SVME) )
        PRINTF("EFER: SVME bit not set (%#"PRIx64")\n", efer);

    if ( !(cr0 & X86_CR0_CD) && (cr0 & X86_CR0_NW) )
        PRINTF("CR0: CD bit is zero and NW bit set (%#"PRIx64")\n", cr0);

    if ( cr0 >> 32 )
        PRINTF("CR0: bits [63:32] are not zero (%#"PRIx64")\n", cr0);

    if ( (cr0 & X86_CR0_PG) &&
         ((cr3 & 7) ||
          ((!(cr4 & X86_CR4_PAE) || (efer & EFER_LMA)) && (cr3 & 0xfe0)) ||
          ((efer & EFER_LMA) &&
           (cr3 >> v->domain->arch.cpuid->extd.maxphysaddr))) )
        PRINTF("CR3: MBZ bits are set (%#"PRIx64")\n", cr3);

    valid = hvm_cr4_guest_valid_bits(v->domain);
    if ( cr4 & ~valid )
        PRINTF("CR4: invalid value %#lx (valid %#lx, rejected %#lx)\n",
               cr4, valid, cr4 & ~valid);

    if ( vmcb_get_dr6(vmcb) >> 32 )
        PRINTF("DR6: bits [63:32] are not zero (%#"PRIx64")\n",
               vmcb_get_dr6(vmcb));

    if ( vmcb_get_dr7(vmcb) >> 32 )
        PRINTF("DR7: bits [63:32] are not zero (%#"PRIx64")\n",
               vmcb_get_dr7(vmcb));

    if ( efer & ~EFER_KNOWN_MASK )
        PRINTF("EFER: unknown bits are not zero (%#"PRIx64")\n", efer);

    if ( hvm_efer_valid(v, efer, -1) )
        PRINTF("EFER: %s (%"PRIx64")\n", hvm_efer_valid(v, efer, -1), efer);

    if ( (efer & EFER_LME) && (cr0 & X86_CR0_PG) )
    {
        if ( !(cr4 & X86_CR4_PAE) )
            PRINTF("EFER_LME and CR0.PG are both set and CR4.PAE is zero\n");
        if ( !(cr0 & X86_CR0_PE) )
            PRINTF("EFER_LME and CR0.PG are both set and CR0.PE is zero\n");
    }

    if ( (efer & EFER_LME) && (cr0 & X86_CR0_PG) && (cr4 & X86_CR4_PAE) &&
         vmcb->cs.l && vmcb->cs.db )
        PRINTF("EFER_LME, CR0.PG, CR4.PAE, CS.L and CS.D are all non-zero\n");

    if ( !(vmcb_get_general2_intercepts(vmcb) & GENERAL2_INTERCEPT_VMRUN) )
        PRINTF("GENERAL2_INTERCEPT: VMRUN intercept bit is clear (%#"PRIx32")\n",
               vmcb_get_general2_intercepts(vmcb));

    if ( vmcb->event_inj.resvd1 )
        PRINTF("eventinj: MBZ bits are set (%#"PRIx64")\n",
               vmcb->event_inj.raw);

#undef PRINTF
    return ret;
}

#ifdef CONFIG_COCO_AMD_SEV
/* VMSA for GPR and segments */
struct sev_es_save_area {
	struct segment_register es;
	struct segment_register cs;
	struct segment_register ss;
	struct segment_register ds;
	struct segment_register fs;
	struct segment_register gs;
	struct segment_register gdtr;
	struct segment_register ldtr;
	struct segment_register idtr;
	struct segment_register tr;
	u64 pl0_ssp;
	u64 pl1_ssp;
	u64 pl2_ssp;
	u64 pl3_ssp;
	u64 u_cet;
	u8 reserved_0xc8[2];
	u8 vmpl;
	u8 cpl;
	u8 reserved_0xcc[4];
	u64 efer;
	u8 reserved_0xd8[104];
	u64 xss;
	u64 cr4;
	u64 cr3;
	u64 cr0;
	u64 dr7;
	u64 dr6;
	u64 rflags;
	u64 rip;
	u64 dr0;
	u64 dr1;
	u64 dr2;
	u64 dr3;
	u64 dr0_addr_mask;
	u64 dr1_addr_mask;
	u64 dr2_addr_mask;
	u64 dr3_addr_mask;
	u8 reserved_0x1c0[24];
	u64 rsp;
	u64 s_cet;
	u64 ssp;
	u64 isst_addr;
	u64 rax;
	u64 star;
	u64 lstar;
	u64 cstar;
	u64 sfmask;
	u64 kerngsbase;
	u64 sysenter_cs;
	u64 sysenter_esp;
	u64 sysenter_eip;
	u64 cr2;
	u8 reserved_0x248[32];
	u64 g_pat;
	u64 dbgctl;
	u64 br_from;
	u64 br_to;
	u64 last_excp_from;
	u64 last_excp_to;
	u8 reserved_0x298[80];
	u32 pkru;
	u32 tsc_aux;
	u64 tsc_scale;
	u64 tsc_offset;
	u8 reserved_0x300[8];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u64 reserved_0x320;	/* rsp already available at 0x01d8 */
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_0x380[16];
	u64 guest_exit_info_1;
	u64 guest_exit_info_2;
	u64 guest_exit_int_info;
	u64 guest_nrip;
	u64 sev_features;
	u64 vintr_ctrl;
	u64 guest_exit_code;
	u64 virtual_tom;
	u64 tlb_id;
	u64 pcpu_id;
	u64 event_inj;
	u64 xcr0;
	u8 reserved_0x3f0[16];

	/* Floating point area */
	u64 x87_dp;
	u32 mxcsr;
	u16 x87_ftw;
	u16 x87_fsw;
	u16 x87_fcw;
	u16 x87_fop;
	u16 x87_ds;
	u16 x87_cs;
	u64 x87_rip;
	u8 fpreg_x87[80];
	u8 fpreg_xmm[256];
	u8 fpreg_ymm[256];
};

bool sev_vmsa_dump(struct vcpu *v)
{
    struct domain *d = v->domain;
    struct page_info *vmsa_page = v->arch.hvm.svm.vmsa_page;
    struct sev_es_save_area *vmsa_dec = NULL;
    struct sev_data_dbg sd_dbg = {};
    struct cpu_user_regs *regs = &v->arch.user_regs;
    unsigned int psp_ret;
    int rc = 0;

    if ( !is_sev_es_domain(d) )
        return true;

    if ( !vmsa_page )
        return true;

    if ( d->arch.hvm.svm.sev.asp_policy.no_debug )
        return true;

    vmsa_dec = alloc_xenheap_pages(0, 0);
    
    sd_dbg.handle = d->arch.hvm.svm.sev.asp_handle;
    sd_dbg.reserved = 0;
    sd_dbg.src_addr = page_to_maddr(vmsa_page);
    sd_dbg.dst_addr = virt_to_maddr(vmsa_dec);
    sd_dbg.len = PAGE_SIZE_4K;

    /* Make sure VMSA is up to date on all CPUs */
    flush_all(FLUSH_CACHE_WRITEBACK);

    rc = sev_do_cmd(SEV_CMD_DBG_DECRYPT, &sd_dbg, &psp_ret, true);

    if ( rc )
    {
       printk(XENLOG_ERR "asp: failed to DBG_DECRYPT d%huv%d: err %u\n",
              d->domain_id, v->vcpu_id, psp_ret);
       free_xenheap_page(vmsa_dec);
       return true;
    }

    flush_area_local(vmsa_dec, FLUSH_CACHE_EVICT);

    printk("Decrypted SEV-ES state\n");
    printk("cpl = %d efer = %#"PRIx64" star = %#"PRIx64" lstar = %#"PRIx64"\n",
           vmsa_dec->cpl, vmsa_dec->efer, vmsa_dec->star, vmsa_dec->lstar);

    printk("CR0 = 0x%016"PRIx64" CR2 = 0x%016"PRIx64"\n",
           vmsa_dec->cr0, vmsa_dec->cr2);
    printk("CR3 = 0x%016"PRIx64" CR4 = 0x%016"PRIx64"\n",
           vmsa_dec->cr3, vmsa_dec->cr4);
    printk("DR6 = 0x%016"PRIx64", DR7 = 0x%016"PRIx64"\n",
           vmsa_dec->dr6, vmsa_dec->dr7);
    printk("CSTAR = 0x%016"PRIx64" SFMask = 0x%016"PRIx64"\n",
           vmsa_dec->cstar, vmsa_dec->sfmask);
    printk("KernGSBase = 0x%016"PRIx64" PAT = 0x%016"PRIx64"\n",
           vmsa_dec->kerngsbase, vmsa_dec->g_pat);
    printk("SSP = 0x%016"PRIx64" S_CET = 0x%016"PRIx64" ISST = 0x%016"PRIx64"\n",
           vmsa_dec->ssp, vmsa_dec->s_cet, vmsa_dec->isst_addr);

    printk("       sel attr  limit   base\n");
    svm_dump_sel("  CS", &vmsa_dec->cs);
    svm_dump_sel("  DS", &vmsa_dec->ds);
    svm_dump_sel("  SS", &vmsa_dec->ss);
    svm_dump_sel("  ES", &vmsa_dec->es);
    svm_dump_sel("  FS", &vmsa_dec->fs);
    svm_dump_sel("  GS", &vmsa_dec->gs);
    svm_dump_sel("GDTR", &vmsa_dec->gdtr);
    svm_dump_sel("LDTR", &vmsa_dec->ldtr);
    svm_dump_sel("IDTR", &vmsa_dec->idtr);
    svm_dump_sel("  TR", &vmsa_dec->tr);

    regs->r15 = vmsa_dec->r15;
    regs->r14 = vmsa_dec->r14;
    regs->r13 = vmsa_dec->r13;
    regs->r12 = vmsa_dec->r12;
    regs->rbp = vmsa_dec->rbp;
    regs->rbx = vmsa_dec->rbx;
    regs->r11 = vmsa_dec->r11;
    regs->r10 = vmsa_dec->r10;
    regs->r9 = vmsa_dec->r9;
    regs->r8 = vmsa_dec->r8;
    regs->rax = vmsa_dec->rax;
    regs->rcx = vmsa_dec->rcx;
    regs->rdx = vmsa_dec->rdx;
    regs->rsi = vmsa_dec->rsi;
    regs->rdi = vmsa_dec->rdi;
    regs->rip = vmsa_dec->rip;
    regs->rflags = vmsa_dec->rflags;
    regs->rsp = vmsa_dec->rsp;
    
    vcpu_show_registers(v);

    free_xenheap_page(vmsa_dec);

    return true;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

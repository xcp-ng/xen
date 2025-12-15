/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * sev_es_debug.c: debug SEV-ES features
 * Copyright (c) 2025, Vates SAS
 *
 */

#include <xen/lib.h>
#include <xen/sched.h>

#include <asm/hvm/svm/sev_es.h>

static void svm_dump_sel(const char *name, const struct segment_register *s)
{
    printk("%s: %04x %04x %08x %016"PRIx64"\n",
           name, s->sel, s->attr, s->limit, s->base);
}

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
    struct page_info *vmsa_page = v->arch.hvm.svm.sev.vmsa_page;
    struct sev_es_save_area *vmsa_dec = NULL;
    struct sev_data_dbg sd_dbg = {};
    struct cpu_user_regs *regs = &v->arch.user_regs;
    unsigned int psp_ret;
    int rc = 0;

    if ( !is_sev_es_domain(d) )
			return false;

		if ( !vmsa_page || d->arch.hvm.svm.sev.asp_policy.no_debug )
			return true;

    vmsa_dec = alloc_xenheap_pages(0, 0);
    if ( !d )
       return true;
    
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

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

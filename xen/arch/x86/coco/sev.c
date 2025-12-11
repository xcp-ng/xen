/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * coco/sev.c: AMD SEV support
 * Copyright (c) Vates SAS
 */

#include <xen/config.h>
#include <xen/coco.h>
#include <xen/guest_access.h>
#include <xen/mm.h>
#include <xen/xmalloc.h>

#include <asm/cpu-policy.h>
#include <asm/cpufeature.h>
#include <asm/flushtlb.h>
#include <asm/p2m.h>
#include <asm/psp-sev.h>
#include <asm/hvm/asid.h>
#include <asm/hvm/svm/sev.h>
#include <asm/hvm/svm/sev_es.h>
#include <asm/hvm/svm/svmdebug.h>
#include <asm/msr.h>

#include <public/domctl.h>
#include <public/hvm/coco.h>

static int sev_domain_initialise(struct domain *d)
{
    struct sev_data_launch_start sd_ls = {};
    struct sev_data_activate sd_a = {};
    union sev_guest_policy sev_policy = d->arch.hvm.svm.sev.asp_policy;
    unsigned int psp_ret = 0;
    long rc = 0;

    if (unlikely(d->arch.hvm.svm.sev.status != SEV_GUEST_UNINIT)) {
        /* This should never happen */
        printk(XENLOG_ERR "sev: Trying to init an already init guest\n");
    }

    if ( sev_policy.rsvd0 || sev_policy.rsvd1 )
    {
        printk(XENLOG_ERR "sev: Reserved bits set in policy\n");
        return -EINVAL;
    }

    if ( sev_policy.es && !cpu_has_sev_es )
    {
        printk(XENLOG_ERR "sev: SEV-ES is not supported\n");
        return -EINVAL;
    }

    if ( !(d->arch.emulation_flags & XEN_X86_EMU_FORCE_X2APIC) )
    {
        printk(XENLOG_ERR "sev: Guest must have forced x2apic\n");
        return -EINVAL;
    }

    sd_ls.handle = 0; /* generate new one */
    sd_ls.policy = sev_policy;
    if (d->arch.hvm.svm.sev.owner_crt && d->arch.hvm.svm.sev.session) {
        sd_ls.dh_cert_address = virt_to_maddr(d->arch.hvm.svm.sev.owner_crt);
        sd_ls.dh_cert_len = sizeof(*d->arch.hvm.svm.sev.owner_crt);
        sd_ls.session_address = virt_to_maddr(d->arch.hvm.svm.sev.session);
        sd_ls.session_len = sizeof(*d->arch.hvm.svm.sev.session);
    } else {
        sd_ls.dh_cert_address = 0; /* do not DH stuff */
    }

    rc = sev_do_cmd(SEV_CMD_LAUNCH_START, (void *)(&sd_ls), &psp_ret, true);
    if ( rc || psp_ret )
    {
        printk(XENLOG_ERR "asp: failed to LAUNCH_START domain(%d): psp_ret %u\n",
                d->domain_id, psp_ret);
        return rc;
    }
    xfree(d->arch.hvm.svm.sev.owner_crt);
    xfree(d->arch.hvm.svm.sev.session);
    d->arch.hvm.svm.sev.owner_crt = NULL;
    d->arch.hvm.svm.sev.session = NULL;

    sd_a.handle = sd_ls.handle;
    sd_a.asid = d->arch.hvm.asid.asid;

    rc = sev_do_cmd(SEV_CMD_ACTIVATE, (void *)(&sd_a), &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to ACTIVATE domain(%d): psp_ret %u\n",
                d->domain_id, psp_ret);
        return rc;
    }

    d->arch.hvm.svm.sev.asp_handle = sd_ls.handle;
    d->arch.hvm.svm.sev.status = SEV_GUEST_LUPDATE;
    return 0;
}

static int sev_domain_prepare_initial_mem(struct domain *d, gfn_t gfn, size_t count)
{
    struct page_info *page;
    int rc = 0;
    unsigned int psp_ret = 0;
    struct sev_data_launch_update_data sd_lud;

    mfn_t mfn = INVALID_MFN, mfn_base = INVALID_MFN;
    size_t segment_size = 0;

    if (unlikely(d->arch.hvm.svm.sev.status != SEV_GUEST_LUPDATE)) {
        /* This should never happen */
        printk(XENLOG_ERR "sev: Trying to update a guest in wrong state\n");
    }

    flush_all(FLUSH_CACHE_WRITEBACK);

    do {
        page = get_page_from_gfn(d, gfn_x(gfn), NULL, P2M_ALLOC);
        if ( unlikely(!page) )
            return rc;

        mfn = page_to_mfn(page);
        put_page(page);

        if ( !mfn_valid(mfn_base) )
            mfn_base = mfn;
        else
        {
            /* Check for a break. */
            if (mfn_x(mfn_base) + segment_size != mfn_x(mfn) || segment_size == 512)
            {
                printk(XENLOG_DEBUG
                       "asp: LAUNCH_UPDATE_DATA d%hu: base=%"PRI_xen_pfn", size=%zx\n",
                       d->domain_id, mfn_x(mfn_base), segment_size);

                sd_lud.reserved = 0;
                sd_lud.handle = d->arch.hvm.svm.sev.asp_handle;
                sd_lud.address = mfn_x(mfn_base) << PAGE_SHIFT;
                sd_lud.len = segment_size * PAGE_SIZE;
                rc = sev_do_cmd(SEV_CMD_LAUNCH_UPDATE_DATA, (void *)(&sd_lud),
                                &psp_ret, true);
                if ( rc || psp_ret )
                {
                    printk(XENLOG_ERR
                           "asp: failed to LAUNCH_UPDATE_DATA dom(%hu): err %u\n",
                           d->domain_id, psp_ret);
                    return rc;
                }

                mfn_base = mfn;
                segment_size = 0;
            }
        }

        gfn = gfn_add(gfn, 1);
        segment_size++;
        count--;
    } while ( count );

    // Last launch update data.
    if ( segment_size )
    {
        sd_lud.reserved = 0;
        sd_lud.handle = d->arch.hvm.svm.sev.asp_handle;
        sd_lud.address = mfn_x(mfn_base) << PAGE_SHIFT;
        sd_lud.len = segment_size * PAGE_SIZE;
        rc = sev_do_cmd(SEV_CMD_LAUNCH_UPDATE_DATA, (void *)(&sd_lud),
                        &psp_ret, true);

        if ( rc )
            printk(XENLOG_ERR "asp: failed to LAUNCH_UPDATE_DATA dom(%hu): err %u\n",
                   d->domain_id, psp_ret);
    }

    return rc;
}

static int sev_domain_finish_memory(struct domain *d) {
    struct sev_data_launch_measure sd_lm;
    unsigned int psp_ret = 0;
    long rc = 0;

    if (unlikely(d->arch.hvm.svm.sev.status != SEV_GUEST_LUPDATE)) {
        /* This should never happen */
        printk(XENLOG_ERR "sev: Trying to measure a guest in wrong state\n");
    }

    sd_lm.handle = d->arch.hvm.svm.sev.asp_handle;
    sd_lm.address = virt_to_maddr(d->arch.hvm.svm.sev.measure);
    sd_lm.len = sizeof(d->arch.hvm.svm.sev.measure);
    sd_lm.reserved = 0;

    rc = sev_do_cmd(SEV_CMD_LAUNCH_MEASURE, (void *)(&sd_lm), &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to LAUNCH_MEASURE for d%hu: psp_ret %u, rc %ld\n",
            d->domain_id, psp_ret, rc);

        if (psp_ret == SEV_RET_INVALID_LEN)
            printk(XENLOG_ERR "asp: Expected %"PRIu32" bytes\n", sd_lm.len);
        return rc;
    }

    printk(XENLOG_DEBUG"asp: LAUNCH_MEASURE for d%hu: ",  d->domain_id);
    for (int i = 0; i < sd_lm.len; i++) {
        printk("%02x", d->arch.hvm.svm.sev.measure[i]);
    }
    printk("\n");
    
    d->arch.hvm.svm.sev.status = SEV_GUEST_LSECRET;
    d->arch.hvm.svm.sev.measure_len = sd_lm.len;

    return 0;
}

static int sev_domain_creation_finished(struct domain *d)
{
    struct sev_data_launch_finish sd_lf;
    unsigned int psp_ret;
    long rc = 0;

    if (unlikely(d->arch.hvm.svm.sev.status != SEV_GUEST_LSECRET)) {
        /* This should never happen */
        printk(XENLOG_ERR "sev: Trying to finish a guest in wrong state\n");
    }

    sd_lf.handle = d->arch.hvm.svm.sev.asp_handle;

    rc = sev_do_cmd(SEV_CMD_LAUNCH_FINISH, (void *)(&sd_lf), &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to LAUNCH_FINISH for d%hu: psp_ret %u, rc %ld\n",
                d->domain_id, psp_ret, rc);
        return rc;
    }
    d->arch.hvm.svm.sev.status = SEV_GUEST_RUNNING;
    return 0;
}

static void sev_domain_destroy(struct domain *d)
{
    struct sev_data_deactivate sd_da;
    struct sev_data_decommission sd_de;
    unsigned int psp_ret;
    long rc = 0;
    struct vcpu *v;

    /* FIXME: Why do I need that here and not in vcpu_destroy ? */
    for_each_vcpu( d, v )
    {
        struct sev_vcpu *sev = &v->arch.hvm.svm.sev;

        if ( v->arch.hvm.svm.sev.ghcb_page )
        {
            UNMAP_DOMAIN_PAGE(sev->ghcb_map);
            put_page(sev->ghcb_page);
            sev->ghcb_page = NULL;
            sev->ghcb_gfn = 0;
        }
    }

    sd_da.handle = d->arch.hvm.svm.sev.asp_handle;

    rc = sev_do_cmd(SEV_CMD_DEACTIVATE, (void *)(&sd_da), &psp_ret, true);
    if (rc)
    {
        printk(XENLOG_ERR "asp: failed to DEACTIVATE for d%hu: psp_ret %u\n",
               d->domain_id, psp_ret);
        return;
    }

    /**
     * SEV API Specification, 6.22 DF_FLUSH
     *
     * The x86 system software invokes this command after deactivating one or more
     * guests. The x86 system software must execute a WBINVD on the hardware threads
     * that the previous guest was active on before invoking the DF_FLUSH command.
     *
     * Each core must have executed a WBINVD instruction since the last DEACTIVATE
     * command was invoked.
     */
    flush_all(FLUSH_CACHE_EVICT);

    rc = sev_do_cmd(SEV_CMD_DF_FLUSH, NULL, &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to DF_FLUSH for d%hu: psp_ret %u\n",
               d->domain_id, psp_ret);
        return;
    }

    sd_de.handle = d->arch.hvm.svm.sev.asp_handle;

    rc = sev_do_cmd(SEV_CMD_DECOMMISSION, (void *)(&sd_de), &psp_ret, true);
    if (rc)
    {
        printk(XENLOG_ERR "asp: failed to DECOMMISSION for d%hu: psp_ret %u\n",
               d->domain_id, psp_ret);
        return;
    }

    d->arch.hvm.svm.sev.asp_handle = 0;
    d->arch.hvm.svm.sev.status = SEV_GUEST_UNINIT;
}

static int sev_asid_alloc(struct domain *d, struct hvm_asid *asid)
{
    unsigned long asid_min = raw_cpu_policy.extd.min_no_es_asid;
    unsigned long asid_max = raw_cpu_policy.extd.max_sev_guests;

    return hvm_asid_alloc_range(asid, asid_min, asid_max);
}

static int sev_attestation_report(struct domain *d,
    struct coco_attestation_report *args) {
    struct sev_data_attestation_report report;
    unsigned int psp_ret = 0;
    int rc = 0;


    if (unlikely(!(d->arch.hvm.svm.sev.status == SEV_GUEST_LSECRET ||
                    d->arch.hvm.svm.sev.status == SEV_GUEST_SENT ||
                    d->arch.hvm.svm.sev.status == SEV_GUEST_SUPDATE ||
                    d->arch.hvm.svm.sev.status == SEV_GUEST_RUNNING))) {
        printk(XENLOG_ERR "sev: Trying to get an attestation for a guest in wrong state\n");
    }

    report.handle = d->arch.hvm.svm.sev.asp_handle;
    report.len = sizeof(struct sev_attestation_report_response);
    args->len = sizeof(struct sev_attestation_report_response);
    report.reserved = 0;
    report.address = (uint64_t) virt_to_maddr(&args->sev);
    for (size_t i =0; i < 16; i++) { // or memset ?
        report.mnonce[i] = args->mnonce[i];
    }

    printk(XENLOG_ERR
           "asp: ATTESTATION_REPORT d%d: size=%u\n", d->domain_id, args->len);

    rc = sev_do_cmd(SEV_CMD_ATTESTATION_REPORT, (void *)(&report),
        &psp_ret, true);

    if (!rc && !psp_ret) {
        return 0;
    }
    printk(XENLOG_ERR "asp: failed to ATTESTATION for d%hu: psp_ret %x\n",
           d->domain_id, psp_ret);

    return rc;
}

static int sev_domain_update_secret(struct domain *d,
    coco_domain_secret_t *args) {
    struct page_info *page;
    struct sev_data_launch_secret cmd;
    unsigned int psp_ret = 0;
    gfn_t gfn;
    mfn_t mfn = INVALID_MFN;
    int rc = 0;
    void *data = _xmalloc(args->sev.secret_len, __alignof__(args->sev.secret));
    
    if ( copy_from_guest(data, args->sev.secret, args->sev.secret_len))
        return -EFAULT;
    
    if (unlikely(d->arch.hvm.svm.sev.status != SEV_GUEST_LSECRET)) {
        printk(XENLOG_ERR "sev: Trying to get an attestation for a guest in wrong state\n");
    }
    
    if (args->sev.secret_len > PAGE_SIZE - (args->sev.gpa & 0xFFF)) {
        return -ENOSPC;
    }
    //TODO : max pages or tot pages ?
    if (args->sev.gpa + args->sev.secret_len > d->max_pages << 12) {
        return -ENOSPC;
    }
    
    flush_all(FLUSH_CACHE_WRITEBACK);
        
    gfn = gaddr_to_gfn(args->sev.gpa);
    put_gfn(d, gfn);
    page = get_page_from_gfn(d, gfn_x(gfn), NULL, P2M_ALLOC);
    if ( unlikely(!page) )
        return rc;
    mfn = page_to_mfn(page);
    put_page(page);
    if (!mfn_valid(mfn)) {
        return -EFAULT;
    }
    printk(XENLOG_DEBUG"asp: LAUNCH_UPDATE_DATA d%hu: base=%"PRI_xen_pfn", size=%zx\n",d->domain_id,  mfn_to_maddr(mfn) + (args->sev.gpa & 0xFFF), args->sev.secret_len);
    
    cmd.guest_address = mfn_to_maddr(mfn) + (args->sev.gpa & 0xFFF);
    cmd.guest_len = args->sev.secret_len;
    
    cmd.handle = d->arch.hvm.svm.sev.asp_handle;
    cmd.trans_address = (uint64_t) virt_to_maddr(data);
    cmd.trans_len = args->sev.secret_len;
    cmd.hdr_address = (uint64_t) virt_to_maddr(&args->sev.header);
    cmd.hdr_len = sizeof(args->sev.header);
    rc = sev_do_cmd(SEV_CMD_LAUNCH_UPDATE_SECRET, (&cmd),
    &psp_ret, true);
    
    xfree(data);
    
    if (!rc && !psp_ret) {
        return 0;
    }
    printk(XENLOG_ERR "asp: failed SEV_CMD_LAUNCH_UPDATE_SECRET for d%hu: psp_ret %x\n",
        d->domain_id, psp_ret);
        
    return rc;
}

static int sev_es_asid_alloc(struct domain *d, struct hvm_asid *asid)
{
    if ( WARN_ON(!raw_cpu_policy.extd.min_no_es_asid) )
        return -ENOSPC;

    return hvm_asid_alloc_range(asid, 1, raw_cpu_policy.extd.min_no_es_asid - 1);
}

static int sev_es_domain_vcpu_initialise(struct domain *d)
{
    struct vcpu *v;
    struct sev_data_launch_update_vmsa sd_luv = {};
    sd_luv.handle = d->arch.hvm.svm.sev.asp_handle;
    sd_luv.reserved = 0;

    if (unlikely(d->arch.hvm.svm.sev.status != SEV_GUEST_LUPDATE)) {
        /* This should never happen */
        printk(XENLOG_ERR "sev: Trying to update a guest in wrong state. Stage : %d\n", d->arch.hvm.svm.sev.status);
    }

    for_each_vcpu ( d, v )
    {
        int rc;
        unsigned int psp_ret;
        struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
        struct cpu_user_regs *regs = &v->arch.user_regs;
        void *vmsa;

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

        vmcb->vmsa_regs.xcr0 = X86_XCR0_X87; /* must be set */

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

        sd_luv.address = page_to_maddr(v->arch.hvm.svm.sev.vmsa_page);
        sd_luv.len = PAGE_SIZE_4K;

        rc = sev_do_cmd(SEV_CMD_LAUNCH_UPDATE_VMSA, (void *)(&sd_luv), &psp_ret, true);
        if ( rc )
        {
            printk(XENLOG_ERR "asp: failed to LAUNCH_UPDATE_VMSA d%huv%d: psp_ret %u\n",
                   d->domain_id, v->vcpu_id, psp_ret);
            return rc;
        }
        
        printk(XENLOG_DEBUG "asp: LAUNCH_UPDATE_VMSA d%huv%d:\n",
                   d->domain_id, v->vcpu_id);
    }

    return 0;
}

static int sev_init(void)
{
    unsigned long syscfg, hwcr;

    if ( WARN_ON(!cpu_has_sme || !cpu_has_sev) )
        return -ENOSYS;

    /* AMD SME and SmmLock are required for SEV. */
    rdmsrl(MSR_K8_SYSCFG, syscfg);

    if ( !(syscfg & SYSCFG_MEM_ENCRYPT) )
    {
        printk(XENLOG_ERR "sev: SME is not enabled\n");
        return -EINVAL;
    }

    rdmsrl(MSR_K8_HWCR, hwcr);

    if ( !(hwcr & K8_HWCR_SMM_LOCK) )
    {
        printk(XENLOG_ERR "sev: SMM Lock is not enabled\n");
        return -EINVAL;
    }

    ASSERT(raw_cpu_policy.extd.c_bit_pos > 0);
    ASSERT(raw_cpu_policy.extd.max_sev_guests > 0);

    printk(XENLOG_INFO "sev: C-bit is %"PRIu32"\n", raw_cpu_policy.extd.c_bit_pos);
    printk(XENLOG_INFO "sev: Supports up to %"PRIu32" SEV guests\n",
            raw_cpu_policy.extd.max_sev_guests - raw_cpu_policy.extd.min_no_es_asid);

    if ( cpu_has_sev_es )
        printk(XENLOG_INFO "sev-es: Supports up to %"PRIu32" SEV-ES guests\n",
            raw_cpu_policy.extd.min_no_es_asid - 1);

    /* Make non-SEV ASIDs allocated above max_sev_guests if possible. */
    if ( asid_default_min < raw_cpu_policy.extd.max_sev_guests )
        asid_default_min = raw_cpu_policy.extd.max_sev_guests;
    return 0;
}

static int sev_get_platform_status(struct coco_platform_status *status)
{
    status->platform = COCO_PLATFORM_amd_sev;
    /* cannot call do_sev_cmd, platform isn't initialized yet
        so the structure is missing information like version... */
    if ( cpu_has_sev_es )
        status->platform_flags |= COCO_PLATFORM_FLAG_sev_es;

    status->flags = COCO_STATUS_FLAG_supported;

    return 0;
}

static int sev_get_platform_certs(struct coco_platform_certs *certs) {
    int rc;
    unsigned int psp_ret = 0;
    struct sev_data_pdh_cert_export pdh_cert_export;
    struct sev_user_data_status status;
    struct sev_data_get_id get_id;


    rc = sev_do_cmd(SEV_CMD_PLATFORM_STATUS, (void *)(&status), &psp_ret, true);
    if ( rc || psp_ret )
    {
        printk(XENLOG_ERR "asp: failed to PLATFORM_STATUS: rc %u psp_ret %u\n", rc, psp_ret);
        return rc;
    }
    certs->status = platform_status; // flags
    certs->status.version_major = status.api_major;
    certs->status.version_minor = status.api_minor;
    certs->status.version_build = status.build;
    certs->status.flags = certs->status.flags |
            (status.flags & 0x1) ? COCO_STATUS_FEATURES_PLATFORM_OWNED : 0;

    if (status.api_major > 1 || status.api_minor > 15) {
        // SEV GET_ID is available from SEV API v0.16 and up
        get_id.address = (uint64_t) virt_to_maddr(&certs->hwid);
        get_id.len = sizeof(certs->hwid);

        rc = sev_do_cmd(SEV_CMD_GET_ID, (void *)(&get_id), &psp_ret, true);
        if ( rc || psp_ret )
        {
            printk(XENLOG_ERR "asp: failed to GET_ID: rc %u psp_ret %u\n", rc, psp_ret);
            return rc;
        }
        certs->cpu_number = nr_sockets;
    }

    pdh_cert_export.pdh_cert_address = (uint64_t) virt_to_maddr(&certs->sev.pdh);
    pdh_cert_export.pdh_cert_len = sizeof(certs->sev.pdh);

    /* PSP needs contiguous memory for the 3 certificates */
    pdh_cert_export.cert_chain_address = (uint64_t) virt_to_maddr(&certs->sev.pek);
    pdh_cert_export.cert_chain_len = sizeof(certs->sev.pek) * 3;
    pdh_cert_export.reserved = 0;

    rc = sev_do_cmd(SEV_CMD_PDH_CERT_EXPORT, (void *)(&pdh_cert_export), &psp_ret, true);
    if ( rc || psp_ret )
    {
        printk(XENLOG_ERR "asp: failed to PDH_CERT_EXPORT: rc %u psp_ret %u\n", rc, psp_ret);
        return rc;
    }
    return 0;
}

static int sev_get_csr(coco_certificate_t *cert) {
    struct sev_data_pek_csr arg;
    struct sev_certificate *c = &(cert->sev);
    unsigned int psp_ret = 0;
    int rc = 0;

    arg.len = sizeof(cert->sev);
    arg.address = (uint64_t) virt_to_maddr(c);

    rc = sev_do_cmd(SEV_CMD_PEK_CSR, (void *)(&arg),
    &psp_ret, true);

    if (rc || psp_ret) {
        printk(XENLOG_ERR "asp: PEK_CSR: rc %d psp %x size=%u\n",rc, psp_ret, arg.len);
        return rc;
    }
    return 0;
}

static int sev_regen_certificate(enum coco_certificate_name cert) {
    int rc;
    unsigned int psp_ret;

    COCO_CERTIFICATE_NAME_ARRAY_DEF()

    switch (cert) {
        case sev_pek: {
            rc = sev_do_cmd(SEV_CMD_PEK_GEN, NULL, &psp_ret, true);
            break;
        }
        case sev_pdh:{
            rc = sev_do_cmd(SEV_CMD_PDH_GEN, NULL, &psp_ret, true);
            break;
        }
        default:
        printk(XENLOG_ERR"sev: Invalid certificate");
        return -EINVAL;
    }
    if (rc || psp_ret) {
        printk(XENLOG_ERR "sev: regen certificate %d failed: rc %d psp %x \n", cert, rc, psp_ret);
        switch (psp_ret) {
            case  SEV_RET_INVALID_PLATFORM_STATE:
            printk(XENLOG_ERR "asp: the platform is not in the right state,"
                       "no guest should run and the platform must be init\n");
            break;
        }
    } else {
        printk(XENLOG_ERR "sev: %s certificate regenerate\n", certs_name[cert]);
    }
    return rc;
}

static int sev_import_certificate(coco_platform_import_certs_t *certs) {
    int rc;
    unsigned int psp_ret = 0;
    struct sev_data_pek_cert_import arg;
    arg.oca_cert_address = virt_to_maddr(&(certs->sev.oca));
    arg.oca_cert_len = sizeof(certs->sev.oca);
    arg.pek_cert_address = virt_to_maddr(&(certs->sev.pek));
    arg.pek_cert_len = sizeof(certs->sev.pek);

    rc = sev_do_cmd(SEV_CMD_PEK_CERT_IMPORT, &arg, &psp_ret, true);

    if (rc || psp_ret) {
        printk(XENLOG_ERR "asp: SEV_CMD_PEK_CERT_IMPORT: rc %d psp %x \n", rc, psp_ret);
        switch (psp_ret) {
            case  SEV_RET_ALREADY_OWNED:
            printk(XENLOG_ERR "asp: the platform is already owned, regenerate the certificate to own it\n");
            break;
        }
    }
    return rc;
}

static int sev_platform_update(void* firmware, int len) {
    int rc;
    unsigned int psp_ret = 0;

    rc = sev_do_cmd(SEV_CMD_SHUTDOWN, NULL, &psp_ret, true);
    if (rc || psp_ret) {
        printk(XENLOG_ERR "asp: SEV_CMD_SHUTDOWN: rc %d psp %x \n", rc, psp_ret);
        printk(XENLOG_ERR "sev: can't update, is there running guest ?\n");
        return rc;
    }
    rc = sp_update_firmware(firmware, len, &psp_ret);

    return rc;
}

static struct coco_domain_ops sev_domain_ops = {
    .prepare_initial_mem = sev_domain_prepare_initial_mem,
    .domain_initialise = sev_domain_initialise,
    .domain_creation_finished = sev_domain_creation_finished,
    .domain_memory_finished = sev_domain_finish_memory,
    .domain_attestation_report = sev_attestation_report,
    .domain_destroy = sev_domain_destroy,
    .asid_alloc = sev_asid_alloc,
    .domain_update_secret = sev_domain_update_secret
};

static struct coco_domain_ops sev_es_domain_ops = {
    .prepare_initial_mem = sev_domain_prepare_initial_mem,
    .domain_initialise = sev_domain_initialise,
    .domain_vcpu_initialise = sev_es_domain_vcpu_initialise,
    .domain_creation_finished = sev_domain_creation_finished,
    .domain_memory_finished = sev_domain_finish_memory,
    .domain_destroy = sev_domain_destroy,
    .domain_attestation_report = sev_attestation_report,
    .asid_alloc = sev_es_asid_alloc,
    .show_execution_state = sev_vmsa_dump,
    .domain_update_secret = sev_domain_update_secret
};

static struct coco_domain_ops *sev_get_domain_ops(struct domain *d,
    const struct xen_domctl_createdomain *config)
{
    /* We need to set a valid policy for the initialization. */
    union sev_guest_policy *sev_policy = &d->arch.hvm.svm.sev.asp_policy;

    if (config->arch.coco.sev.flags & XEN_X86_SEV_POLICY_VALID ) {
        sev_policy->raw = config->arch.coco.sev.policy;
    }
    else
        // Use a reasonable default policy
        *sev_policy = (union sev_guest_policy){
            .no_key_sharing = true,
            .no_debug = true,
            .no_send = true, /* To change when SEV live migration is something */
            .es = cpu_has_sev_es, /* Use SEV-ES if available */
        };
    if (config->arch.coco.sev.sp.p) {
        sev_start_parameters_t sp;
        if ( copy_from_guest(&sp, config->arch.coco.sev.sp, 1) )
            goto out;
        d->arch.hvm.svm.sev.owner_crt = xmalloc(struct sev_certificate);
        d->arch.hvm.svm.sev.session = xmalloc(struct sev_session);
        memcpy(d->arch.hvm.svm.sev.owner_crt, sp.crt, sizeof(sp.crt));
        memcpy(d->arch.hvm.svm.sev.session, sp.session, sizeof(sp.session));
    }

out:
    return sev_policy->es ? &sev_es_domain_ops : &sev_domain_ops;
}

struct coco_ops sev_coco_ops = {
    .name = "SEV",
    .init = sev_init,
    .get_platform_status = sev_get_platform_status,
    .get_platform_certs = sev_get_platform_certs,
    .get_certificate_signing_request = sev_get_csr,
    .import_certificates = sev_import_certificate,
    .update_platform = sev_platform_update,
    .regen_platform_cert = sev_regen_certificate,
    .get_domain_ops = sev_get_domain_ops,
};


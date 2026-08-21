/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * coco/sev.c: AMD SEV support
 * Copyright (c) Vates SAS
 */

#include <xen/coco.h>
#include <xen/config.h>
#include <xen/errno.h>
#include <xen/param.h>
#include <xen/mm.h>
#include <xen/smp.h>

#include <asm/cpu-policy.h>
#include <asm/cpufeature.h>
#include <asm/flushtlb.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/p2m.h>
#include <asm/psp-sev.h>
#include <asm/hvm/asid.h>
#include <asm/hvm/svm.h>
#include <asm/hvm/svm/sev_es.h>
#include <asm/hvm/svm/sev_snp.h>

#include <public/domctl.h>
#include <public/hvm/coco.h>
#include <public/arch-x86/hvm/coco.h>

static mfn_t __ro_after_init rmp_base_mfn, rmp_end_mfn;
static bool __ro_after_init opt_sev_snp = false;

static __ro_after_init struct sev_data_snp_status snp_platform_status;

static int __init cf_check parse_sev(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("snp", s, ss)) >= 0 )
            opt_sev_snp = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("sev", parse_sev);

static int sev_domain_initialise(struct domain *d)
{
    struct sev_data_launch_start sd_ls = {};
    struct sev_data_activate sd_a = {};
    struct sev_state *sev = &d->arch.hvm.svm.sev;
    union sev_guest_policy sev_policy = sev->legacy.policy;
    unsigned int psp_ret = 0;
    long rc = 0;

    if ( sev_policy.rsvd0 || sev_policy.rsvd1 )
    {
        printk(XENLOG_ERR "sev: Reserved bits set in policy\n");
        return -EINVAL;
    }

    if ( sev_policy.es && !cpu_has_sev_es )
    {
        printk(XENLOG_ERR "sev: SEV-ES is not supported\n");
        return -ENOSYS;
    }

    sd_ls.handle = 0; /* generate new one */
    sd_ls.policy = sev_policy;
    sd_ls.dh_cert_address = 0; /* do not DH stuff */

    rc = sev_do_cmd(SEV_CMD_LAUNCH_START, (void *)(&sd_ls), &psp_ret, true);
    if ( rc || psp_ret )
    {
        printk(XENLOG_ERR "asp: failed to LAUNCH_START domain(%d): psp_ret %u\n",
                d->domain_id, psp_ret);
        return rc;
    }

    sd_a.handle = sd_ls.handle;
    sd_a.asid = d->arch.hvm.asid.asid;

    rc = sev_do_cmd(SEV_CMD_ACTIVATE, (void *)(&sd_a), &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to ACTIVATE domain(%d): psp_ret %u\n",
                d->domain_id, psp_ret);
        return rc;
    }

    sev->legacy.asp_handle = sd_ls.handle;
    return 0;
}

static int sev_domain_prepare_initial_mem(struct domain *d, gfn_t gfn, size_t count)
{
    int rc = 0;
    unsigned int psp_ret = 0;
    struct sev_data_launch_update_data sd_lud;
    uint32_t asp_handle = d->arch.hvm.svm.sev.legacy.asp_handle;
    p2m_type_t t;

    mfn_t mfn = INVALID_MFN, mfn_base = INVALID_MFN;
    size_t segment_size = 0;

    flush_all(FLUSH_CACHE_WRITEBACK);

    /* FIXME: We need to retain gfn refcounts while encrypting pages. */

    do {
        mfn = get_gfn_unshare(d, gfn_x(gfn), &t);

        if ( !p2m_is_ram(t) )
        {
            rc = -EINVAL;
            put_gfn(d, gfn_x(gfn));
            break;
        }

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
                sd_lud.handle = asp_handle;
                sd_lud.address = mfn_x(mfn_base) << PAGE_SHIFT;
                sd_lud.len = segment_size * PAGE_SIZE;
                rc = sev_do_cmd(SEV_CMD_LAUNCH_UPDATE_DATA, (void *)(&sd_lud),
                                &psp_ret, true);
                if ( rc || psp_ret )
                {
                    printk(XENLOG_ERR
                           "asp: failed to LAUNCH_UPDATE_DATA dom(%hu): err %u\n",
                           d->domain_id, psp_ret);
                    put_gfn(d, gfn_x(gfn));
                    return rc;
                }

                mfn_base = mfn;
                segment_size = 0;
            }
        }

        put_gfn(d, gfn_x(gfn));
        gfn = gfn_add(gfn, 1);
        segment_size++;
        count--;
    } while ( count );

    /* Last launch update data. */
    if ( segment_size )
    {
        sd_lud.reserved = 0;
        sd_lud.handle = asp_handle;
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

static int sev_domain_creation_finished(struct domain *d)
{
    struct sev_data_launch_measure sd_lm;
    struct sev_data_launch_finish sd_lf;
    unsigned int psp_ret;
    long rc = 0;
    struct sev_state *sev = &d->arch.hvm.svm.sev;

    sd_lm.handle = sev->legacy.asp_handle;
    sd_lm.address = virt_to_maddr(sev->legacy.measure);
    sd_lm.len = sizeof(sev->legacy.measure);
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

    sd_lf.handle = sev->legacy.asp_handle;

    rc = sev_do_cmd(SEV_CMD_LAUNCH_FINISH, (void *)(&sd_lf), &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to LAUNCH_FINISH for d%hu: psp_ret %u, rc %ld\n",
                d->domain_id, psp_ret, rc);
        return rc;
    }

    return 0;
}

static void sev_es_teardown_vmpl(struct sev_vmpl_state *vmpl)
{
    if ( vmpl->ghcb_page )
    {
        UNMAP_DOMAIN_PAGE(vmpl->ghcb_map);
        put_page(vmpl->ghcb_page);
        vmpl->ghcb_page = NULL;
        vmpl->ghcb_gfn = 0;
    }

    if ( vmpl->vmsa_page )
    {
        put_page(vmpl->vmsa_page);
        vmpl->vmsa_page = NULL;
    }
}

static int sev_es_domain_teardown(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu( d, v )
    {
        struct sev_vcpu *sev_v = &v->arch.hvm.svm.sev;

        for ( unsigned int vmpl = 0; vmpl < SEV_MAX_VMPL; vmpl++ )
            sev_es_teardown_vmpl(&sev_v->vmpl[vmpl]);
    }

    return 0;
}

static void sev_domain_destroy(struct domain *d)
{
    struct sev_data_deactivate sd_da;
    struct sev_data_decommission sd_de;
    unsigned int psp_ret;
    long rc = 0;
    struct sev_state *sev = &d->arch.hvm.svm.sev;

    sd_da.handle = sev->legacy.asp_handle;

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

    sd_de.handle = sev->legacy.asp_handle;

    rc = sev_do_cmd(SEV_CMD_DECOMMISSION, (void *)(&sd_de), &psp_ret, true);
    if (rc)
    {
        printk(XENLOG_ERR "asp: failed to DECOMMISSION for d%hu: psp_ret %u\n",
               d->domain_id, psp_ret);
        return;
    }

    sev->legacy.asp_handle = 0;
}

static int sev_asid_alloc(struct domain *d, struct hvm_asid *asid)
{
    unsigned long asid_min = host_cpu_policy.extd.min_no_es_asid;
    unsigned long asid_max = host_cpu_policy.extd.max_sev_guests;

    return hvm_asid_alloc_range(asid, asid_min, asid_max);
}

static struct coco_domain_ops sev_domain_ops = {
    .prepare_initial_mem = sev_domain_prepare_initial_mem,
    .domain_initialise = sev_domain_initialise,
    .domain_creation_finished = sev_domain_creation_finished,
    .domain_destroy = sev_domain_destroy,
    .asid_alloc = sev_asid_alloc,
};

static int sev_es_asid_alloc(struct domain *d, struct hvm_asid *asid)
{
    if ( WARN_ON(!raw_cpu_policy.extd.min_no_es_asid) )
        return -ENOSPC;

    return hvm_asid_alloc_range(asid, 1, raw_cpu_policy.extd.min_no_es_asid - 1);
}

static int sev_es_domain_creation_finished(struct domain *d)
{
    struct vcpu *v;
    struct sev_data_launch_update_vmsa sd_luv = {};
    sd_luv.handle = d->arch.hvm.svm.sev.legacy.asp_handle;
    sd_luv.reserved = 0;

    for_each_vcpu ( d, v )
    {
        int rc;
        unsigned int psp_ret;
        struct page_info *vmsa_page;

        if ( !v->is_initialised )
            continue;

        vmsa_page = alloc_domheap_page(d, MEMF_no_owner);
        if ( !vmsa_page )
            return -ENOMEM;

        v->arch.hvm.svm.sev.vmpl[0].vmsa_page = vmsa_page;

        rc = sev_es_build_vmsa(v, vmsa_page);
        if ( rc )
        {
            printk(XENLOG_ERR "sev-es: Unable to build d%huv%d VMSA: rc = %d\n",
                   d->domain_id, v->vcpu_id, rc);
            return rc;
        }

        sd_luv.address = page_to_maddr(vmsa_page);
        sd_luv.len = PAGE_SIZE_4K;

        rc = sev_do_cmd(SEV_CMD_LAUNCH_UPDATE_VMSA, (void *)(&sd_luv), &psp_ret, true);
        if ( rc )
        {
            printk(XENLOG_ERR "asp: failed to LAUNCH_UPDATE_VMSA d%huv%d: err %u\n",
                   d->domain_id, v->vcpu_id, psp_ret);
            return rc;
        }
    }

    return sev_domain_creation_finished(d);
}

static struct coco_domain_ops sev_es_domain_ops = {
    .prepare_initial_mem = sev_domain_prepare_initial_mem,
    .domain_initialise = sev_domain_initialise,
    .domain_creation_finished = sev_es_domain_creation_finished,
    .domain_teardown = sev_es_domain_teardown,
    .domain_destroy = sev_domain_destroy,
    .asid_alloc = sev_es_asid_alloc,
    .show_execution_state = sev_vmsa_dump,
};

static void __init snp_init_cpu(void *_param)
{
    unsigned long syscfg;
    rdmsrl(MSR_K8_SYSCFG, syscfg);

    /* Make sure that there is no dirty cache towards RMP table. */
    wbinvd();

    /* Setup RMP MSRs */
    wrmsrl(MSR_AMD64_RMP_BASE, mfn_to_maddr(rmp_base_mfn));
    wrmsrl(MSR_AMD64_RMP_END, mfn_to_maddr(rmp_end_mfn));

    /* Enable MFDM, SNP and VMPL as asked. */
    syscfg |= SYSCFG_MTRR_FIX_DRAM_MOD_EN;
    syscfg |= SYSCFG_SNP_ENABLE;
    syscfg |= SYSCFG_VMPL_ENABLE;

    wrmsrl(MSR_K8_SYSCFG, syscfg);

    /* Transiently set host save area to zero. */
    wrmsrl(MSR_K8_VM_HSAVE_PA, 0);
}

static void __init snp_init_cpu_post(void *_param)
{
    /* Recover host save area */
    wrmsrl(MSR_K8_VM_HSAVE_PA, this_cpu(hsa));
}

/*
 * SEV-SNP initialization needs to be done after all the initcall have been
 * done, as we need to use PSP and ensure various MSR are configured before
 * they get locked down by SEV-SNP enablement.
 */
static int __init sev_init_late(void)
{
    struct sev_data_snp_init_ex init_ex = { 0 };
    int rc = 0;
    unsigned int psp_ret = 0;
    unsigned long nr_rmp_pages = 4, order; /* 16KB */
    struct page_info *rmp_base;

    if ( !opt_sev_snp )
        return 0;

    /* 
     * Setup RMP table, RMP table is composed of : 
     * - 16 KB of "bookkeeping"
     * - RMP entries that cover the "entire" host memory, with 16B per page entries.
     *
     * The RMP table needs to be 8KB aligned.
     * 2 pages (8 KB) covers 512 of physical memory pages.
     */

    /* Count how many pages we need to cover max_pages (fitting the alignment). */
    nr_rmp_pages += 2 * (ROUNDUP(max_page, 512) / 512);

    order = get_order_from_pages(nr_rmp_pages);
    rmp_base = alloc_domheap_pages(NULL, order, MEMF_no_scrub);

    if ( !rmp_base )
    {
        printk(XENLOG_ERR
               "sev-snp: Unable to allocate RMP table (%lu pages, order=%lu)\n",
               nr_rmp_pages, order);
        return -ENOMEM;
    }

    rmp_base_mfn = page_to_mfn(rmp_base);
    rmp_end_mfn = mfn_add(rmp_base_mfn, nr_rmp_pages);

    printk("sev-snp: RMP table [%"PRI_mfn"-%"PRI_mfn"] (%"PRI_mfn"-%"PRI_mfn")\n",
           mfn_x(rmp_base_mfn), mfn_x(rmp_end_mfn),
           mfn_x(rmp_base_mfn), mfn_x(rmp_base_mfn) + (1 << order));

    printk(XENLOG_INFO "sev-snp: Supports up to %"PRIu32" SEV-SNP guests\n",
           host_cpu_policy.extd.min_no_es_asid - 1);

    /* Prepare all other CPUs for SNP_INIT_EX. */
    on_each_cpu(snp_init_cpu, NULL, true);

    /* Finally call SNP_INIT_EX */
    init_ex.init_rmp = true;
    rc = sev_do_cmd(SEV_CMD_SNP_INIT_EX, &init_ex, &psp_ret, true);

    /* Recover HSA on each CPU. */
    on_each_cpu(snp_init_cpu_post, NULL, true);

    if ( rc )
    {
        printk(XENLOG_ERR
               "sev-snp: SNP_INIT_EX failed (rc=%d, psp_ret=%u)\n",
               rc, psp_ret);
        goto err;
    }

    printk("sev-snp: Enabled SEV-SNP and initialized RMP table\n");
    return 0;

err:
    free_domheap_pages(mfn_to_page(rmp_base_mfn), order);
    /*
     * Instead of reporting a error (which will disable coco including SEV/SEV-ES),
     * only disable SEV-SNP we failed to initialize.
     */
    opt_sev_snp = false;
    return 0;
}

static void snp_reclaim_mem(struct domain *d, struct page_info *pg)
{
    /* All-0 is the default state for hypervisor-owned pages. */
    struct rmp_entry entry = { 0 };
    int rc = 0;

    ASSERT(opt_sev_snp);

    do {
        rc = rmpupdate(pg, &entry);

        if ( rc )
        {
            if ( rc != -EAGAIN )
            {
                /*
                 * If you fail here, there's a good chance that you tried to reclaim a
                 * immutable page, likely a SNP_DECOMMISSION or SNP_RECLAIM_PAGE call
                 * is missing.
                 */
                printk(XENLOG_ERR "sev-snp: Unexpected rmpupdate failure rc=%d\n", rc);
                BUG();
            }
            cpu_relax();
        }
    } while ( rc != 0 );

    dprintk(XENLOG_DEBUG, "sev-snp: Reclaimed MFN:%"PRI_mfn" from ",
            mfn_x(page_to_mfn(pg)));
    
    pg->count_info &= ~PGC_coco_restrict;
    
    if ( d )
        dprintk(XENLOG_DEBUG, "domain %d\n", d->domain_id);
    else
        dprintk(XENLOG_DEBUG, "firmware\n");
}


static int snp_reclaim_immutable_page(struct page_info *pg)
{
    int rc = 0;
    unsigned int psp_ret = 0;

    struct sev_data_snp_page_reclaim ctx = {
        .paddr = page_to_maddr(pg)
    };

    rc = sev_do_cmd(SEV_CMD_SNP_PAGE_RECLAIM, &ctx, &psp_ret, true);

    if ( rc )
    {
        uint32_t status;
        printk(XENLOG_ERR
               "sev-snp: Unable to reclaim firmware page (%d, %u)\n",
               rc, psp_ret);
        /*
         * Writes to this page will cause RMP violation and we can't manage to
         * transition it back to a acceptable state. Mark the page as broken to avoid
         * reusing it in the future..
         */
        offline_page(page_to_mfn(pg), true, &status);
        return rc;
    }

    /* Then finally put back the page into being hypervisor owned. */
    snp_reclaim_mem(NULL, pg);
    return 0;
}

static int snp_decommision_gctx(struct page_info *pg)
{
    int rc = 0;
    unsigned int psp_ret = 0;

    struct snp_guest_context ctx = {
        .gctx_paddr = page_to_maddr(pg)
    };

    rc = sev_do_cmd(SEV_CMD_SNP_DECOMMISSION, &ctx, &psp_ret, true);
    
    if ( rc )
    {
        uint32_t status;

        printk(XENLOG_ERR
               "sev-snp: Unable to reclaim guest context page (%d, %u)\n",
               rc, psp_ret);

        /* See comment in snp_reclaim_firmware_page(). */
        offline_page(page_to_mfn(pg), true, &status);
    }

    /* Then, we need to reclaim the firmware page. */
    return snp_reclaim_immutable_page(pg);
}

static int snp_domain_initialise(struct domain *d)
{
    struct sev_data_snp_launch_start sd_ls = { 0 };
    struct sev_data_snp_activate sd_a = { 0 };
    struct snp_guest_context gctx_cmd = { 0 };
    struct rmp_entry rmp = { 0 };
    unsigned int psp_ret = 0;
    int rc = 0;
    struct page_info *gctx_page;
    struct sev_state *sev = &d->arch.hvm.svm.sev;

    if ( !opt_sev_snp )
    {
        printk(XENLOG_ERR "sev-snp: SEV-SNP is not supported\n");
        return -ENOSYS;
    }

    gctx_page = alloc_domheap_page(d, MEMF_no_refcount);
    if ( !gctx_page )
    {
        printk(XENLOG_ERR "Unable to allocate guest context page\n");
        return -ENOMEM;
    }

    /* Firmware-owned RMP entry. */
    rmp = (struct rmp_entry){
        .asid = 0,
        .assigned = 1,
        .immutable = 1
    };

    rc = rmpupdate(gctx_page, &rmp);

    if ( rc )
    {
        printk(XENLOG_ERR
               "sev-snp: Unable to assign guest context page to firmware (%d)\n",
               rc);
        free_domheap_page(gctx_page);
        return rc;
    }

    gctx_cmd.gctx_paddr = page_to_maddr(gctx_page);

    rc = sev_do_cmd(SEV_CMD_SNP_GCTX_CREATE, &gctx_cmd, &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to SNP_GCTX_CREATE domain(%d): psp_ret %u\n",
                d->domain_id, psp_ret);
        snp_reclaim_immutable_page(gctx_page);
        free_domheap_page(gctx_page);
        return rc;
    }

    sd_ls.gctx_paddr = page_to_maddr(gctx_page);
    sd_ls.policy = sev->snp.policy.raw;

    rc = sev_do_cmd(SEV_CMD_SNP_LAUNCH_START, &sd_ls, &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to SNP_LAUNCH_START domain(%d): psp_ret %u\n",
                d->domain_id, psp_ret);
        snp_decommision_gctx(gctx_page);
        free_domheap_page(gctx_page);
        return rc;
    }

    sd_a.gctx_paddr = page_to_maddr(gctx_page);
    sd_a.asid = d->arch.hvm.asid.asid;

    rc = sev_do_cmd(SEV_CMD_SNP_ACTIVATE, &sd_a, &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to SNP_ACTIVATE domain(%d): psp_ret %u\n",
                d->domain_id, psp_ret);
        snp_decommision_gctx(gctx_page);
        free_domheap_page(gctx_page);
        return rc;
    }

    sev->snp.gctx_page = gctx_page;
    return 0;
}

static int snp_domain_prepare_initial_mem(struct domain *d, gfn_t gfn, size_t count)
{
    int rc = 0;
    unsigned int psp_ret = 0;
    p2m_type_t t;
    mfn_t mfn;
    struct page_info *pg;
    struct sev_data_snp_launch_update sd_lu;
    struct rmp_entry rmp;

    flush_all(FLUSH_CACHE_WRITEBACK);

    while ( count )
    {
        mfn = get_gfn_unshare(d, gfn_x(gfn), &t);

        if ( !p2m_is_ram(t) )
        {
            rc = -EINVAL;
            put_gfn(d, gfn_x(gfn));
            break;
        }

        pg = mfn_to_page(mfn);

        /*
         * We need to be a bit careful here as SNP_LAUNCH_UPDATE requires the page to be
         * immutable. That prevents us from recovering by just doing RMPUPDATE on page
         * to bring it back into being hypervisor owned; we also have to first ask the
         * PSP to unlock it with SNP_PAGE_RECLAIM.
         */
        rmp = (struct rmp_entry){
            .gpa = gfn_to_gaddr(gfn),
            .assigned = 1,
            .page_size = 0,
            .immutable = 1,
            .asid = d->arch.hvm.asid.asid
        };

        rc = rmpupdate(pg, &rmp);
        if ( rc )
        {
            put_gfn(d, gfn_x(gfn));
            break;
        }

        memset(&sd_lu, 0, sizeof(sd_lu));

        sd_lu.gctx_paddr = page_to_maddr(d->arch.hvm.svm.sev.snp.gctx_page);
        sd_lu.page_size = 0;
        sd_lu.page_type = SNP_PAGE_TYPE_NORMAL;
        sd_lu.address = mfn_to_maddr(mfn);

        rc = sev_do_cmd(SEV_CMD_SNP_LAUNCH_UPDATE, &sd_lu, &psp_ret, true);
        if ( rc )
        {
            printk(XENLOG_ERR "asp: failed to SNP_LAUNCH_UPDATE dom(%hu): err %u\n",
                   d->domain_id, psp_ret);
            snp_reclaim_immutable_page(pg);
            put_gfn(d, gfn_x(gfn));
            return rc;
        }
        pg->count_info |= PGC_coco_restrict;

        gfn = gfn_add(gfn, 1);
        count--;
    }

    return rc;
}

static int snp_domain_creation_finished(struct domain *d)
{
    int rc = 0;
    unsigned int psp_ret;
    struct sev_data_snp_launch_finish sd_lf = { 0 };
    struct sev_state *sev = &d->arch.hvm.svm.sev;
    struct rmp_entry rmp;
    struct vcpu *v;

    for_each_vcpu ( d, v )
    {
        int rc;
        unsigned int psp_ret;
        struct sev_data_snp_launch_update sd_lu = { 0 };
        struct page_info *vmsa_page;
        gfn_t vmsa_gfn = gfn_add(_gfn(XEN_SNP_INIT_VMSA_GFN_START), v->vcpu_id);

        if ( !v->is_initialised )
            continue;
        
        vmsa_page = alloc_domheap_page(d, MEMF_no_owner);
        if ( !vmsa_page )
            return -ENOMEM;

        v->arch.hvm.svm.sev.vmpl[0].vmsa_page = vmsa_page;

        rc = sev_es_build_vmsa(v, vmsa_page);
        if ( rc )
        {
            printk(XENLOG_ERR
                   "sev-snp: Unable to build d%huv%d VMSA: rc = %d\n",
                   d->domain_id, v->vcpu_id, rc);
            return rc;
        }

        /* See snp_domain_prepare_initial_mem comment regarding mutability aspect. */
        rmp = (struct rmp_entry){
            .asid = d->arch.hvm.asid.asid,
            .assigned = 1,
            .gpa = gfn_to_gaddr(vmsa_gfn),
            .immutable = 1,
        };

        rc = rmpupdate(vmsa_page, &rmp);
        if ( rc )
        {
            printk(XENLOG_ERR
                   "sev-snp: Unable to assign vmsa page to guest (%d)\n", rc);
            return rc;
        }

        vmsa_page->count_info |= PGC_coco_restrict;

        sd_lu.address = page_to_maddr(vmsa_page);
        sd_lu.gctx_paddr = page_to_maddr(sev->snp.gctx_page);
        sd_lu.page_type = SNP_PAGE_TYPE_VMSA;

        rc = sev_do_cmd(SEV_CMD_SNP_LAUNCH_UPDATE, &sd_lu, &psp_ret, true);
        if ( rc )
        {
            printk(XENLOG_ERR
                   "asp: failed to SNP_LAUNCH_UPDATE(VMSA) d%huv%d: err %u\n",
                   d->domain_id, v->vcpu_id, psp_ret);
            snp_reclaim_immutable_page(vmsa_page);
            return rc;
        }

        /*
         * The RMP entry of the VMSA requires the VMSA to exist inside the
         * guest at a specific GPA. 
         */
        rc = p2m_add_page(d, vmsa_gfn, page_to_mfn(vmsa_page), 0, p2m_ram_rw);
        if ( rc )
        {
            printk(XENLOG_ERR
                   "sev-snp: Unable to install d%dv%d VMSA page at %"PRI_gfn" (%d)\n",
                   d->domain_id, v->vcpu_id, gfn_x(vmsa_gfn), rc);
            return rc;
        }
    }

    sd_lf.gctx_paddr = page_to_maddr(sev->snp.gctx_page);

    rc = sev_do_cmd(SEV_CMD_SNP_LAUNCH_FINISH, &sd_lf, &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR
               "asp: failed to SNP_LAUNCH_FINISH for d%hu: psp_ret %u, rc %d\n",
               d->domain_id, psp_ret, rc);
        return rc;
    }

    return 0;
}

static int snp_domain_teardown(struct domain *d)
{
    int rc = 0;
    
    rc = sev_es_domain_teardown(d);
    if ( rc )
        return rc;

    /* TODO */

    return 0;
}

static void snp_domain_destroy(struct domain *d)
{
    struct sev_state *sev = &d->arch.hvm.svm.sev;
    unsigned int psp_ret = 0;
    int rc = 0;

    snp_decommision_gctx(sev->snp.gctx_page);

    /**
     * SEV-SNP API Specification, 8.13 SNP_DF_FLUSH
     *
     * This command flushes SoC data buffers after CPU caches have been invalidated.
     * After a VM is decommissioned or exported, the hypervisor must execute a WBINVD on
     * the cores that the previous guest was active on before invoking the SNP_DF_FLUSH
     * command. The combination of WBINVD and SNP_DF_FLUSH ensures that all data
     * associated with the previous guest are no longer in any CPU caches.
     */
    flush_all(FLUSH_CACHE_EVICT);

    rc = sev_do_cmd(SEV_CMD_SNP_DF_FLUSH, NULL, &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to SNP_DF_FLUSH for d%hu: psp_ret %u\n",
               d->domain_id, psp_ret);
        return;
    }

    FREE_DOMHEAP_PAGE(sev->snp.gctx_page);
}

static struct coco_domain_ops snp_domain_ops = {
    .domain_initialise = snp_domain_initialise,
    .domain_creation_finished = snp_domain_creation_finished,
    .domain_teardown = snp_domain_teardown,
    .domain_destroy = snp_domain_destroy,
    .show_execution_state = sev_vmsa_dump,
    .asid_alloc = sev_es_asid_alloc, /* TODO: Ciphertext-aware ASID partitioning */
    .prepare_initial_mem = snp_domain_prepare_initial_mem,
};

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

    ASSERT(host_cpu_policy.extd.c_bit_pos > 0);
    ASSERT(host_cpu_policy.extd.max_sev_guests > 0);

    printk(XENLOG_INFO "sev: C-bit is %"PRIu32"\n", host_cpu_policy.extd.c_bit_pos);
    printk(XENLOG_INFO "sev: Supports up to %"PRIu32" SEV guests\n",
            host_cpu_policy.extd.max_sev_guests - host_cpu_policy.extd.min_no_es_asid);

    if ( cpu_has_sev_es )
        printk(XENLOG_INFO "sev-es: Supports up to %"PRIu32" SEV-ES guests\n",
               host_cpu_policy.extd.min_no_es_asid - 1);

    /* Make non-SEV ASIDs allocated above max_sev_guests if possible. */
    if ( asid_default_min < host_cpu_policy.extd.max_sev_guests )
        asid_default_min = host_cpu_policy.extd.max_sev_guests;

    if ( opt_sev_snp && !cpu_has_sev_snp )
    {
        printk(XENLOG_WARNING "sev-snp: CPU doesn't support SEV-SNP\n");
        opt_sev_snp = false;
    }

    return 0;
}

static int sev_get_platform_status(struct coco_platform_status *status)
{
    int rc = 0;
    unsigned int psp_ret = 0;
    struct sev_user_data_status platform_status = { 0 };

    status->platform = COCO_PLATFORM_amd_sev;

    if ( cpu_has_sev_es )
        status->platform_flags |= COCO_PLATFORM_FLAG_sev_es;

    if ( opt_sev_snp )
    {
        rc = sev_do_cmd(SEV_CMD_SNP_PLATFORM_STATUS, &snp_platform_status, &psp_ret, true);

        if ( !rc )
        {
            status->flags = COCO_STATUS_FLAG_supported;
            status->platform_flags |= COCO_PLATFORM_FLAG_sev_snp;

            status->version_major = snp_platform_status.api_major;
            status->version_minor = snp_platform_status.api_minor;
            status->version_build = snp_platform_status.build_id;
        }
        else
        {
            printk(XENLOG_ERR
                   "sev-snp: Unable to get SNP platform status (%d, %u)\n",
                   rc, psp_ret);
            
            opt_sev_snp = false;
            return 0;
        }
    }
    
    if ( !opt_sev_snp )
    {
        /* Use legacy (SEV/SEV-ES) interface. */
        rc = sev_do_cmd(SEV_CMD_PLATFORM_STATUS, &platform_status, &psp_ret, true);

        if ( !rc )
        {
            status->flags = COCO_STATUS_FLAG_supported;

            status->version_major = platform_status.api_major;
            status->version_minor = platform_status.api_minor;
            status->version_build = platform_status.build;
        }
        else
        {
            printk(XENLOG_ERR
                    "sev: Unable to get platform status (%d, %u)\n",
                    rc, psp_ret);
        }
    }

    return rc;
}

static struct coco_domain_ops *sev_get_domain_ops(struct domain *d,
    const struct xen_domctl_createdomain *config)
{
    union sev_guest_policy *sev_policy;
    union snp_guest_policy *snp_policy;
    
    if ( config->arch.coco.sev.flags & XEN_X86_SEV_SNP )
    {
        snp_policy = &d->arch.hvm.svm.sev.snp.policy;

        if ( config->arch.coco.sev.flags & XEN_X86_SEV_POLICY_VALID )
            snp_policy->raw = config->arch.coco.sev.policy;
        else
            /* Use a reasonable default policy */
            *snp_policy = (union snp_guest_policy){
                .no_page_swap = true, /* Unused in Xen */
                .smt = true,
                .rsvd_one = 1,
            };

        return &snp_domain_ops;
    }
    
    /* We need to set a valid policy for the initialization. */
    sev_policy = &d->arch.hvm.svm.sev.legacy.policy;

    if ( config->arch.coco.sev.flags & XEN_X86_SEV_POLICY_VALID )
        sev_policy->raw = (uint32_t)config->arch.coco.sev.policy;
    else
        /* Use a reasonable default policy */
        *sev_policy = (union sev_guest_policy){
            .no_key_sharing = true,
            .no_debug = true,
            .no_send = true, /* To review when SEV live migration is something */
            .es = cpu_has_sev_es, /* Use SEV-ES if available */
        };

    return sev_policy->es ? &sev_es_domain_ops : &sev_domain_ops;
}

struct coco_ops sev_coco_ops = {
    .name = "SEV",
    .init = sev_init,
    .init_late = sev_init_late,
    .get_platform_status = sev_get_platform_status,
    .get_domain_ops = sev_get_domain_ops,
};

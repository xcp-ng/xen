/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * coco/sev.c: AMD SEV support
 * Copyright (c) Vates SAS
 */

#include <xen/coco.h>
#include <xen/config.h>
#include <xen/errno.h>
#include <xen/mm.h>

#include <asm/cpu-policy.h>
#include <asm/cpufeature.h>
#include <asm/flushtlb.h>
#include <asm/p2m.h>
#include <asm/psp-sev.h>
#include <asm/hvm/asid.h>
#include <asm/hvm/svm/sev_es.h>
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

    d->arch.hvm.svm.sev.asp_handle = sd_ls.handle;
    return 0;
}

static int sev_domain_prepare_initial_mem(struct domain *d, gfn_t gfn, size_t count)
{
    int rc = 0;
    unsigned int psp_ret = 0;
    struct sev_data_launch_update_data sd_lud;
    p2m_type_t t;

    mfn_t mfn = INVALID_MFN, mfn_base = INVALID_MFN;
    size_t segment_size = 0;

    flush_all(FLUSH_CACHE_WRITEBACK);

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

        put_gfn(d, gfn_x(gfn));
        gfn = gfn_add(gfn, 1);
        segment_size++;
        count--;
    } while ( count );

    /* Last launch update data. */
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

static int sev_domain_creation_finished(struct domain *d)
{
    struct sev_data_launch_measure sd_lm;
    struct sev_data_launch_finish sd_lf;
    unsigned int psp_ret;
    long rc = 0;

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

    sd_lf.handle = d->arch.hvm.svm.sev.asp_handle;

    rc = sev_do_cmd(SEV_CMD_LAUNCH_FINISH, (void *)(&sd_lf), &psp_ret, true);
    if ( rc )
    {
        printk(XENLOG_ERR "asp: failed to LAUNCH_FINISH for d%hu: psp_ret %u, rc %ld\n",
                d->domain_id, psp_ret, rc);
        return rc;
    }

    d->arch.hvm.svm.sev.measure_len = sd_lm.len;
    return 0;
}

static int sev_domain_teardown(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu( d, v )
    {
        struct sev_vcpu *sev_v = &v->arch.hvm.svm.sev;

        if ( sev_v->ghcb_page )
        {
            UNMAP_DOMAIN_PAGE(sev_v->ghcb_map);
            put_page(sev_v->ghcb_page);
            sev_v->ghcb_page = NULL;
            sev_v->ghcb_gfn = 0;
        }
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

    sd_da.handle = sev->asp_handle;

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

    sd_de.handle = sev->asp_handle;

    rc = sev_do_cmd(SEV_CMD_DECOMMISSION, (void *)(&sd_de), &psp_ret, true);
    if (rc)
    {
        printk(XENLOG_ERR "asp: failed to DECOMMISSION for d%hu: psp_ret %u\n",
               d->domain_id, psp_ret);
        return;
    }

    sev->asp_handle = 0;
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
    .domain_teardown = sev_domain_teardown,
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
    sd_luv.handle = d->arch.hvm.svm.sev.asp_handle;
    sd_luv.reserved = 0;

    for_each_vcpu ( d, v )
    {
        int rc;
        unsigned int psp_ret;

        rc = sev_es_build_vmsa(v);
        if ( rc )
        {
            printk(XENLOG_ERR "Unable to build d%huv%d VMSA: rc = %d\n",
                   d->domain_id, v->vcpu_id, rc);
            return rc;
        }

        sd_luv.address = page_to_maddr(v->arch.hvm.svm.sev.vmsa_page);
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
    .domain_destroy = sev_domain_destroy,
    .asid_alloc = sev_es_asid_alloc,
    .show_execution_state = sev_vmsa_dump,
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

    return rc;
}

static struct coco_domain_ops *sev_get_domain_ops(struct domain *d,
    const struct xen_domctl_createdomain *config)
{
    /* We need to set a valid policy for the initialization. */
    union sev_guest_policy *sev_policy = &d->arch.hvm.svm.sev.asp_policy;

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
    .get_platform_status = sev_get_platform_status,
    .get_domain_ops = sev_get_domain_ops,
};

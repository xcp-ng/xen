/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * General confidential computing functions.
 */

#include "asm/psp-sev.h"
#include "xen/config.h"
#include "xen/lib.h"
#include <xen/coco.h>
#include <xen/errno.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/sched.h>
#include <xen/sections.h>
#include <xen/types.h>

#include <asm/p2m.h>

#include <public/hvm/coco.h>

static __ro_after_init struct coco_ops *coco_ops;
__read_mostly struct coco_platform_status platform_status;

void __init coco_register_ops(struct coco_ops *ops)
{
    coco_ops = ops;
}

int __init coco_init(void)
{
    int rc = 0;

    if ( coco_ops )
        printk("coco: Using '%s'\n", coco_ops->name);
    else
    {
        printk("coco: No platform found\n");
        return 0;
    }

    if ( coco_ops->init )
    {
        rc = coco_ops->init();

        if ( rc )
        {
            printk("coco: Unable to initialize coco platform (%d)", rc);
            goto err;
        }
    }

    rc = coco_ops->get_platform_status(&platform_status);
    if ( rc )
    {
        printk("coco: Unable to get platform status\n");
        goto err;
    }

    return 0;

err:
    /* Disable confidential computing if initialization failed. */
    coco_ops = NULL;
    return rc;
}

void coco_set_domain_ops(struct domain *d)
{
    ASSERT(is_coco_domain(d));

    d->coco_ops = coco_ops->get_domain_ops(d);
}

int coco_prepare_initial_memory(struct domain *d, gfn_t gfn, size_t page_count)
{
    /* TODO: Check prepare_initial_memory constraints (no dangling mapping). */

    if ( d->coco_ops->prepare_initial_mem )
        return d->coco_ops->prepare_initial_mem(d, gfn, page_count);

    return 0;
}

long coco_op_prepare_initial_mem(struct coco_prepare_initial_mem arg)
{
    long rc = 0;
    struct domain *d = get_domain_by_id(arg.domid);

    if ( !d )
        return -ENOENT;

    if ( !is_coco_domain(d) )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    rc = coco_prepare_initial_memory(d, _gfn(arg.gfn), arg.count);

out:
    put_domain(d);
    return rc;
}

static long coco_op_get_attestation_report(coco_attestation_report_t *report) {
    struct domain *d;
    int rc;

    d = get_domain_by_id(report->domid);

    if (!d)
        return -ENOENT;

    if (!is_coco_domain(d))
        return -EOPNOTSUPP;

    if (!d->coco_ops || !d->coco_ops->domain_attestation_report)
        return -EOPNOTSUPP;

    rc = d->coco_ops->domain_attestation_report(d, report);

    return rc;
}

static long coco_op_get_certificate(coco_platform_certs_t *certs) {
    int rc;
    int psp_ret = 0;
    struct sev_data_pdh_cert_export pdh_cert_export;

    certs->status = platform_status;
    certs->cpu_number = nr_sockets;
    printk(XENLOG_DEBUG "version: major = %d, minor %d\n", platform_status.version_major, platform_status.version_minor);
    
    if (platform_status.version_major >= 1 || platform_status.version_minor >= 15) {
        // get id
        struct sev_data_get_id get_id;
        get_id.address = (uint64_t) virt_to_maddr(&certs->hwid);
        get_id.len = sizeof(certs->hwid); // size of AMD-SEV attestation

        rc = sev_do_cmd(SEV_CMD_GET_ID, (void *)(&get_id),
            &psp_ret, true);
        printk(XENLOG_DEBUG "get_id: rc = %d, psp_ret %d\n", rc, psp_ret);
    }

    pdh_cert_export.cert_chain_address = (uint64_t) virt_to_maddr(&certs->sev.phd_cert);
    pdh_cert_export.pdh_cert_address = (uint64_t) virt_to_maddr(&certs->sev.phd_cert_chain);
    pdh_cert_export.cert_chain_len = sizeof(struct sev_certificate);
    pdh_cert_export.pdh_cert_len = sizeof(struct sev_certificate);
    pdh_cert_export.reserved = 0;
    
    rc = sev_do_cmd(SEV_CMD_PDH_CERT_EXPORT, (void *)(&pdh_cert_export),
            &psp_ret, true);
    
    printk(XENLOG_DEBUG "PDH_CERT_EXPORT: rc = %d, psp_ret %d\n", rc, psp_ret);

    for (size_t i = 0; i < 128 - 1; i++) {
		printk("%02X", certs->hwid[i]);
	}
	printk("%02X\n", certs->hwid[127]);
    // note : get_id is irrelevant for rome processor : 
    // https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/57230.pdf
    printk(XENLOG_DEBUG "%s: rc = %d, psp_ret %d\n", __func__, rc, psp_ret);
	/* SEV GET_ID is available from SEV API v0.16 and up */
	// if (!sev_version_greater_or_equal(0, 16))
	// 	return -ENOTSUPP;
    return rc;
}


long do_coco_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    if ( !is_hardware_domain(current->domain) )
        return -EPERM;

    switch (cmd)
    {
        case XEN_COCO_platform_status:
        {
            if ( copy_to_guest(arg, &platform_status, 1) )
                return -EFAULT;

            return 0;
        }

        case XEN_COCO_prepare_initial_mem:
        {
            struct coco_prepare_initial_mem prepare_initial_mem;

            if ( copy_from_guest(&prepare_initial_mem, arg, 1) )
                return -EFAULT;

            return coco_op_prepare_initial_mem(prepare_initial_mem);
        }
        case XEN_COCO_attestation_report:
        {
            coco_attestation_report_t report;
            int rc = 0;

            if ( copy_from_guest(&report, arg, 1) )
                return -EFAULT;

            rc = coco_op_get_attestation_report(&report);
            if (rc)
                return rc;

            if (copy_to_guest(arg, &report, 1))
                return -EFAULT;

            return 0;
        }
        case XEN_COCO_platform_certs:
        {
            coco_platform_certs_t certs;
            int rc = 0;

            if ( copy_from_guest(&certs, arg, 1) )
                return -EFAULT;

            rc = coco_op_get_certificate(&certs);
            return rc;
        }

        default:
            return -ENOSYS;
    }
}

long do_sev_console_op(unsigned long c)
{
    printk("%c", (unsigned char)c);
    return 0;
}

__initcall(coco_init);

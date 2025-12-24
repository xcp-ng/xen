/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * General confidential computing functions.
 */

#include "xen/config.h"
#include "xen/lib.h"
#include "xen/xmalloc.h"
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

#include <public/domctl.h>
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

void coco_set_domain_ops(struct domain *d, const struct xen_domctl_createdomain *config)
{
    ASSERT(is_coco_domain(d));

    d->coco_ops = coco_ops->get_domain_ops(d, config);
}

int coco_prepare_initial_memory(struct domain *d, gfn_t gfn, size_t page_count)
{
    /* TODO: Check prepare_initial_memory constraints (no dangling mapping). */

    if ( d->coco_ops->prepare_initial_mem )
        return d->coco_ops->prepare_initial_mem(d, gfn, page_count);
    
    return 0;
}

long coco_op_prepare_initial_mem(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct coco_prepare_initial_mem prepare_initial_mem;
    struct domain *d;
    long rc = 0;

    if ( copy_from_guest(&prepare_initial_mem, arg, 1) )
        return -EFAULT;
    
    d = get_domain_by_id(prepare_initial_mem.domid);
    if (!d)
        return -ENOENT;
    if (!is_coco_domain(d))
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    rc = coco_prepare_initial_memory(d, _gfn(prepare_initial_mem.gfn), prepare_initial_mem.count);

out:
    put_domain(d);
    return rc;
}

long coco_op_finish_initial_mem(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct domain *d;
    domid_t domid;
    long rc = 0;
    
    if ( copy_from_guest(&domid, arg, 1) )
        return -EFAULT;

    d = get_domain_by_id(domid);
    if (!d)
        return -ENOENT;
    if (!is_coco_domain(d))
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    rc = coco_domain_vcpu_initialise(d);
    if (rc)
        goto out;
    rc = coco_domain_memory_finished(d);

out:
    put_domain(d);
    return rc;
}

static long coco_op_get_attestation_report(XEN_GUEST_HANDLE_PARAM(void) arg) {
    coco_attestation_report_t report;
    struct domain *d;
    int rc;

    if ( copy_from_guest(&report, arg, 1) )
        return -EFAULT;
    
    d = get_domain_by_id(report.domid);
    if (!d)
        return -ENOENT;
    if (!is_coco_domain(d))
        return -EOPNOTSUPP;
    if (!d->coco_ops || !d->coco_ops->domain_attestation_report)
        return -EOPNOTSUPP;

    rc = d->coco_ops->domain_attestation_report(d, &report);

    if (!rc && copy_to_guest(arg, &report, 1))
        return -EFAULT;
    
    return rc;
}

static long coco_op_update_secret(XEN_GUEST_HANDLE_PARAM(void) arg) {
    coco_domain_secret_t cmd;
    struct domain *d;
    int rc;
            
    if ( copy_from_guest(&cmd, arg, 1) )
        return -EFAULT;

    d = get_domain_by_id(cmd.domid);
    if (!d)
        return -ENOENT;
    if (!is_coco_domain(d))
        return -EOPNOTSUPP;
    if (!d->coco_ops || !d->coco_ops->domain_update_secret)
        return -EOPNOTSUPP;

    rc = d->coco_ops->domain_update_secret(d, &cmd);

    return rc;
}

static long coco_op_certs(XEN_GUEST_HANDLE_PARAM(void) arg) {
    coco_platform_certs_t *certs = xmalloc(coco_platform_certs_t);
    int rc = 0;

    if (!certs){
        printk(XENLOG_ERR"%s: could not malloc\n", __func__);
        return -ENOSPC;
    }
    
    if ( copy_from_guest(certs, arg, 1) )
        return -EFAULT;
    
    if (!coco_ops || !coco_ops->get_platform_certs) {
        return -EOPNOTSUPP;
    }
    
    rc = coco_ops->get_platform_certs(certs);
    
    if (!rc && copy_to_guest(arg, certs, 1))
        return -EFAULT;
    
    xfree(certs);
    return rc;
}

static long coco_op_csr(XEN_GUEST_HANDLE_PARAM(void) arg) {
    coco_certificate_t cert;
    int rc;

    if ( copy_from_guest(&cert, arg, 1) )
        return -EFAULT;
            
    if (!coco_ops || !coco_ops->get_certificate_signing_request)
        return -EOPNOTSUPP;
    
    rc = coco_ops->get_certificate_signing_request(&cert);
    
    if (!rc && copy_to_guest(arg, &cert, 1))
        return -EFAULT;

    return rc;
}

static long coco_op_regen_platform_cert(XEN_GUEST_HANDLE_PARAM(void) arg) {
    coco_certificate_name_t cert;

    if ( copy_from_guest(&cert, arg, 1) )
        return -EFAULT;
    
    if (!coco_ops || !coco_ops->regen_platform_cert)
        return -EOPNOTSUPP;
    
    return coco_ops->regen_platform_cert(&cert);
}

static long coco_op_import_certificate(XEN_GUEST_HANDLE_PARAM(void) arg) {
    coco_platform_import_certs_t cert;

    if ( copy_from_guest(&cert, arg, 1) )
        return -EFAULT;
    
    if (!coco_ops || !coco_ops->import_certificates)
        return -EOPNOTSUPP;
    
    return coco_ops->import_certificates(&cert);
}

static long coco_op_update(XEN_GUEST_HANDLE_PARAM(void) arg) {
    coco_update_t update;
    
    if ( copy_from_guest(&update, arg, 1) )
        return -EFAULT;
    if (!coco_ops || !coco_ops->update_platform)
        return -EOPNOTSUPP;

    return coco_ops->update_platform(&update);
}

static long coco_op_set_secrets_area(XEN_GUEST_HANDLE_PARAM(void) arg) {
    coco_domain_secret_area_t secret_area;
    struct domain *d;
    
    if ( copy_from_guest(&secret_area, arg, 1) )
        return -EFAULT;
    d = get_domain_by_id(secret_area.domid);
    if (!d)
        return -ENOENT;
    if (!is_coco_domain(d))
        return -EOPNOTSUPP;
    if (!d->coco_ops || !d->coco_ops->domain_set_secret_area)
        return -EOPNOTSUPP;

    return d->coco_ops->domain_set_secret_area(d, &secret_area);
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
        case XEN_COCO_domain_prepare_initial_mem:
            return coco_op_prepare_initial_mem(arg);
        case XEN_COCO_domain_finish_initial_mem:
            return coco_op_finish_initial_mem(arg);
        case XEN_COCO_domain_attestation_report:
            return coco_op_get_attestation_report(arg);
        case XEN_COCO_platform_get_certificates:
            return coco_op_certs(arg);
        case XEN_COCO_platform_get_certificate_signing_request:
            return coco_op_csr(arg);
        case XEN_COCO_platform_regenerate_certificate:
            return coco_op_regen_platform_cert(arg);
        case XEN_COCO_platform_import_certificate:
            return coco_op_import_certificate(arg);
        case XEN_COCO_platform_update:
            return coco_op_update(arg);
        case XEN_COCO_domain_update_secrets:
            return coco_op_update_secret(arg);
        case XEN_COCO_domain_set_secrets_area:
            return coco_op_set_secrets_area(arg);
        
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

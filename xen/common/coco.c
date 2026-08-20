/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * General confidential computing functions.
 */
 
#include <xen/coco.h>
#include <xen/errno.h>
#include <xen/domain.h>
#include <xen/domain_page.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/sched.h>
#include <xen/sections.h>
#include <xen/types.h>
#include <xsm/xsm.h>

#include <asm/p2m.h>

#include <public/domctl.h>
#include <public/hvm/coco.h>

static __ro_after_init struct coco_ops *coco_ops;
__read_mostly struct coco_platform_status coco_platform_status;

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

    return 0;

err:
    /* Disable confidential computing if initialization failed. */
    coco_ops = NULL;
    return rc;
}

void coco_show_platform(void)
{
    if ( !coco_ops || !coco_platform_status.platform )
        return;

    printk("coco: CoCo platform: %s\n", coco_ops->name);
    printk("coco: Platform version: %"PRIu32".%"PRIu32".%"PRIu32"\n",
           coco_platform_status.version_major, coco_platform_status.version_minor,
           coco_platform_status.version_build);
    
    printk("coco: Platform flags:");
    switch ( coco_platform_status.platform )
    {
        case COCO_PLATFORM_amd_sev:
            if ( coco_platform_status.platform_flags & COCO_PLATFORM_FLAG_sev_es )
                printk(" SEV-ES");
            if ( coco_platform_status.platform_flags & COCO_PLATFORM_FLAG_sev_snp )
                printk(" SEV-SNP");
            if ( coco_platform_status.platform_flags & COCO_PLATFORM_FLAG_sev_tio )
                printk(" SEV-TIO");
            break;
    }
    printk("\n");

    printk("coco: Status: %s",
           coco_platform_status.flags & COCO_STATUS_FLAG_supported ? "Supported"
                                                                   : "Unsupported");

    if ( coco_platform_status.flags & COCO_STATUS_FLAG_unsafe )
        printk("coco: Platform is using a unsafe configuration\n");
}

void __init coco_init_late(void)
{
    int rc = 0;

    if ( !coco_ops )
        return;

    if ( coco_ops->init_late )
    {
        rc = coco_ops->init_late();

        if ( rc )
        {
            printk("coco: Unable to late-initialize coco platform (%d)", rc);
            goto err;
        }
    }

    ASSERT(coco_ops->get_platform_status);
    rc = coco_ops->get_platform_status(&coco_platform_status);
    if ( rc )
    {
        printk("coco: Unable to get platform status\n");
        goto err;
    }

    return;

err:
    coco_ops = NULL;
}

void coco_set_domain_ops(struct domain *d, const struct xen_domctl_createdomain *config)
{
    ASSERT(is_coco_domain(d));

    d->coco_ops = coco_ops->get_domain_ops(d, config);
}

static long coco_op_prepare_initial_mem(struct coco_prepare_initial_mem arg)
{
    long rc = 0;
    struct domain *d;
    
    rc = rcu_lock_remote_domain_by_id(arg.domid, &d);
    if ( rc )
        return rc;

    if ( xsm_coco_op(XSM_DM_PRIV, d, XEN_COCO_prepare_initial_mem) )
    {   
        rc = -EPERM;
        goto out;
    }

    if ( !is_coco_domain(d) )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    if ( d->coco_ops && d->coco_ops->prepare_initial_mem )
        rc = d->coco_ops->prepare_initial_mem(d, _gfn(arg.gfn), arg.count);

out:
    rcu_unlock_domain(d);
    return rc;
}

long do_coco_op(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    switch (cmd)
    {
        case XEN_COCO_platform_status:
        {
            if ( xsm_coco_op(XSM_DM_PRIV, NULL, cmd) )
                return -EPERM;

            if ( copy_to_guest(arg, &coco_platform_status, 1) )
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
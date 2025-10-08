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
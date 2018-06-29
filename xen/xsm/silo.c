/******************************************************************************
 * xsm/silo.c
 *
 * SILO module for XSM(Xen Security Modules)
 *
 * Copyright (c) 2018 Citrix Systems Ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xsm/xsm.h>

struct xsm_operations silo_xsm_ops;

/*
 * Check if inter-domain communication is allowed.
 * Return true when pass check.
 */
static bool silo_mode_dom_check(const struct domain *ldom,
                                const struct domain *rdom)
{
    const struct domain *cur_dom = current->domain;

    return (is_control_domain(cur_dom) || is_control_domain(ldom) ||
            is_control_domain(rdom) || ldom == rdom);
}

static int silo_evtchn_unbound(struct domain *d1, struct evtchn *chn,
                               domid_t id2)
{   
    int rc = -EPERM;
    struct domain *d2 = rcu_lock_domain_by_any_id(id2);
    
    if ( d2 == NULL )
        rc = -ESRCH;
    else 
    {
        if ( silo_mode_dom_check(d1, d2) )
            rc = dummy_xsm_ops.evtchn_unbound(d1, chn, id2);
        rcu_unlock_domain(d2);
    }

    return rc;
}

static int silo_evtchn_interdomain(struct domain *d1, struct evtchn *chan1,
                                   struct domain *d2, struct evtchn *chan2)
{
    if ( silo_mode_dom_check(d1, d2) )
        return dummy_xsm_ops.evtchn_interdomain(d1, chan1, d2, chan2);
    return -EPERM;
}

static int silo_grant_mapref(struct domain *d1, struct domain *d2,
                             uint32_t flags)
{
    if ( silo_mode_dom_check(d1, d2) )
        return dummy_xsm_ops.grant_mapref(d1, d2, flags);
    return -EPERM;
}

static int silo_grant_transfer(struct domain *d1, struct domain *d2)
{
    if ( silo_mode_dom_check(d1, d2) )
        return dummy_xsm_ops.grant_transfer(d1, d2);
    return -EPERM;
}

static int silo_grant_copy(struct domain *d1, struct domain *d2)
{
    if ( silo_mode_dom_check(d1, d2) )
        return dummy_xsm_ops.grant_copy(d1, d2);
    return -EPERM;
}

void __init silo_init(void)
{
    printk("Initialising XSM SILO mode\n");

    silo_xsm_ops = dummy_xsm_ops;

    silo_xsm_ops.evtchn_unbound = silo_evtchn_unbound;
    silo_xsm_ops.evtchn_interdomain = silo_evtchn_interdomain;
    silo_xsm_ops.grant_mapref = silo_grant_mapref;
    silo_xsm_ops.grant_transfer = silo_grant_transfer;
    silo_xsm_ops.grant_copy = silo_grant_copy;

    xsm_ops = &silo_xsm_ops;
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

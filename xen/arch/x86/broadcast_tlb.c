/**
 * broadcast_tlb.c
 *
 * Broadcast TLB flushing implementations.
 *
 * Copyright (C) 2025 Vates SAS
 */

#include <xen/errno.h>
#include <xen/param.h>
#include <xen/lib.h>
#include <xen/mm.h>
 
#include <asm/cpufeature.h>
#include <asm/alternative-call.h>
#include <asm/broadcast_tlb.h>

bool __read_mostly use_broadcast_tlb = true;
boolean_param("tlb-broadcast", use_broadcast_tlb);

static struct broadcast_tlb_ops __ro_after_init ops;

void __init broadcast_tlb_setup(void)
{
    if ( ops.name )
        printk(XENLOG_INFO "Using broadcast TLB flushing method '%s', "
               "HVM guest TLB flushing is %savailable",
               ops.name, ops.flush_tlb_hvm ? "" : "not ");
    else
        use_broadcast_tlb = false;
}

int broadcast_flush_tlb(const cpumask_t *mask, const void *va, unsigned int flags)
{
    if ( ops.flush_tlb )
        return alternative_call(ops.flush_tlb, mask, va, flags);

    return -EOPNOTSUPP;
}

int broadcast_flush_tlb_hvm(const cpumask_t *mask, struct domain *d)
{
    if ( ops.flush_tlb )
        return alternative_call(ops.flush_tlb_hvm, mask, d);

    return -EOPNOTSUPP;
}

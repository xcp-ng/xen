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
#include <asm/invlpgb.h>

bool __read_mostly use_broadcast_tlb = true;
boolean_param("broadcast-tlb", use_broadcast_tlb);

static bool __initdata opt_invlpgb = true;
boolean_param("invlpgb", opt_invlpgb);

static struct broadcast_tlb_ops __ro_after_init ops;

void __init broadcast_tlb_setup(void)
{
    if ( !use_broadcast_tlb )
        return;

    if ( opt_invlpgb && cpu_has_invlpgb )
    {
        ops.name = "invlpgb";
        ops.flush_tlb = invlpgb_flush_tlb;

        if ( cpu_has_invlpgb_np )
            ops.flush_tlb_hvm = invlpgb_flush_tlb_hvm;
    }

    if ( ops.name )
        printk(XENLOG_INFO "Using broadcast TLB flushing method '%s'\n"
               "- HVM guest TLB flushing is %savailable\n",
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

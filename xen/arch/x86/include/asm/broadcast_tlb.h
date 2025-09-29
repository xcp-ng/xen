/* SPDX-License-Identifier: GPL-2.0-only */
/******************************************************************************
 * asm-x86/broadcast_tlb.h
 *
 * Copyright (c) 2025 Vates SAS.
 */

#ifndef X86_BROADCAST_TLB_H
#define X86_BROADCAST_TLB_H

#include <xen/cpumask.h>
#include <xen/init.h>

extern bool use_broadcast_tlb;

struct broadcast_tlb_ops {
  const char *name;

  int (*flush_tlb)(const cpumask_t *mask, const void *va, unsigned int flags);
  int (*flush_tlb_hvm)(const cpumask_t *mask, struct domain *d);
};

void __init broadcast_tlb_setup(void);

int broadcast_flush_tlb(const cpumask_t *mask, const void *va, unsigned int flags);
int broadcast_flush_tlb_hvm(const cpumask_t *mask, struct domain *d);

#endif /* X86_BROADCAST_TLB_H */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * asid.h: ASID management
 * Copyright (c) 2007, Advanced Micro Devices, Inc.
 * Copyright (c) 2009, Citrix Systems, Inc.
 */

#ifndef __ASM_X86_HVM_ASID_H__
#define __ASM_X86_HVM_ASID_H__

#include <xen/stdbool.h>
#include <xen/stdint.h>

struct hvm_asid {
  uint32_t asid;
};

#ifdef CONFIG_HVM
extern bool asid_enabled;
#else
#define asid_enabled (false)
#endif

/* Initialise ASID management distributed across all CPUs. */
int hvm_asid_init(unsigned long nasids);

int hvm_asid_alloc(struct hvm_asid *asid);
int hvm_asid_alloc_range(struct hvm_asid *asid, unsigned long min, unsigned long max);
void hvm_asid_free(struct hvm_asid *asid);

#endif /* __ASM_X86_HVM_ASID_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

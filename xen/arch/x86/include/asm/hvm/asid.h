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

extern bool asid_enabled;

/* Initialise ASID management distributed across all CPUs. */
int hvm_asid_init(unsigned long nasids);

int hvm_asid_alloc(struct hvm_asid *asid);
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

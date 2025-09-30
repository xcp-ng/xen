/* SPDX-License-Identifier: GPL-2.0 */
/*
 * AMD SEV header common between the guest and the hypervisor.
 *
 * Copyright (c) 2025 - Vates SAS
 */

#ifndef X86_HVM_SVM_SEV_H
#define X86_HVM_SVM_SEV_H

#include <asm/nospec.h>
#include <asm/cpufeature.h>

#include <xen/sched.h>

static always_inline bool is_sev_domain(const struct domain *d)
{
  return cpu_has_sev && evaluate_nospec(d->options & XEN_DOMCTL_CDF_coco);
}

#endif /* X86_HVM_SVM_SEV_H */

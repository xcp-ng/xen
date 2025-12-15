/* SPDX-License-Identifier: GPL-2.0 */
#ifndef X86_HVM_SVM_SEV_H
#define X86_HVM_SVM_SEV_H

#include <asm/cpufeature.h>
#include <asm/nospec.h>
#include <asm/psp-sev.h>

#include <xen/sched.h>

static always_inline bool is_sev_domain(const struct domain *d)
{
    return IS_ENABLED(CONFIG_COCO_AMD_SEV) && cpu_has_sev &&
           evaluate_nospec(d->options & XEN_DOMCTL_CDF_coco);
}

#endif /* X86_HVM_SVM_SEV_H */

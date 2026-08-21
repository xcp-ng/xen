/* SPDX-License-Identifier: GPL-2.0 */
#ifndef X86_HVM_SVM_SEV_ES_H
#define X86_HVM_SVM_SEV_ES_H

#include <xen/config.h>
#include <xen/sched.h>

#include <asm/cpufeature.h>
#include <asm/hvm/svm/sev.h>
#include <asm/nospec.h>

#ifdef CONFIG_COCO_AMD_SEV
int sev_es_build_vmsa(struct vcpu *v, struct page_info *vmsa_page);
uint64_t sev_es_default_ghcb_msr(struct domain *d);
bool sev_vmsa_dump(struct vcpu *v);

static always_inline bool is_sev_es_domain(const struct domain *d)
{
    const struct sev_state *sev = &d->arch.hvm.svm.sev;

    return is_sev_domain(d) && cpu_has_sev_es &&
           ((cpu_has_sev_snp && sev->flags & XEN_X86_SEV_SNP) || sev->legacy.policy.es);
}
#else
static inline bool sev_vmsa_dump(struct vcpu *v) { return false; }
static inline int sev_es_build_vmsa(struct vcpu *v, struct page_info *vmsa_page)
{
    return -EOPNOTSUPP;
}
static inline uint64_t sev_es_default_ghcb_msr(struct domain *d) { return 0; }
static always_inline bool is_sev_es_domain(const struct domain *d) { return false; }
#endif

#endif /* X86_HVM_SVM_SEV_ES_H */
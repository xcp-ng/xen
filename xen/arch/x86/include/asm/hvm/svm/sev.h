#ifndef __XEN_SEV_H__
#define __XEN_SEV_H__

#include <xen/types.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <asm/cache.h>
#include <asm/nospec.h>

extern uint64_t pte_c_bit_mask;
extern unsigned int min_sev_asid;
extern unsigned int max_sev_asid;

#define PAGE_MEM_ENCRYPT_MASK  (pte_c_bit_mask)

static always_inline bool is_sev_domain(const struct domain *d)
{
    return boot_cpu_has(X86_FEATURE_SEV) &&
	evaluate_nospec(d->options & XEN_DOMCTL_CDF_coco);
}

int  sev_domain_initialize(struct domain *d);
int  sev_domain_creation_finished(struct domain *d);
void sev_domain_destroy(struct domain *d);
int  sev_vcpu_initialize(struct vcpu *v);
void sev_vcpu_destroy(struct vcpu *v);
int  sev_create_vmcb(struct vcpu *v);
void sev_destroy_vmcb(struct vcpu *v);

#endif

#ifndef __XEN_HVM_SEV_H__
#define __XEN_HVM_SEV_H__

#include <asm/nospec.h>
#include <asm/cpufeature.h>

#include <xen/sched.h>

static always_inline bool is_sev_domain(const struct domain *d)
{
  return cpu_has_sev && evaluate_nospec(d->options & XEN_DOMCTL_CDF_coco);
}

#endif /* __XEN_HVM_SEV_H__ */

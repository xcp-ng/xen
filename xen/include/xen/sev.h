#ifndef __XEN_SEV_H__
#define __XEN_SEV_H__

#include <xen/types.h>
#include <asm/cache.h>

extern uint64_t __read_mostly pte_c_bit_mask;
extern unsigned int __read_mostly min_sev_asid;
extern unsigned int __read_mostly max_sev_asid;

#endif

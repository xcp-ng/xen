/* SPDX-License-Identifier: GPL-2.0 */
#ifndef X86_HVM_SVM_SEV_SNP_H
#define X86_HVM_SVM_SEV_SNP_H

#include <xen/config.h>
#include <xen/sched.h>

#include <asm/cpufeature.h>
#include <asm/hvm/svm/sev.h>
#include <asm/hvm/svm/sev_es.h>
#include <asm/nospec.h>

/* The layout of this structure is specified in RMPUPDATE
 * instruction reference of the APM. */
struct rmp_entry {
    uint64_t gpa;
    uint8_t assigned;  /* 0/1 */
    uint8_t page_size; /* 0: 4KB, 1: 2MB */
    uint8_t immutable; /* 0/1 */
    uint8_t rsvd;
    uint32_t asid;
} __aligned(8);

#ifdef CONFIG_COCO_AMD_SEV
static always_inline bool is_sev_snp_domain(const struct domain *d)
{
    const struct sev_state *sev = &d->arch.hvm.svm.sev;

    return is_sev_es_domain(d) && cpu_has_sev_snp && (sev->flags & XEN_X86_SEV_SNP);
}

static always_inline
int rmpupdate(struct page_info *pg, struct rmp_entry *entry)
{
    unsigned int eax;

    asm volatile (".byte 0xf2, 0x0f, 0x01, 0xfe"
                  : "=a"(eax) : "a"(page_to_maddr(pg)), "c"(entry)
                  : "memory"); /* binutils >= ??? */
    
    switch (eax)
    {
    case 0:
        return 0;
    case 1: /* FAIL_INPUT */
        return -EINVAL;
    case 2: /* FAIL_PERMISSION */
        return -EPERM;
    case 3: /* FAIL_INUSE (concurrent rmpupdate) */
        return -EAGAIN;
    case 4: /* FAIL_OVERLAP */
        return -EXDEV;
    default:
        return -EIO;
    }
}
#else
static always_inline bool is_sev_snp_domain(const struct domain *d) { return false; }
static always_inline int rmpupdate(struct page_info *pg, struct rmp_entry *entry)
{
    ASSERT_UNREACHABLE();
}
#endif

#endif /* X86_HVM_SVM_SEV_SNP_H */
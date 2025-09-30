#ifndef X86_INVLPGB_H
#define X86_INVLPGB_H

#include <xen/page-defs.h>
#include <xen/cpumask.h>
#include <xen/sched.h>

#include <asm/flushtlb.h>

#define INVLPGB_RAX_VALID_VA       (1ULL << 0)
#define INVLPGB_RAX_VALID_PCID     (1ULL << 1)
#define INVLPGB_RAX_VALID_ASID     (1ULL << 2)
#define INVLPGB_RAX_INCLUDE_GLOBAL (1ULL << 3)
#define INVLPGB_RAX_FINAL_ONLY     (1ULL << 4)
#define INVLPGB_RAX_INCLUDE_NESTED (1ULL << 5)

#define INVLPGB_EDX_ASID_SHIFT (0)
#define INVLPGB_EDX_PCID_SHIFT (16)

#define INVLPGB_ECX_PAGE_SIZE_2M (1ULL << 31)

/**
 * Invalidate TLB Entry(s) with Broadcast
 * AMD APM Volume 3
 * 
 * rax
 *  - 0: Valid VA
 *  - 1: Valid PCID
 *  - 2: Valid ASID
 *  - 3: Include Global
 *  - 4: Final Translation Only
 *  - 5: Include Nested Translations
 *  - 11:6: Reserved, MBZ
 *  - 63:12 or 31:12: VA
 * ecx:
 *  - 15:0: Number of additional sequential pages to invalidate (0 being one page)
 *  - 31: If set, page size is 2M, if cleared, page size is 4K
 * edx:
 *  - 15:0: ASID
 *  - 27:16: PCID
 *  - 28:31: Reserved, MBZ
 */
static inline void invlpgb(uint64_t rax, uint32_t ecx, uint32_t edx)
{ 
    /* INVLPGB */
    asm volatile(".byte 0x0f, 0x01, 0xfe" :: "a" (rax), "c" (ecx), "d" (edx));
}

static inline void tlbsync(void)
{
    /* TLBSYNC */
    asm volatile(".byte 0x0f, 0x01, 0xff" ::: "memory");
}

static inline int invlpgb_flush_tlb(const cpumask_t *mask, const void *va, unsigned int flags)
{
    uint64_t rax = 0;
    uint32_t ecx = 0, edx = 0;

    /* We only flush for ASID = 0 */
    rax |= INVLPGB_RAX_VALID_ASID;

    if ( flags & FLUSH_TLB_GLOBAL )
        rax |= INVLPGB_RAX_INCLUDE_GLOBAL;

    if ( flags & FLUSH_VA_VALID )
    {
        unsigned int order = 1 << (flags - 1) & FLUSH_ORDER_MASK;
        rax |= INVLPGB_RAX_VALID_VA;

        if ( order >= PAGE_ORDER_2M )
        {
            /* Use 2M flushes */
            ecx = INVLPGB_ECX_PAGE_SIZE_2M | 1 << (order - PAGE_ORDER_2M);
            rax |= PAGE_MASK_2M & (uint64_t)va;
        }
        else
        {
            /* Use 4K flushes */
            ecx = 1 << order;
            rax |= PAGE_MASK_4K & (uint64_t)va;
        }
    }

    invlpgb(rax, ecx, edx);
    tlbsync();
    return 0;
}

static inline int invlpgb_flush_tlb_hvm(const cpumask_t *mask, struct domain *d)
{
    invlpgb(INVLPGB_RAX_VALID_ASID | INVLPGB_RAX_INCLUDE_GLOBAL | INVLPGB_RAX_INCLUDE_NESTED,
            0, d->arch.hvm.asid.asid);
    tlbsync();
    return 0;
}

#endif	/* X86_INVLPGB_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

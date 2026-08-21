/* SPDX-License-Identifier: MIT */
#ifndef __XEN_PUBLIC_HVM_COCO_H__
#define __XEN_PUBLIC_HVM_COCO_H__

#include "../xen.h"

#define XEN_COCO_platform_status 0

/**
 * XEN_COCO_platform_status: Get the status of confidential computing platform.
 *
 * Query informations regarding the current confidential computing platform.
 *
 * Confidential computing is supposed working as long as COCO_STATUS_FLAG_SUPPORTED bit
 * is set, and additionally security-supported only if COCO_STATUS_FLAG_UNSAFE bit
 * is cleared.
 *
 * If COCO_PLATFORM_FLAG_UNSAFE is set but COCO_PLATFORM_FLAG_SUPPORTED is not,
 * then confidential computing is explicitly present but intentionally disabled
 * or forbidden by policy.
 */
struct coco_platform_status {
#define COCO_PLATFORM_none        0 /* None */
#define COCO_PLATFORM_amd_sev     1 /* AMD Secure Encrypted Virtualization */
#define COCO_PLATFORM_intel_tdx   2 /* Intel Trust Domain Extensions */
#define COCO_PLATFORM_arm_rme     3 /* ARM Realm Management Extension */
    uint32_t platform; /* OUT */

#define COCO_PLATFORM_FLAG_sev_es  (1 << 0) /* AMD SEV Encrypted State */
#define COCO_PLATFORM_FLAG_sev_snp (1 << 1) /* AMD SEV Secure Nested Paging */
#define COCO_PLATFORM_FLAG_sev_tio (1 << 2) /* AMD SEV Trusted I/O */
    uint32_t platform_flags; /* OUT */

#define COCO_STATUS_FLAG_supported (1 << 0) /* Confidential computing is supported and usable */
#define COCO_STATUS_FLAG_unsafe    (1 << 1) /* Confidential computing is using a unsafe */
                                            /* configuration (e.g weak or debug mode) */
    uint32_t flags;    /* OUT */
    uint32_t features; /* OUT */

    uint32_t version_major; /* OUT */
    uint32_t version_minor; /* OUT */
    uint32_t version_build; /* OUT */
};
typedef struct coco_platform_status coco_platform_status_t;
DEFINE_XEN_GUEST_HANDLE(coco_platform_status_t);

#define XEN_COCO_prepare_initial_mem 1

/**
 * XEN_COCO_prepare_initial_mem: Prepare early memory pages of a guest
 *
 * During guest construction, the confidential computing platform may require memory
 * to be prepared (e.g., encrypted) before the guest is started.
 *
 * After preparation, any further access to these pages is invalid, as they may be
 * encrypted, sealed, or tracked by the platform.
 */
struct coco_prepare_initial_mem {
    domid_t domid;      /* IN */
    uint16_t _rsvd[3];  /* ZERO */
    uint64_t gfn;       /* IN */
    uint64_t count;     /* IN */
};
typedef struct coco_prepare_initial_mem coco_prepare_initial_mem_t;
DEFINE_XEN_GUEST_HANDLE(coco_prepare_initial_mem_t);

#define XEN_COCO_platform_op 2

/*
 * XEN_COCO_arch_op: Architecture specific sub-operation.
 *
 * See arch_coco_op in arch-$arch/hvm/coco.h.
 */

#endif /* __XEN_PUBLIC_HVM_COCO_H__ */

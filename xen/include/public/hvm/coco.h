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
#define COCO_STATUS_FLAG_unsafe    (1 << 1) /* Confidential computing is unsafe (e.g debug mode) */
    uint32_t flags;    /* OUT */
    uint32_t features; /* OUT */

    uint32_t version_major; /* OUT */
    uint32_t version_minor; /* OUT */
};
typedef struct coco_platform_status coco_platform_status_t;
DEFINE_XEN_GUEST_HANDLE(coco_platform_status_t);

#define XEN_COCO_prepare_initial_mem 1
#define XEN_COCO_attestation_report 2
#define XEN_COCO_platform_certs 3

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


struct sev_attestation_report_response {
	uint8_t mnonce[16];
	uint8_t launch_digest[32];
	uint32_t policy;
	uint32_t sig_usage;
	uint32_t sig_algo;
	uint32_t reserved;
	uint8_t sig[144];
}  __attribute__((packed));

/**
 * len is the size used by the attestation, it can be used to determine the attestation type
 * the union is used to make sure the struct is big enough to handle all attestation
 */
struct coco_attestation_report {
    domid_t domid;          /* IN */
	uint8_t mnonce[16];     /* IN */
	uint32_t len;           /* OUT */
    union {
        struct sev_attestation_report_response sev;
    } /* OUT */;
};
typedef struct coco_attestation_report coco_attestation_report_t;
DEFINE_XEN_GUEST_HANDLE(coco_attestation_report_t);

struct sev_certificate {
	uint32_t version;
	uint8_t api_major;
	uint8_t api_minor;
	uint8_t reserved;
	uint8_t reserved1;
	uint32_t pubkey_usage; /* should be 0x1000 */
	uint32_t pubkey_algo;  /* should be 0x0 */
	uint8_t pubkey[1028];  /*sevctl generate works */
	uint32_t sig1_usage;
	uint32_t sig1_algo;
	uint32_t reserved2;
	uint8_t sig1[512];
	uint32_t sig2_usage;
	uint32_t sig2_algo;
	uint32_t reserved3;
	uint8_t sig2[512];
};

struct sev_certificate_fullchain {
    struct sev_certificate phd_cert;
    struct sev_certificate phd_cert_chain;
};

/**
 */
struct coco_platform_certs {
    uint8_t hwid[128];          /* OUT */
    uint8_t cpu_number;          /* OUT */
    struct coco_platform_status status;          /* OUT */
    union {
        struct sev_certificate_fullchain sev;
    };
};
typedef struct coco_platform_certs coco_platform_certs_t;
DEFINE_XEN_GUEST_HANDLE(coco_platform_certs_t);


#endif /* __XEN_PUBLIC_HVM_COCO_H__ */

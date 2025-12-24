/* SPDX-License-Identifier: MIT */
#ifndef __XEN_PUBLIC_HVM_COCO_H__
#define __XEN_PUBLIC_HVM_COCO_H__

#include "../xen.h"

/* TODO : Enum ? */
#define XEN_COCO_platform_status 0
#define XEN_COCO_domain_prepare_initial_mem 1
#define XEN_COCO_domain_attestation_report 2
#define XEN_COCO_platform_get_certificates 3
#define XEN_COCO_platform_get_certificate_signing_request 4
#define XEN_COCO_platform_regenerate_certificate 5
#define XEN_COCO_platform_import_certificate 6
#define XEN_COCO_platform_update 7
#define XEN_COCO_domain_finish_initial_mem 8
#define XEN_COCO_domain_update_secrets 9
#define XEN_COCO_domain_set_secrets_area 10

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
#define COCO_STATUS_FEATURES_PLATFORM_OWNED (1 << 31) /* The owner added their certificate to the platform */
    uint32_t flags;    /* OUT */
    uint32_t features; /* OUT */

    uint32_t version_major; /* OUT */
    uint32_t version_minor; /* OUT */
    uint32_t version_build; /* OUT */
};
typedef struct coco_platform_status coco_platform_status_t;
DEFINE_XEN_GUEST_HANDLE(coco_platform_status_t);


/**
 * XEN_COCO_domain_prepare_initial_mem: Prepare early memory pages of a guest
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

/**
 * XEN_COCO_domain_attestation_report : Request an attestation report for a guest
 */
struct sev_attestation_report_response {
	uint8_t mnonce[16];
	uint8_t launch_digest[32];
	uint32_t policy;
	uint32_t sig_usage;
	uint32_t sig_algo;
	uint32_t reserved;
	uint8_t sig[144];
}  __attribute__((packed));

struct coco_attestation_report {
    domid_t domid;          /* IN */
    union {
        struct {
            uint8_t mnonce[16];     /* IN */
            struct sev_attestation_report_response rsp; /* OUT */
        } sev;
    } /* OUT */;
};
typedef struct coco_attestation_report coco_attestation_report_t;
DEFINE_XEN_GUEST_HANDLE(coco_attestation_report_t);

struct sev_session {
    uint8_t nonce[16];
    uint8_t wrap_tk[32];
    uint8_t wrap_iv[16];
    uint8_t wrap_mac[32];
    uint8_t policy_mac[32];
} __attribute__((packed));

struct sev_certificate {
	uint32_t version;
	uint8_t api_major;
	uint8_t api_minor;
	uint8_t reserved;
	uint8_t reserved1;
	uint32_t pubkey_usage;
	uint32_t pubkey_algo;
	uint8_t pubkey[1028];
	uint32_t sig1_usage;
	uint32_t sig1_algo;
	uint8_t sig1[512];
	uint32_t sig2_usage;
	uint32_t sig2_algo;
	uint8_t sig2[512];
} __attribute__((packed));

/**
 * Note : this cek is not signed by amd,
 * you need to use it with the cpuid to get the signed version from amd's server
 */
struct sev_certificate_fullchain {
    struct sev_certificate pdh;
    struct sev_certificate pek;
    struct sev_certificate oca;
    struct sev_certificate cek; 
} __attribute__((packed));

/**
 * XEN_COCO_platform_get_certificates : export the platform certificate for the guest owner
 */
struct coco_platform_certs {
    uint8_t cpu_number;          /* OUT */
    struct coco_platform_status status;          /* OUT */
    union {
        struct {
            struct sev_certificate_fullchain crt; /* OUT */
            uint8_t hwid[128];          /* OUT */
        }sev;
    };
};
typedef struct coco_platform_certs coco_platform_certs_t;
DEFINE_XEN_GUEST_HANDLE(coco_platform_certs_t);

struct coco_certificate {
    union {
        struct sev_certificate sev; /* OUT */
    };
};
typedef struct coco_certificate coco_certificate_t;
DEFINE_XEN_GUEST_HANDLE(coco_certificate_t);

/**
 * XEN_COCO_platform_update : provide the updated firmware to update the platform
 */
struct coco_update {
    union {
        struct {
            XEN_GUEST_HANDLE(void) data;
            uint32_t size;
        } sev;
    };
};
typedef struct coco_update coco_update_t;
DEFINE_XEN_GUEST_HANDLE(coco_update_t);

/** 
 * XEN_COCO_platform_import_certificate : provide the platform with the owner certificate 
 */
struct coco_platform_import_certs {
    union {
        struct {
            struct sev_certificate pek;
            struct sev_certificate oca;
        } sev;
    };
};
typedef struct coco_platform_import_certs coco_platform_import_certs_t;
DEFINE_XEN_GUEST_HANDLE(coco_platform_import_certs_t);

struct sev_launch_secret_packet_header {
	uint32_t compressed:1,
            rsvd:31;
	uint8_t iv[16];
	uint8_t mac[32];
} __attribute__((packed));

/**
 * XEN_COCO_domain_update_secrets : provide a domain the secret from the guest owner
 */
struct coco_domain_secret {
    domid_t domid;
    union {
        struct {
            struct sev_launch_secret_packet_header header;
            XEN_GUEST_HANDLE(void) secret;
            uint64_t secret_len;
            uint64_t gpa;
        } sev;
    };
};
typedef struct coco_domain_secret coco_domain_secret_t;
DEFINE_XEN_GUEST_HANDLE(coco_domain_secret_t);

struct coco_domain_secret_area {
    domid_t domid;
    uint64_t gpa;
    uint64_t size;
};
typedef struct coco_domain_secret_area coco_domain_secret_area_t;
DEFINE_XEN_GUEST_HANDLE(coco_domain_secret_area_t);

enum coco_certificate_name {
    sev_pek = 0, 
    sev_pdh, 
};
typedef enum coco_certificate_name coco_certificate_name_t;

#define COCO_CERTIFICATE_NAME_ARRAY_DEF() \
    const char *certs_name[] = { \
        [sev_pek] = "sev_pek", \
        [sev_pdh] = "sev_pdh", \
    }; \

#endif /* __XEN_PUBLIC_HVM_COCO_H__ */

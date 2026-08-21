/* SPDX-License-Identifier: MIT */
#ifndef __XEN_PUBLIC_X86_HVM_COCO_H__
#define __XEN_PUBLIC_X86_HVM_COCO_H__

#include "../../xen.h"

/*
 * First page used as a default GFN location.
 * Used per vCPU page: XEN_SNP_INIT_VMSA_GFN_START + vcpu_id
 */
#define XEN_SNP_INIT_VMSA_GFN_START 0xFFFFFFFFF

/**
 * XEN_COCO_SEV_platform_status: Get SEV-specific platform informations.
 */
#define XEN_COCO_SEV_platform_status 0x10000

struct coco_sev_platform_status {
    uint16_t max_sev_guests;
    uint16_t max_sev_es_guests;
    uint16_t max_sev_snp_guests;
    uint16_t max_vmpl;

};
typedef struct coco_sev_platform_status coco_sev_platform_status_t;

/**
 * XEN_COCO_SNP_launch_update: Prepare initial memory (SEV-SNP specific).
 *
 * This effectively performs SNP_LAUNCH_UPDATE then update the RMP table
 * accordingly. 
 */
#define XEN_COCO_SNP_launch_update 0x10001

struct coco_snp_launch_update {
    domid_t domid;      /* IN */
/* This deliberately matches PSP ABI specification. */
#define COCO_SNP_KIND_normal     1
#define COCO_SNP_KIND_vmsa       2
#define COCO_SNP_KIND_zero       3
#define COCO_SNP_KIND_unmeasured 4
#define COCO_SNP_KIND_secret     5
#define COCO_SNP_KIND_cpuid      6
    uint16_t kind;      /* IN */
    uint16_t vmpl;      /* IN */
    uint16_t pad;       /* ZERO */
    uint64_t gfn;       /* IN */
};
typedef struct coco_snp_launch_update coco_snp_launch_update_t;

/**
 * XEN_COCO_SNP_set_vcpu_vmsa: Initialize vCPU+VMPL VMSA address.
 */
#define XEN_COCO_SNP_set_vcpu_vmsa 0x10002

struct coco_snp_set_vcpu_vmsa {
    uint32_t vcpu_id;   /* IN */
    uint16_t vmpl;      /* IN */
    uint16_t flags;     /* IN */
    uint64_t gfn;       /* IN */
};
typedef struct coco_snp_set_vmsa coco_snp_set_vmsa_t;

/**
 * XEN_COCO_SNP_set_vcpu_context: Set SEV-specific vCPU context.
 */
#define XEN_COCO_SEV_set_vcpu_context 0x10003

/**
 * XEN_COCO_SNP_get_vcpu_context: Get SEV-specific vCPU context.
 */
#define XEN_COCO_SEV_get_vcpu_context 0x10004

struct coco_sev_vcpu_context {
    uint32_t vcpu_id;   /* IN */
#define COCO_SNP_set_vmpl (1 << 0)
#define COCO_SNP_set_ghcb (1 << 1)
    uint16_t flags;     /* IN(set)     / ZERO(get) */
    uint16_t vmpl;      /* IN-opt(set) / OUT(get) */
    uint64_t ghcb;      /* IN-opt(set) / OUT(get) */
};

struct arch_coco_op {
    uint32_t op;
    domid_t domid;
    uint16_t pad;

    union {
        struct coco_sev_platform_status sev_platform_status;
        struct coco_snp_launch_update snp_launch_update;
        struct coco_snp_set_vcpu_vmsa snp_set_vcpu_vmsa;
        struct coco_sev_vcpu_context snp_vcpu_context;
    } u;
};
typedef struct arch_coco_op arch_coco_op_t;

#endif /* __XEN_PUBLIC_X86_HVM_COCO_H__ */
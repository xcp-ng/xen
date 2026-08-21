/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD Secure Encrypted Virtualization (SEV) driver interface
 *
 * Copyright (C) 2016-2017 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV API spec is available at https://developer.amd.com/sev
 */

#ifndef __PSP_SEV_H__
#define __PSP_SEV_H__

#include <xen/types.h>

/**
 * SEV platform and guest management commands
 */
enum sev_cmd {
    /* platform commands */
    SEV_CMD_INIT      = 0x001,
    SEV_CMD_SHUTDOWN    = 0x002,
    SEV_CMD_FACTORY_RESET    = 0x003,
    SEV_CMD_PLATFORM_STATUS    = 0x004,
    SEV_CMD_PEK_GEN      = 0x005,
    SEV_CMD_PEK_CSR      = 0x006,
    SEV_CMD_PEK_CERT_IMPORT    = 0x007,
    SEV_CMD_PDH_CERT_EXPORT    = 0x008,
    SEV_CMD_PDH_GEN      = 0x009,
    SEV_CMD_DF_FLUSH    = 0x00A,
    SEV_CMD_DOWNLOAD_FIRMWARE  = 0x00B,
    SEV_CMD_GET_ID      = 0x00C,
    SEV_CMD_INIT_EX                 = 0x00D,

    /* Guest commands */
    SEV_CMD_DECOMMISSION    = 0x020,
    SEV_CMD_ACTIVATE    = 0x021,
    SEV_CMD_DEACTIVATE    = 0x022,
    SEV_CMD_GUEST_STATUS    = 0x023,

    /* Guest launch commands */
    SEV_CMD_LAUNCH_START    = 0x030,
    SEV_CMD_LAUNCH_UPDATE_DATA  = 0x031,
    SEV_CMD_LAUNCH_UPDATE_VMSA  = 0x032,
    SEV_CMD_LAUNCH_MEASURE    = 0x033,
    SEV_CMD_LAUNCH_UPDATE_SECRET  = 0x034,
    SEV_CMD_LAUNCH_FINISH    = 0x035,
    SEV_CMD_ATTESTATION_REPORT  = 0x036,

    /* Guest migration commands (outgoing) */
    SEV_CMD_SEND_START    = 0x040,
    SEV_CMD_SEND_UPDATE_DATA  = 0x041,
    SEV_CMD_SEND_UPDATE_VMSA  = 0x042,
    SEV_CMD_SEND_FINISH    = 0x043,
    SEV_CMD_SEND_CANCEL    = 0x044,

    /* Guest migration commands (incoming) */
    SEV_CMD_RECEIVE_START    = 0x050,
    SEV_CMD_RECEIVE_UPDATE_DATA  = 0x051,
    SEV_CMD_RECEIVE_UPDATE_VMSA  = 0x052,
    SEV_CMD_RECEIVE_FINISH    = 0x053,

    /* Guest debug commands */
    SEV_CMD_DBG_DECRYPT    = 0x060,
    SEV_CMD_DBG_ENCRYPT    = 0x061,

    /* SNP specific commands */
    SEV_CMD_SNP_INIT		= 0x081,
    SEV_CMD_SNP_SHUTDOWN		= 0x082,
    SEV_CMD_SNP_PLATFORM_STATUS	= 0x083,
    SEV_CMD_SNP_DF_FLUSH		= 0x084,
    SEV_CMD_SNP_INIT_EX		= 0x085,
    SEV_CMD_SNP_SHUTDOWN_EX		= 0x086,
    SEV_CMD_SNP_DECOMMISSION	= 0x090,
    SEV_CMD_SNP_ACTIVATE		= 0x091,
    SEV_CMD_SNP_GUEST_STATUS	= 0x092,
    SEV_CMD_SNP_GCTX_CREATE		= 0x093,
    SEV_CMD_SNP_GUEST_REQUEST	= 0x094,
    SEV_CMD_SNP_ACTIVATE_EX		= 0x095,
    SEV_CMD_SNP_LAUNCH_START	= 0x0A0,
    SEV_CMD_SNP_LAUNCH_UPDATE	= 0x0A1,
    SEV_CMD_SNP_LAUNCH_FINISH	= 0x0A2,
    SEV_CMD_SNP_DBG_DECRYPT		= 0x0B0,
    SEV_CMD_SNP_DBG_ENCRYPT		= 0x0B1,
    SEV_CMD_SNP_PAGE_SWAP_OUT	= 0x0C0,
    SEV_CMD_SNP_PAGE_SWAP_IN	= 0x0C1,
    SEV_CMD_SNP_PAGE_MOVE		= 0x0C2,
    SEV_CMD_SNP_PAGE_MD_INIT	= 0x0C3,
    SEV_CMD_SNP_PAGE_SET_STATE	= 0x0C6,
    SEV_CMD_SNP_PAGE_RECLAIM	= 0x0C7,
    SEV_CMD_SNP_PAGE_UNSMASH	= 0x0C8,
    SEV_CMD_SNP_CONFIG		= 0x0C9,
    SEV_CMD_SNP_DOWNLOAD_FIRMWARE_EX = 0x0CA,
    SEV_CMD_SNP_COMMIT		= 0x0CB,
    SEV_CMD_SNP_VLEK_LOAD		= 0x0CD,
    SEV_CMD_SNP_FEATURE_INFO	= 0x0CE,

    SEV_CMD_MAX,
};

/**
 * struct sev_data_init - INIT command parameters
 *
 * @flags: processing flags
 * @tmr_address: system physical address used for SEV-ES
 * @tmr_len: len of tmr_address
 */
struct sev_data_init {
    uint32_t flags;       /* In */
    uint32_t reserved;    /* In */
    uint64_t tmr_address; /* In */
    uint32_t tmr_len;     /* In */
} __packed;

/**
 * struct sev_data_init_ex - INIT_EX command parameters
 *
 * @length: len of the command buffer read by the PSP
 * @flags: processing flags
 * @tmr_address: system physical address used for SEV-ES
 * @tmr_len: len of tmr_address
 * @nv_address: system physical address used for PSP NV storage
 * @nv_len: len of nv_address
 */
struct sev_data_init_ex {
    uint32_t length;      /* In */
    uint32_t flags;       /* In */
    uint64_t tmr_address; /* In */
    uint32_t tmr_len;     /* In */
    uint32_t reserved;    /* In */
    uint64_t nv_address;  /* In/Out */
    uint32_t nv_len;      /* In */
} __packed;

#define SEV_INIT_FLAGS_SEV_ES  0x01

/**
 * struct sev_data_pek_csr - PEK_CSR command parameters
 *
 * @address: PEK certificate chain
 * @len: len of certificate
 */
struct sev_data_pek_csr {
    uint64_t address; /* In */
    uint32_t len;     /* In/Out */
} __packed;

/**
 * struct sev_data_cert_import - PEK_CERT_IMPORT command parameters
 *
 * @pek_address: PEK certificate chain
 * @pek_len: len of PEK certificate
 * @oca_address: OCA certificate chain
 * @oca_len: len of OCA certificate
 */
struct sev_data_pek_cert_import {
    uint64_t pek_cert_address; /* In */
    uint32_t pek_cert_len;     /* In */
    uint32_t reserved;         /* In */
    uint64_t oca_cert_address; /* In */
    uint32_t oca_cert_len;     /* In */
} __packed;

/**
 * struct sev_data_download_firmware - DOWNLOAD_FIRMWARE command parameters
 *
 * @address: physical address of firmware image
 * @len: len of the firmware image
 */
struct sev_data_download_firmware {
    uint64_t address; /* In */
    uint32_t len;     /* In */
} __packed;

/**
 * struct sev_data_get_id - GET_ID command parameters
 *
 * @address: physical address of region to place unique CPU ID(s)
 * @len: len of the region
 */
struct sev_data_get_id {
    uint64_t address; /* In */
    uint32_t len;     /* In/Out */
} __packed;
/**
 * struct sev_data_pdh_cert_export - PDH_CERT_EXPORT command parameters
 *
 * @pdh_address: PDH certificate address
 * @pdh_len: len of PDH certificate
 * @cert_chain_address: PDH certificate chain
 * @cert_chain_len: len of PDH certificate chain
 */
struct sev_data_pdh_cert_export {
    uint64_t pdh_cert_address;   /* In */
    uint32_t pdh_cert_len;       /* In/Out */
    uint32_t reserved;           /* In */
    uint64_t cert_chain_address; /* In */
    uint32_t cert_chain_len;     /* In/Out */
} __packed;

/**
 * struct sev_data_decommission - DECOMMISSION command parameters
 *
 * @handle: handle of the VM to decommission
 */
struct sev_data_decommission {
    uint32_t handle; /* In */
} __packed;

/**
 * struct sev_data_activate - ACTIVATE command parameters
 *
 * @handle: handle of the VM to activate
 * @asid: asid assigned to the VM
 */
struct sev_data_activate {
    uint32_t handle; /* In */
    uint32_t asid;   /* In */
} __packed;

/**
 * struct sev_data_deactivate - DEACTIVATE command parameters
 *
 * @handle: handle of the VM to deactivate
 */
struct sev_data_deactivate {
    uint32_t handle; /* In */
} __packed;

union sev_guest_policy {
    uint32_t raw;
    struct {
        /* Disable debugging mode (NODBG) */
        bool no_debug: 1;
        /* Disallow sharing key with other guests (NOKS) */
        bool no_key_sharing: 1;
        /* SEV-ES guest (ES) */
        bool es: 1;
        /* Disallow guest live migration (NOSEND) */
        bool no_send: 1;
        /* Check domain certificate in live migrations (DOMAIN) */
        bool check_domain_cert: 1;
        /* Check platform certificates in live migration (SEV) */
        bool check_platform_cert: 1;
        uint8_t rsvd0: 2;
        uint8_t rsvd1;
        /* Minumum API major for live migration */
        uint8_t api_major;
        /* Minimum API minor for live migration */
        uint8_t api_minor;
    };
} __packed;

union snp_guest_policy {
    uint64_t raw;
    struct {
        unsigned long rsvd: 38;
        /* Disable access to SNP_PAGE_MOVE, SNP_SWAP_OUT and SNP_SWAP_IN. */
        bool no_page_swap: 1;
        /* Require ciphertext hiding for the DRAM. */
        bool ciphertext_hiding: 1;
        /* Require RAPL from being disabled. */
        bool no_rapl: 1;
        /* Require AES-256-XTS for memory encryption. */
        bool aes_256_xts: 1;
        /* Allow CXL to be populated with devices or memory. */
        bool allow_cxl: 1;
        /* Require the guest from being activated only on one socket. */
        bool single_socket: 1;
        /* Enable debugging mode. */
        bool debug: 1;
        /* Enable support for live migration with Migration Agent. */
        bool migrate_ma: 1;
        /* Reserved, must be one. */
        bool rsvd_one: 1;
        /* Allow SMT to be enabled. */
        bool smt: 1;
        /* Minumum API major */
        uint8_t api_major;
        /* Minimum API minor */
        uint8_t api_minor;
    };
};

/**
 * struct sev_data_guest_status - SEV GUEST_STATUS command parameters
 *
 * @handle: handle of the VM to retrieve status
 * @policy: policy information for the VM
 * @asid: current ASID of the VM
 * @state: current state of the VM
 */
struct sev_data_guest_status {
    uint32_t handle; /* In */
    union sev_guest_policy policy; /* Out */
    uint32_t asid;   /* Out */
    uint8_t state;   /* Out */
} __packed;

/**
 * struct sev_data_launch_start - LAUNCH_START command parameters
 *
 * @handle: handle assigned to the VM
 * @policy: guest launch policy
 * @dh_cert_address: physical address of DH certificate blob
 * @dh_cert_len: len of DH certificate blob
 * @session_address: physical address of session parameters
 * @session_len: len of session parameters
 */
struct sev_data_launch_start {
    uint32_t handle;          /* In/Out */
    union sev_guest_policy policy; /* In */
    uint64_t dh_cert_address; /* In */
    uint32_t dh_cert_len;     /* In */
    uint32_t reserved;        /* In */
    uint64_t session_address; /* In */
    uint32_t session_len;     /* In */
} __packed;

/**
 * struct sev_data_launch_update_data - LAUNCH_UPDATE_DATA command parameter
 *
 * @handle: handle of the VM to update
 * @len: len of memory to be encrypted
 * @address: physical address of memory region to encrypt
 */
struct sev_data_launch_update_data {
    uint32_t handle;   /* In */
    uint32_t reserved;
    uint64_t address;  /* In */
    uint32_t len;      /* In */
} __packed;

/**
 * struct sev_data_launch_update_vmsa - LAUNCH_UPDATE_VMSA command
 *
 * @handle: handle of the VM
 * @address: physical address of memory region to encrypt
 * @len: len of memory region to encrypt
 */
struct sev_data_launch_update_vmsa {
    uint32_t handle;   /* In */
    uint32_t reserved;
    uint64_t address;  /* In */
    uint32_t len;      /* In */
} __packed;

/**
 * struct sev_data_launch_measure - LAUNCH_MEASURE command parameters
 *
 * @handle: handle of the VM to process
 * @address: physical address containing the measurement blob
 * @len: len of measurement blob
 */
struct sev_data_launch_measure {
    uint32_t handle;   /* In */
    uint32_t reserved;
    uint64_t address;  /* In */
    uint32_t len;      /* In/Out */
} __packed;

/**
 * struct sev_data_launch_secret - LAUNCH_SECRET command parameters
 *
 * @handle: handle of the VM to process
 * @hdr_address: physical address containing the packet header
 * @hdr_len: len of packet header
 * @guest_address: system physical address of guest memory region
 * @guest_len: len of guest_paddr
 * @trans_address: physical address of transport memory buffer
 * @trans_len: len of transport memory buffer
 */
struct sev_data_launch_secret {
    uint32_t handle;         /* In */
    uint32_t reserved1;
    uint64_t hdr_address;    /* In */
    uint32_t hdr_len;        /* In */
    uint32_t reserved2;
    uint64_t guest_address;  /* In */
    uint32_t guest_len;      /* In */
    uint32_t reserved3;
    uint64_t trans_address;  /* In */
    uint32_t trans_len;      /* In */
} __packed;

/**
 * struct sev_data_launch_finish - LAUNCH_FINISH command parameters
 *
 * @handle: handle of the VM to process
 */
struct sev_data_launch_finish {
    uint32_t handle; /* In */
} __packed;

/**
 * struct sev_data_send_start - SEND_START command parameters
 *
 * @handle: handle of the VM to process
 * @policy: policy information for the VM
 * @pdh_cert_address: physical address containing PDH certificate
 * @pdh_cert_len: len of PDH certificate
 * @plat_certs_address: physical address containing platform certificate
 * @plat_certs_len: len of platform certificate
 * @amd_certs_address: physical address containing AMD certificate
 * @amd_certs_len: len of AMD certificate
 * @session_address: physical address containing Session data
 * @session_len: len of session data
 */
struct sev_data_send_start {
    uint32_t handle;               /* In */
    union sev_guest_policy policy; /* Out */
    uint64_t pdh_cert_address;     /* In */
    uint32_t pdh_cert_len;         /* In */
    uint32_t reserved1;
    uint64_t plat_certs_address;   /* In */
    uint32_t plat_certs_len;       /* In */
    uint32_t reserved2;
    uint64_t amd_certs_address;    /* In */
    uint32_t amd_certs_len;        /* In */
    uint32_t reserved3;
    uint64_t session_address;      /* In */
    uint32_t session_len;          /* In/Out */
} __packed;

/**
 * struct sev_data_send_update - SEND_UPDATE_DATA command
 *
 * @handle: handle of the VM to process
 * @hdr_address: physical address containing packet header
 * @hdr_len: len of packet header
 * @guest_address: physical address of guest memory region to send
 * @guest_len: len of guest memory region to send
 * @trans_address: physical address of host memory region
 * @trans_len: len of host memory region
 */
struct sev_data_send_update_data {
    uint32_t handle;        /* In */
    uint32_t reserved1;
    uint64_t hdr_address;   /* In */
    uint32_t hdr_len;       /* In/Out */
    uint32_t reserved2;
    uint64_t guest_address; /* In */
    uint32_t guest_len;     /* In */
    uint32_t reserved3;
    uint64_t trans_address; /* In */
    uint32_t trans_len;     /* In */
} __packed;

/**
 * struct sev_data_send_update - SEND_UPDATE_VMSA command
 *
 * @handle: handle of the VM to process
 * @hdr_address: physical address containing packet header
 * @hdr_len: len of packet header
 * @guest_address: physical address of guest memory region to send
 * @guest_len: len of guest memory region to send
 * @trans_address: physical address of host memory region
 * @trans_len: len of host memory region
 */
struct sev_data_send_update_vmsa {
    uint32_t handle;      /* In */
    uint64_t hdr_address; /* In */
    uint32_t hdr_len;     /* In/Out */
    uint32_t reserved2;
    uint64_t guest_address; /* In */
    uint32_t guest_len;     /* In */
    uint32_t reserved3;
    uint64_t trans_address; /* In */
    uint32_t trans_len;     /* In */
} __packed;

/**
 * struct sev_data_send_finish - SEND_FINISH command parameters
 *
 * @handle: handle of the VM to process
 */
struct sev_data_send_finish {
    uint32_t handle; /* In */
} __packed;

/**
 * struct sev_data_send_cancel - SEND_CANCEL command parameters
 *
 * @handle: handle of the VM to process
 */
struct sev_data_send_cancel {
    uint32_t handle; /* In */
} __packed;

/**
 * struct sev_data_receive_start - RECEIVE_START command parameters
 *
 * @handle: handle of the VM to perform receive operation
 * @pdh_cert_address: system physical address containing PDH certificate blob
 * @pdh_cert_len: len of PDH certificate blob
 * @session_address: system physical address containing session blob
 * @session_len: len of session blob
 */
struct sev_data_receive_start {
    uint32_t handle;           /* In/Out */
    union sev_guest_policy policy; /* In */
    uint64_t pdh_cert_address; /* In */
    uint32_t pdh_cert_len;     /* In */
    uint32_t reserved1;
    uint64_t session_address; /* In */
    uint32_t session_len;     /* In */
} __packed;

/**
 * struct sev_data_receive_update_data - RECEIVE_UPDATE_DATA command parameters
 *
 * @handle: handle of the VM to update
 * @hdr_address: physical address containing packet header blob
 * @hdr_len: len of packet header
 * @guest_address: system physical address of guest memory region
 * @guest_len: len of guest memory region
 * @trans_address: system physical address of transport buffer
 * @trans_len: len of transport buffer
 */
struct sev_data_receive_update_data {
    uint32_t handle;        /* In */
    uint32_t reserved1;
    uint64_t hdr_address;   /* In */
    uint32_t hdr_len;       /* In */
    uint32_t reserved2;
    uint64_t guest_address; /* In */
    uint32_t guest_len;     /* In */
    uint32_t reserved3;
    uint64_t trans_address; /* In */
    uint32_t trans_len;     /* In */
} __packed;

/**
 * struct sev_data_receive_update_vmsa - RECEIVE_UPDATE_VMSA command parameters
 *
 * @handle: handle of the VM to update
 * @hdr_address: physical address containing packet header blob
 * @hdr_len: len of packet header
 * @guest_address: system physical address of guest memory region
 * @guest_len: len of guest memory region
 * @trans_address: system physical address of transport buffer
 * @trans_len: len of transport buffer
 */
struct sev_data_receive_update_vmsa {
    uint32_t handle;        /* In */
    uint32_t reserved1;
    uint64_t hdr_address;   /* In */
    uint32_t hdr_len;       /* In */
    uint32_t reserved2;
    uint64_t guest_address; /* In */
    uint32_t guest_len;     /* In */
    uint32_t reserved3;
    uint64_t trans_address; /* In */
    uint32_t trans_len;     /* In */
} __packed;

/**
 * struct sev_data_receive_finish - RECEIVE_FINISH command parameters
 *
 * @handle: handle of the VM to finish
 */
struct sev_data_receive_finish {
    uint32_t handle; /* In */
} __packed;

/**
 * struct sev_data_dbg - DBG_ENCRYPT/DBG_DECRYPT command parameters
 *
 * @handle: handle of the VM to perform debug operation
 * @src_addr: source address of data to operate on
 * @dst_addr: destination address of data to operate on
 * @len: len of data to operate on
 */
struct sev_data_dbg {
    uint32_t handle;   /* In */
    uint32_t reserved;
    uint64_t src_addr; /* In */
    uint64_t dst_addr; /* In */
    uint32_t len;      /* In */
} __packed;

/**
 * struct sev_data_attestation_report - SEV_ATTESTATION_REPORT command parameters
 *
 * @handle: handle of the VM
 * @mnonce: a random nonce that will be included in the report.
 * @address: physical address where the report will be copied.
 * @len: length of the physical buffer.
 */
struct sev_data_attestation_report {
    uint32_t handle;    /* In */
    uint32_t reserved;
    uint64_t address;   /* In */
    uint8_t mnonce[16]; /* In */
    uint32_t len;       /* In/Out */
} __packed;

/**
 * struct sev_data_snp_download_firmware - SNP_DOWNLOAD_FIRMWARE command params
 *
 * @address: physical address of firmware image
 * @len: length of the firmware image
 */
struct sev_data_snp_download_firmware {
    uint64_t address;				/* In */
    uint32_t len;				/* In */
} __packed;

/**
 * struct sev_data_snp_activate - SNP_ACTIVATE command params
 *
 * @gctx_paddr: system physical address guest context page
 * @asid: ASID to bind to the guest
 */
struct sev_data_snp_activate {
    uint64_t gctx_paddr;				/* In */
    uint32_t asid;				/* In */
} __packed;

/**
 * struct sev_data_snp_addr - generic SNP command params
 *
 * @address: physical address of generic data param
 */
struct sev_data_snp_addr {
    uint64_t address;				/* In/Out */
} __packed;

/**
 * struct sev_data_snp_launch_start - SNP_LAUNCH_START command params
 *
 * @gctx_paddr: system physical address of guest context page
 * @policy: guest policy
 * @ma_gctx_paddr: system physical address of migration agent
 * @ma_en: the guest is associated with a migration agent
 * @imi_en: launch flow is launching an IMI (Incoming Migration Image) for the
 *          purpose of guest-assisted migration.
 * @rsvd: reserved
 * @desired_tsc_khz: hypervisor desired mean TSC freq in kHz of the guest
 * @gosvw: guest OS-visible workarounds, as defined by hypervisor
 */
struct sev_data_snp_launch_start {
    uint64_t gctx_paddr;				/* In */
    uint64_t policy;				/* In */
    uint64_t ma_gctx_paddr;			/* In */
    uint32_t ma_en:1;				/* In */
    uint32_t imi_en:1;				/* In */
    uint32_t rsvd:30;
    uint32_t desired_tsc_khz;			/* In */
    uint8_t gosvw[16];				/* In */
} __packed;

/* SNP support page type */
enum {
    SNP_PAGE_TYPE_NORMAL    = 0x1,
    SNP_PAGE_TYPE_VMSA		= 0x2,
    SNP_PAGE_TYPE_ZERO		= 0x3,
    SNP_PAGE_TYPE_UNMEASURED	= 0x4,
    SNP_PAGE_TYPE_SECRET		= 0x5,
    SNP_PAGE_TYPE_CPUID		= 0x6,

    SNP_PAGE_TYPE_MAX
};

/**
 * struct sev_data_snp_launch_update - SNP_LAUNCH_UPDATE command params
 *
 * @gctx_paddr: system physical address of guest context page
 * @page_size: page size 0 indicates 4K and 1 indicates 2MB page
 * @page_type: encoded page type
 * @imi_page: indicates that this page is part of the IMI (Incoming Migration
 *            Image) of the guest
 * @rsvd: reserved
 * @rsvd2: reserved
 * @address: system physical address of destination page to encrypt
 * @rsvd3: reserved
 * @vmpl1_perms: VMPL permission mask for VMPL1
 * @vmpl2_perms: VMPL permission mask for VMPL2
 * @vmpl3_perms: VMPL permission mask for VMPL3
 * @rsvd4: reserved
 */
struct sev_data_snp_launch_update {
    uint64_t gctx_paddr;	/* In */
    uint32_t page_size:1;	/* In */
    uint32_t page_type:3;	/* In */
    uint32_t imi_page:1;	/* In */
    uint32_t rsvd:27;
    uint32_t rsvd2;
    uint64_t address;		/* In */
    uint32_t rsvd3:8;
    uint32_t vmpl1_perms:8;	/* In */
    uint32_t vmpl2_perms:8;	/* In */
    uint32_t vmpl3_perms:8;	/* In */
    uint32_t rsvd4;
} __packed;

/**
 * struct sev_data_snp_launch_finish - SNP_LAUNCH_FINISH command params
 *
 * @gctx_paddr: system physical address of guest context page
 * @id_block_paddr: system physical address of ID block
 * @id_auth_paddr: system physical address of ID block authentication structure
 * @id_block_en: indicates whether ID block is present
 * @auth_key_en: indicates whether author key is present in authentication structure
 * @vcek_disabled: indicates whether use of VCEK is allowed for attestation reports
 * @rsvd: reserved
 * @host_data: host-supplied data for guest, not interpreted by firmware
 */
struct sev_data_snp_launch_finish {
    uint64_t gctx_paddr;
    uint64_t id_block_paddr;
    uint64_t id_auth_paddr;
    uint8_t id_block_en:1;
    uint8_t auth_key_en:1;
    uint8_t vcek_disabled:1;
    uint64_t rsvd:61;
    uint8_t host_data[32];
} __packed;

/**
 * struct sev_data_snp_guest_status - SNP_GUEST_STATUS command params
 *
 * @gctx_paddr: system physical address of guest context page
 * @address: system physical address of guest status page
 */
struct sev_data_snp_guest_status {
    uint64_t gctx_paddr;
    uint64_t address;
} __packed;

/**
 * struct sev_data_snp_page_reclaim - SNP_PAGE_RECLAIM command params
 *
 * @paddr: system physical address of page to be claimed. The 0th bit in the
 *         address indicates the page size. 0h indicates 4KB and 1h indicates
 *         2MB page.
 */
struct sev_data_snp_page_reclaim {
    uint64_t paddr;
} __packed;

/**
 * struct sev_data_snp_page_unsmash - SNP_PAGE_UNSMASH command params
 *
 * @paddr: system physical address of page to be unsmashed. The 0th bit in the
 *         address indicates the page size. 0h indicates 4 KB and 1h indicates
 *         2 MB page.
 */
struct sev_data_snp_page_unsmash {
    uint64_t paddr;
} __packed;

/**
 * struct sev_data_snp_dbg - DBG_ENCRYPT/DBG_DECRYPT command parameters
 *
 * @gctx_paddr: system physical address of guest context page
 * @src_addr: source address of data to operate on
 * @dst_addr: destination address of data to operate on
 */
struct sev_data_snp_dbg {
    uint64_t gctx_paddr; /* In */
    uint64_t src_addr;	 /* In */
    uint64_t dst_addr;	 /* In */
} __packed;

/**
 * struct sev_data_snp_guest_request - SNP_GUEST_REQUEST command params
 *
 * @gctx_paddr: system physical address of guest context page
 * @req_paddr: system physical address of request page
 * @res_paddr: system physical address of response page
 */
struct sev_data_snp_guest_request {
    uint64_t gctx_paddr; /* In */
    uint64_t req_paddr;	 /* In */
    uint64_t res_paddr;	 /* In */
} __packed;

/**
 * struct sev_data_snp_init_ex - SNP_INIT_EX structure
 *
 * @init_rmp: indicate that the RMP should be initialized.
 * @list_paddr_en: indicate that list_paddr is valid
 * @rsvd: reserved
 * @rsvd1: reserved
 * @list_paddr: system physical address of range list
 * @rsvd2: reserved
 */
struct sev_data_snp_init_ex {
    uint32_t init_rmp:1;
    uint32_t list_paddr_en:1;
    uint32_t rapl_dis:1;
    uint32_t ciphertext_hiding_en:1;
    uint32_t tio_en:1;
    uint32_t rsvd:27;
    uint32_t rsvd1;
    uint64_t list_paddr;
    uint16_t max_snp_asid;
    uint8_t  rsvd2[46];
} __packed;

/**
 * struct sev_data_range - RANGE structure
 *
 * @base: system physical address of first byte of range
 * @page_count: number of 4KB pages in this range
 * @rsvd: reserved
 */
struct sev_data_range {
    uint64_t base;
    uint32_t page_count;
    uint32_t rsvd;
} __packed;

/**
 * struct sev_data_range_list - RANGE_LIST structure
 *
 * @num_elements: number of elements in RANGE_ARRAY
 * @rsvd: reserved
 * @ranges: array of num_elements of type RANGE
 */
struct sev_data_range_list {
    uint32_t num_elements;
    uint32_t rsvd;
    struct sev_data_range ranges[];
} __packed;

/**
 * struct sev_data_snp_shutdown_ex - SNP_SHUTDOWN_EX structure
 *
 * @len: length of the command buffer read by the PSP
 * @iommu_snp_shutdown: Disable enforcement of SNP in the IOMMU
 * @x86_snp_shutdown: Disable SNP on all cores
 * @rsvd1: reserved
 */
struct sev_data_snp_shutdown_ex {
    uint32_t len;
    uint32_t iommu_snp_shutdown:1;
    uint32_t x86_snp_shutdown:1;
    uint32_t rsvd1:30;
} __packed;

/**
 * struct sev_platform_init_args
 *
 * @error: SEV firmware error code
 * @probe: True if this is being called as part of CCP module probe, which
 *  will defer SEV_INIT/SEV_INIT_EX firmware initialization until needed
 *  unless psp_init_on_probe module param is set
 * @max_snp_asid: When non-zero, enable ciphertext hiding and specify the
 *  maximum ASID that can be used for an SEV-SNP guest.
 */
struct sev_platform_init_args {
    int error;
    bool probe;
    unsigned int max_snp_asid;
};

/**
 * struct sev_data_snp_commit - SNP_COMMIT structure
 *
 * @len: length of the command buffer read by the PSP
 */
struct sev_data_snp_commit {
    uint32_t len;
} __packed;

/**
 * struct sev_data_snp_feature_info - SEV_SNP_FEATURE_INFO structure
 *
 * @length: len of the command buffer read by the PSP
 * @ecx_in: subfunction index
 * @feature_info_paddr : System Physical Address of the FEATURE_INFO structure
 */
struct sev_data_snp_feature_info {
    uint32_t length;
    uint32_t ecx_in;
    uint64_t feature_info_paddr;
} __packed;

/**
 * struct feature_info - FEATURE_INFO structure
 *
 * @eax: output of SNP_FEATURE_INFO command
 * @ebx: output of SNP_FEATURE_INFO command
 * @ecx: output of SNP_FEATURE_INFO command
 * #edx: output of SNP_FEATURE_INFO command
 */
struct snp_feature_info {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} __packed;

/**
 * struct sev_data_snp_status - SNP status
 *
 * @api_major: API major version
 * @api_minor: API minor version
 * @state: current platform state
 * @is_rmp_initialized: whether RMP is initialized or not
 * @rsvd: reserved
 * @build_id: firmware build id for the API version
 * @mask_chip_id: whether chip id is present in attestation reports or not
 * @mask_chip_key: whether attestation reports are signed or not
 * @vlek_en: VLEK (Version Loaded Endorsement Key) hashstick is loaded
 * @feature_info: whether SNP_FEATURE_INFO command is available
 * @rapl_dis: whether RAPL is disabled
 * @ciphertext_hiding_cap: whether platform has ciphertext hiding capability
 * @ciphertext_hiding_en: whether ciphertext hiding is enabled
 * @rsvd1: reserved
 * @guest_count: the number of guest currently managed by the firmware
 * @current_tcb_version: current TCB version
 * @reported_tcb_version: reported TCB version
 */
struct sev_data_snp_status {
    uint8_t api_major;			   /* Out */
    uint8_t api_minor;			   /* Out */
    uint8_t state;			       /* Out */
    uint8_t is_rmp_initialized:1;  /* Out */
    uint8_t rsvd:7;
    uint32_t build_id;			    /* Out */
    uint32_t mask_chip_id:1;		/* Out */
    uint32_t mask_chip_key:1;		/* Out */
    uint32_t vlek_en:1;		        /* Out */
    uint32_t feature_info:1;		/* Out */
    uint32_t rapl_dis:1;		    /* Out */
    uint32_t ciphertext_hiding_cap:1; /* Out */
    uint32_t ciphertext_hiding_en:1;  /* Out */
    uint32_t rsvd1:25;
    uint32_t guest_count;		    /* Out */
    uint64_t current_tcb_version;	/* Out */
    uint64_t reported_tcb_version;	/* Out */
} __packed;

/* Feature bits in ECX */
#define SNP_X86_SHUTDOWN_SUPPORTED		BIT(1)
#define SNP_RAPL_DISABLE_SUPPORTED		BIT(2)
#define SNP_CIPHER_TEXT_HIDING_SUPPORTED	BIT(3)
#define SNP_AES_256_XTS_POLICY_SUPPORTED	BIT(4)
#define SNP_CXL_ALLOW_POLICY_SUPPORTED		BIT(5)

/* Feature bits in EBX */
#define SNP_SEV_TIO_SUPPORTED			BIT(1)

struct snp_guest_context {
    uint64_t gctx_paddr;
};

/**
 * struct sev_data_snp_config - system wide configuration value for SNP.
 *
 * @reported_tcb: the TCB version to report in the guest attestation report.
 * @mask_chip_id: whether chip id is present in attestation reports or not
 * @mask_chip_key: whether attestation reports are signed or not
 * @rsvd: reserved
 * @rsvd1: reserved
 */
struct sev_data_snp_config {
    uint64_t reported_tcb;     /* In */
    uint32_t mask_chip_id:1;   /* In */
    uint32_t mask_chip_key:1;  /* In */
    uint32_t rsvd:30;          /* In */
    uint8_t rsvd1[52];
} __packed;

/**
 * struct sev_data_snp_vlek_load - SNP_VLEK_LOAD structure
 *
 * @len: length of the command buffer read by the PSP
 * @vlek_wrapped_version: version of wrapped VLEK hashstick (Must be 0h)
 * @rsvd: reserved
 * @vlek_wrapped_address: address of a wrapped VLEK hashstick
 *                        (struct sev_user_data_snp_wrapped_vlek_hashstick)
 */
struct sev_data_snp_vlek_load {
    uint32_t len;                   /* In */
    uint8_t vlek_wrapped_version;   /* In */
    uint8_t rsvd[3];                /* In */
    uint64_t vlek_wrapped_address;  /* In */
} __packed;

/**
 * SEV platform commands
 */
enum {
    SEV_FACTORY_RESET = 0,
    SEV_PLATFORM_STATUS,
    SEV_PEK_GEN,
    SEV_PEK_CSR,
    SEV_PDH_GEN,
    SEV_PDH_CERT_EXPORT,
    SEV_PEK_CERT_IMPORT,
    SEV_GET_ID,  /* This command is deprecated, use SEV_GET_ID2 */
    SEV_GET_ID2,

    SEV_MAX,
};

/**
 * SEV Firmware status code
 */
typedef enum {
    /*
    * This error code is not in the SEV spec. Its purpose is to convey that
    * there was an error that prevented the SEV firmware from being called.
    * The SEV API error codes are 16 bits, so the -1 value will not overlap
    * with possible values from the specification.
    */
    SEV_RET_NO_FW_CALL = -1,
    SEV_RET_SUCCESS = 0,
    SEV_RET_INVALID_PLATFORM_STATE,
    SEV_RET_INVALID_GUEST_STATE,
    SEV_RET_INAVLID_CONFIG,
    SEV_RET_INVALID_LEN,
    SEV_RET_ALREADY_OWNED,
    SEV_RET_INVALID_CERTIFICATE,
    SEV_RET_POLICY_FAILURE,
    SEV_RET_INACTIVE,
    SEV_RET_INVALID_ADDRESS,
    SEV_RET_BAD_SIGNATURE,
    SEV_RET_BAD_MEASUREMENT,
    SEV_RET_ASID_OWNED,
    SEV_RET_INVALID_ASID,
    SEV_RET_WBINVD_REQUIRED,
    SEV_RET_DFFLUSH_REQUIRED,
    SEV_RET_INVALID_GUEST,
    SEV_RET_INVALID_COMMAND,
    SEV_RET_ACTIVE,
    SEV_RET_HWSEV_RET_PLATFORM,
    SEV_RET_HWSEV_RET_UNSAFE,
    SEV_RET_UNSUPPORTED,
    SEV_RET_INVALID_PARAM,
    SEV_RET_RESOURCE_LIMIT,
    SEV_RET_SECURE_DATA_INVALID,
    SEV_RET_MAX,
    SEV_RET_SNP_UPDATE_FAILED = 0x24,
} sev_ret_code;

/**
 * struct sev_user_data_status - PLATFORM_STATUS command parameters
 *
 * @major: major API version
 * @minor: minor API version
 * @state: platform state
 * @flags: platform config flags
 * @build: firmware build id for API version
 * @guest_count: number of active guests
 */
struct sev_user_data_status {
    uint8_t api_major;   /* Out */
    uint8_t api_minor;   /* Out */
    uint8_t state;       /* Out */
    uint8_t flags;       /* Out */
    uint8_t build;       /* Out */
    uint8_t guest_count; /* Out */
} __packed;

#define SEV_STATUS_FLAGS_CONFIG_ES  0x0100

/**
 * struct sev_user_data_pek_csr - PEK_CSR command parameters
 *
 * @address: PEK certificate chain
 * @length: length of certificate
 */
struct sev_user_data_pek_csr {
    uint8_t address; /* In */
    uint8_t length;  /* In/Out */
} __packed;

/**
 * struct sev_user_data_cert_import - PEK_CERT_IMPORT command parameters
 *
 * @pek_address: PEK certificate chain
 * @pek_len: length of PEK certificate
 * @oca_address: OCA certificate chain
 * @oca_len: length of OCA certificate
 */
struct sev_user_data_pek_cert_import {
    uint8_t pek_cert_address; /* In */
    uint8_t pek_cert_len;     /* In */
    uint8_t oca_cert_address; /* In */
    uint8_t oca_cert_len;     /* In */
} __packed;

/**
 * struct sev_user_data_pdh_cert_export - PDH_CERT_EXPORT command parameters
 *
 * @pdh_address: PDH certificate address
 * @pdh_len: length of PDH certificate
 * @cert_chain_address: PDH certificate chain
 * @cert_chain_len: length of PDH certificate chain
 */
struct sev_user_data_pdh_cert_export {
    uint8_t pdh_cert_address;   /* In */
    uint8_t pdh_cert_len;       /* In/Out */
    uint8_t cert_chain_address; /* In */
    uint8_t cert_chain_len;     /* In/Out */
} __packed;

/**
 * struct sev_user_data_get_id - GET_ID command parameters (deprecated)
 *
 * @socket1: Buffer to pass unique ID of first socket
 * @socket2: Buffer to pass unique ID of second socket
 */
struct sev_user_data_get_id {
    uint8_t socket1[64]; /* Out */
    uint8_t socket2[64]; /* Out */
} __packed;

/**
 * struct sev_user_data_get_id2 - GET_ID command parameters
 * @address: Buffer to store unique ID
 * @length: length of the unique ID
 */
struct sev_user_data_get_id2 {
    uint8_t address; /* In */
    uint8_t length;  /* In/Out */
} __packed;

extern int sev_do_cmd(int cmd, void *data, unsigned int *psp_ret, bool poll);

#endif  /* __PSP_SEV_H__ */

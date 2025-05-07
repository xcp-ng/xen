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
    uint64_t guest_address; /* In */
    uint32_t guest_len;     /* In */
    uint32_t reserved3;
    uint64_t trans_address; /* In */
    uint32_t trans_len;     /* In */
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
    uint32_t handle;           /* In */
    union sev_guest_policy policy; /* Out */
    uint64_t pdh_cert_address; /* In */
    uint32_t pdh_cert_len;     /* In */
    uint32_t reserved1;
    uint64_t plat_certs_address; /* In */
    uint32_t plat_certs_len;     /* In */
    uint32_t reserved2;
    uint64_t amd_certs_address;  /* In */
    uint32_t amd_certs_len;     /* In */
    uint32_t reserved3;
    uint64_t session_address; /* In */
    uint32_t session_len;     /* In/Out */
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

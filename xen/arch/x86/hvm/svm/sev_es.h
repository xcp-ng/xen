/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SVM_PRIVATE_SEV_ES_H
#define SVM_PRIVATE_SEV_ES_H

#include <xen/stdint.h>

enum VMGEXIT_EXITCODE
{
    VMGEXIT_NPF_MMIO_READ   = 0x80000001,
    VMGEXIT_NPF_MMIO_WRITE  = 0x80000002,
    VMGEXIT_NMI_COMPLETE    = 0x80000003,
    VMGEXIT_AP_RESET_HOLD   = 0x80000004,
    VMGEXIT_AP_JUMP_TABLE   = 0x80000005,
    VMGEXIT_PAGE_STATE_CHANGE = 0x80000010,
    VMGEXIT_AP_CREATION     = 0x80000013,
};

struct ghcb_save_area {
    uint8_t rsvd0[0xcb];
    uint8_t cpl;
    uint8_t rsvd1[0x74];
    uint64_t xss;        /* version >= 2 */
    uint8_t rsvd2[0x18];
    uint64_t dr7;
    uint8_t rsvd3[0x90];
    uint64_t rax;
    uint8_t rsvd4[0x101];
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rbx;
    uint64_t secure_avic_ctl;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint8_t rsvd5[16];
    uint64_t sw_exitcode;
    uint64_t sw_exitinfo1;
    uint64_t sw_exitinfo2;
    uint64_t sw_scratch;
    uint8_t rsvd6[0x38];
    uint64_t xcr0;
    uint64_t valid_bitmap[2];
    uint64_t x87_state_gpa;
    uint8_t rsvd7[0x3f8];
};

struct ghcb {
    struct ghcb_save_area save;

    uint8_t shared_buffer[2032];

    uint8_t reserved_1[10];
    uint16_t protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
    uint32_t ghcb_usage;
};

struct ghcb_psch_header {
    uint16_t cur_entry;
    uint16_t end_entry;
    uint32_t reserved;
};

union ghcb_psch_entry {
    uint64_t raw;
    struct {
        uint64_t cur_page:12;
        uint64_t gfn:40;
        uint64_t operation:4;
        uint64_t pagesize:1;
        uint64_t reserved:7;
    };
};

enum ghcb_msr_info {
    GHCB_MSR_CALL_PA       = 0x000,
    GHCB_MSR_SEV_INFO_RESP = 0x001,
    GHCB_MSR_SEV_INFO_REQ  = 0x002,
    /* 0x003 is reserved */
    GHCB_MSR_CPUID_REQ     = 0x004,
    GHCB_MSR_CPUID_RESP    = 0x005,
    /* GHCB v2.0+ */
    GHCB_MSR_AP_RESET_HOLD_REQ  = 0x006,
    GHCB_MSR_AP_RESET_HOLD_RESP = 0x007,
    /* 0x008-0x009 is reserved */
    GHCB_MSR_PREF_GHCB_GPA_REQ  = 0x010,
    GHCB_MSR_PREF_GHCB_GPA_RESP = 0x011,
    GHCB_MSR_REG_GHCB_GPA_REQ   = 0x012,
    GHCB_MSR_REG_GHCB_GPA_RESP  = 0x013,
    GHCB_MSR_PAGE_STATE_CHG_REQ = 0x014,
    GHCB_MSR_PAGE_STATE_CHG_RESP = 0x015,
    GHCB_MSR_SNP_RUN_VMPL_REQ    = 0x016,
    GHCB_MSR_SNP_RUN_VMPL_RESP   = 0x017,
    GHCB_MSR_UNREG_GHCB_GPA_REQ  = 0x018,
    GHCB_MSR_UNREG_GHCB_GPA_RESP = 0x019,
    GHCB_MSR_HYP_FEATURE_REQ     = 0x080,
    GHCB_MSR_HYP_FEATURE_RESP    = 0x081,
    GHCB_MSR_TERM_REQ            = 0x100,
};

enum ghcb_cpuid_reg {
    GHCB_CPUID_REG_EAX = 0,
    GHCB_CPUID_REG_EBX = 1,
    GHCB_CPUID_REG_ECX = 2,
    GHCB_CPUID_REG_EDX = 3,
};

union ghcb_msr_data {
    unsigned long raw:52;
    struct {
        unsigned long max_version:16;
        unsigned long min_version:16;
        unsigned long c_bit:8;
        unsigned long rsvd:12;
    } info_resp;
    struct {
        uint32_t leaf;
        unsigned long reg:2;
        unsigned long rsvd:18;
    } cpuid_req;
    struct {
        uint32_t value;
        unsigned long reg:2;
        unsigned long rsvd:18;
    } cpuid_resp;
    struct {
        unsigned long rsvd:8;
        unsigned long op:4;
        unsigned long gfn:40;
    } psc_req;
    struct {
        unsigned long error_code:32;
        unsigned long rsvd:20;
    } psc_resp;
    struct {
        unsigned long rsvd1:24;
        unsigned long vmpl:8;
        unsigned long rsvd2:20;
    } vmpl_req;
    struct {
        unsigned long error_code:32;
        unsigned long rsvd:20;
    } vmpl_resp;
    struct {
        unsigned long rsvd:40;
        unsigned long reason:8;
        unsigned long code:4;
    } term_req;
};

/*
 * Support provided for base SEV-SNP support:
 * 
 * - Preferred GHCB GPA MSR Protocol
 * - Register GHCB GPA MSR Protocol
 * - SNP Page State Change MSR Protocol
 * - SNP Page State Change NAE Event
 * - SNP Guest Request NAE Event
 * - SNP Extended Guest Request NAE Event
 *
 * Xen: Supported (if SEV-SNP).
 */
#define GHCB_FEAT_SNP                 (1 << 0)
/*
 * Support provided for SEV-SNP guest AP VMSA creation:
 * - SNP AP Create NAE Event
 * Requires SEV-SNP Feature.
 */
#define GHCB_FEAT_SNP_AP_CREATION     (1 << 1)
/*
 * Support provided for SEV-SNP Restricted Injection:
 * - SNP #HV Doorbell Page
 * - SNP #HV IPI
 * Requires SEV-SNP
 * Requires SEV-SNP AP Creation
 */
#define GHCB_FEAT_SNP_RESTRICTED_INJ  (1 << 2)
/*
 * Support provided for SEV-SNP Restricted Injection Timer
 * - SNP #HV Timer NAE Event
 * Requires SEV-SNP
 * Requires SEV-SNP AP Creation
 * Requires SEV-SNP Restricted Injection
 */
#define GHCB_FEAT_SNP_RESTR_INJ_TIMER (1 << 3)
/* 
 * Support provided to return the list of APIC IDs associated with the
 * guest vCPUs.
 */
#define GHCB_FEAT_APIC_ID_LIST        (1 << 4)
/*
 * Support provided for running a vCPU at different VMPL levels
 *
 * SNP Run VMPL MSR Protocol Request/Response
 * SNP Run VMPL NAE Event
 * Requires SEV-SNP
 * Requires SEV-SNP AP Creation
 */
#define GHCB_FEAT_SNP_MULTI_VMPL      (1 << 5)
/* 
 * Support for additionally allowing SEV-ES guests to use the 
 * Page State Change protocols (MSR and NAE Event).
 */
#define GHCB_FEAT_SEV_ES_PSC          (1 << 6)
/* 
 * Support for additionally allowing SEV-SNP use of trusted IO devices (TDISP).
 */
#define GHCB_FEAT_TIO                 (1 << 7)
/*
 * Support for unregistering the currently registered GHCB GPA.
 */
#define GHCB_FEAT_GHCB_UNREGISTER     (1 << 8)

union ghcb_msr {
    uint64_t raw;
    struct {
        unsigned long info:12;
        /* We can't use ghcb_msr_data directly as unions are not bit-sized. */
        unsigned long data_raw:52;
    };
};

#endif /* SVM_PRIVATE_SEV_ES_H */

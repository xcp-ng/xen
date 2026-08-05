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

#define GHCB_VERSION_MAX	1ULL
#define GHCB_VERSION_MIN	1ULL

#define GHCB_MSR_INFO_POS		0
#define GHCB_DATA_LOW			  12
#define GHCB_MSR_INFO_MASK	((1ULL << GHCB_DATA_LOW) - 1)

#define GHCB_DATA(v)			\
	(((unsigned long)(v) & ~GHCB_MSR_INFO_MASK) >> GHCB_DATA_LOW)

/* SEV Information Request/Response */
#define GHCB_MSR_SEV_INFO_RESP		0x001
#define GHCB_MSR_SEV_INFO_REQ		0x002
#define GHCB_MSR_VER_MAX_POS		48
#define GHCB_MSR_VER_MAX_MASK		0xffff
#define GHCB_MSR_VER_MIN_POS		32
#define GHCB_MSR_VER_MIN_MASK		0xffff
#define GHCB_MSR_CBIT_POS		24
#define GHCB_MSR_CBIT_MASK		0xff
#define GHCB_MSR_SEV_INFO(_max, _min, _cbit)				\
	((((_max) & GHCB_MSR_VER_MAX_MASK) << GHCB_MSR_VER_MAX_POS) |	\
	 (((_min) & GHCB_MSR_VER_MIN_MASK) << GHCB_MSR_VER_MIN_POS) |	\
	 (((_cbit) & GHCB_MSR_CBIT_MASK) << GHCB_MSR_CBIT_POS) |	\
	 GHCB_MSR_SEV_INFO_RESP)
#define GHCB_MSR_INFO(v)		((v) & 0xfffUL)
#define GHCB_MSR_PROTO_MAX(v)		(((v) >> GHCB_MSR_VER_MAX_POS) & GHCB_MSR_VER_MAX_MASK)
#define GHCB_MSR_PROTO_MIN(v)		(((v) >> GHCB_MSR_VER_MIN_POS) & GHCB_MSR_VER_MIN_MASK)

/* CPUID Request/Response */
#define GHCB_MSR_CPUID_REQ		0x004
#define GHCB_MSR_CPUID_RESP		0x005
#define GHCB_MSR_CPUID_FUNC_POS		32
#define GHCB_MSR_CPUID_FUNC_MASK	0xffffffff
#define GHCB_MSR_CPUID_FUNC(data) \
	(((unsigned long)data) >> (GHCB_MSR_CPUID_FUNC_POS - GHCB_DATA_LOW) & \
  GHCB_MSR_CPUID_FUNC_MASK)
#define GHCB_MSR_CPUID_VALUE_POS	32
#define GHCB_MSR_CPUID_VALUE_MASK	0xffffffff
#define GHCB_MSR_CPUID_REG_POS		30
#define GHCB_MSR_CPUID_REG_MASK		0x3
#define GHCB_MSR_CPUID_REG(data) \
	(((unsigned long)data) >> (GHCB_MSR_CPUID_REG_POS - GHCB_DATA_LOW) & \
  GHCB_MSR_CPUID_REG_MASK)
#define GHCB_CPUID_REQ_EAX		0
#define GHCB_CPUID_REQ_EBX		1
#define GHCB_CPUID_REQ_ECX		2
#define GHCB_CPUID_REQ_EDX		3

#define GHCB_CPUID_REQ(fn, reg)		\
		(GHCB_MSR_CPUID_REQ | \
		(((unsigned long)reg & GHCB_MSR_CPUID_REG_MASK) << GHCB_MSR_CPUID_REG_POS) | \
		(((unsigned long)fn) << GHCB_MSR_CPUID_FUNC_POS))

#define GHCB_CPUID_RESP(val, reg)		\
	(GHCB_MSR_CPUID_RESP | \
	(((unsigned long)reg & GHCB_MSR_CPUID_REG_MASK) << GHCB_MSR_CPUID_REG_POS) | \
	(((unsigned long)val) << GHCB_MSR_CPUID_VALUE_POS))

/* AP Reset Hold */
#define GHCB_MSR_AP_RESET_HOLD_REQ		0x006
#define GHCB_MSR_AP_RESET_HOLD_RESP		0x007

/* GHCB Hypervisor Feature Request/Response */
#define GHCB_MSR_HV_FT_REQ			0x080
#define GHCB_MSR_HV_FT_RESP			0x081

#define GHCB_MSR_TERM_REQ		0x100
#define GHCB_MSR_TERM_REASON_SET_POS	12
#define GHCB_MSR_TERM_REASON_SET_MASK	0xf
#define GHCB_MSR_TERM_REASON_POS	16
#define GHCB_MSR_TERM_REASON_MASK	0xff
#define GHCB_SEV_TERM_REASON(reason_set, reason_val)						  \
	(((((u64)reason_set) &  GHCB_MSR_TERM_REASON_SET_MASK) << GHCB_MSR_TERM_REASON_SET_POS) | \
	((((u64)reason_val) & GHCB_MSR_TERM_REASON_MASK) << GHCB_MSR_TERM_REASON_POS))

#define GHCB_SEV_ES_REASON_GENERAL_REQUEST	0
#define GHCB_SEV_ES_REASON_PROTOCOL_UNSUPPORTED	1

#define GHCB_RESP_CODE(v)		((v) & GHCB_MSR_INFO_MASK)

#endif /* SVM_PRIVATE_SEV_ES_H */

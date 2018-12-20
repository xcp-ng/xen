/***************************************************************************
 * synic.c
 *
 * An implementation of some interrupt related Viridian enlightenments.
 * See Microsoft's Hypervisor Top Level Functional Specification.
 * for more information.
 */

#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/sched.h>
#include <xen/version.h>

#include <asm/apic.h>
#include <asm/hvm/support.h>
#include <asm/hvm/vlapic.h>

#include "private.h"

typedef struct _HV_VIRTUAL_APIC_ASSIST
{
    uint32_t no_eoi:1;
    uint32_t reserved_zero:31;
} HV_VIRTUAL_APIC_ASSIST;

typedef union _HV_VP_ASSIST_PAGE
{
    HV_VIRTUAL_APIC_ASSIST ApicAssist;
    uint8_t ReservedZBytePadding[PAGE_SIZE];
} HV_VP_ASSIST_PAGE;

typedef enum HV_MESSAGE_TYPE {
    HvMessageTypeNone,
    HvMessageTimerExpired = 0x80000010,
} HV_MESSAGE_TYPE;

typedef struct HV_MESSAGE_FLAGS {
    uint8_t MessagePending:1;
    uint8_t Reserved:7;
} HV_MESSAGE_FLAGS;

typedef struct HV_MESSAGE_HEADER {
    HV_MESSAGE_TYPE MessageType;
    uint16_t Reserved1;
    HV_MESSAGE_FLAGS MessageFlags;
    uint8_t PayloadSize;
    uint64_t Reserved2;
} HV_MESSAGE_HEADER;

#define HV_MESSAGE_SIZE 256
#define HV_MESSAGE_MAX_PAYLOAD_QWORD_COUNT 30

typedef struct HV_MESSAGE {
    HV_MESSAGE_HEADER Header;
    uint64_t Payload[HV_MESSAGE_MAX_PAYLOAD_QWORD_COUNT];
} HV_MESSAGE;

void viridian_apic_assist_set(struct vcpu *v)
{
    HV_VP_ASSIST_PAGE *ptr = v->arch.hvm.viridian->vp_assist.ptr;

    if ( !ptr )
        return;

    /*
     * If there is already an assist pending then something has gone
     * wrong and the VM will most likely hang so force a crash now
     * to make the problem clear.
     */
    if ( v->arch.hvm.viridian->apic_assist_pending )
        domain_crash(v->domain);

    v->arch.hvm.viridian->apic_assist_pending = true;
    ptr->ApicAssist.no_eoi = 1;
}

bool viridian_apic_assist_completed(struct vcpu *v)
{
    HV_VP_ASSIST_PAGE *ptr = v->arch.hvm.viridian->vp_assist.ptr;

    if ( !ptr )
        return false;

    if ( v->arch.hvm.viridian->apic_assist_pending &&
         !ptr->ApicAssist.no_eoi )
    {
        /* An EOI has been avoided */
        v->arch.hvm.viridian->apic_assist_pending = false;
        return true;
    }

    return false;
}

void viridian_apic_assist_clear(struct vcpu *v)
{
    HV_VP_ASSIST_PAGE *ptr = v->arch.hvm.viridian->vp_assist.ptr;

    if ( !ptr )
        return;

    ptr->ApicAssist.no_eoi = 0;
    v->arch.hvm.viridian->apic_assist_pending = false;
}

int viridian_synic_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val)
{
    struct domain *d = v->domain;

    switch ( idx )
    {
    case HV_X64_MSR_EOI:
        vlapic_EOI_set(vcpu_vlapic(v));
        break;

    case HV_X64_MSR_ICR:
        vlapic_reg_write(v, APIC_ICR2, val >> 32);
        vlapic_reg_write(v, APIC_ICR, val);
        break;

    case HV_X64_MSR_TPR:
        vlapic_reg_write(v, APIC_TASKPRI, val);
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        /* release any previous mapping */
        viridian_unmap_guest_page(&v->arch.hvm.viridian->vp_assist);
        v->arch.hvm.viridian->vp_assist.msr.raw = val;
        viridian_dump_guest_page(v, "VP_ASSIST",
                                 &v->arch.hvm.viridian->vp_assist);
        if ( v->arch.hvm.viridian->vp_assist.msr.fields.enabled )
            viridian_map_guest_page(d, &v->arch.hvm.viridian->vp_assist);
        break;

    case HV_X64_MSR_SCONTROL:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        v->arch.hvm.viridian->scontrol = val;
        break;

    case HV_X64_MSR_SVERSION:
        return X86EMUL_EXCEPTION;

    case HV_X64_MSR_SIEFP:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        v->arch.hvm.viridian->siefp = val;
        break;

    case HV_X64_MSR_SIMP:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        viridian_unmap_guest_page(&v->arch.hvm.viridian->simp);
        v->arch.hvm.viridian->simp.msr.raw = val;
        viridian_dump_guest_page(v, "SIMP", &v->arch.hvm.viridian->simp);
        if ( v->arch.hvm.viridian->simp.msr.fields.enabled )
            viridian_map_guest_page(d, &v->arch.hvm.viridian->simp);
        break;

    case HV_X64_MSR_EOM:
    {
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        v->arch.hvm.viridian->msg_pending = 0;
        break;
    }
    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
    {
        unsigned int sintx = idx - HV_X64_MSR_SINT0;
        uint8_t vector = v->arch.hvm.viridian->sint[sintx].fields.vector;

        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        /*
         * Invalidate any previous mapping by setting an out-of-range
         * index.
         */
        v->arch.hvm.viridian->vector_to_sintx[vector] =
            ARRAY_SIZE(v->arch.hvm.viridian->sint);

        v->arch.hvm.viridian->sint[sintx].raw = val;

        /* Vectors must be in the range 16-255 inclusive */
        vector = v->arch.hvm.viridian->sint[sintx].fields.vector;
        if ( vector < 16 )
            return X86EMUL_EXCEPTION;

        printk(XENLOG_G_INFO "%pv: VIRIDIAN SINT%u: vector: %x\n", v, sintx,
               vector);
        v->arch.hvm.viridian->vector_to_sintx[vector] = sintx;

        if ( v->arch.hvm.viridian->sint[sintx].fields.polling )
            clear_bit(sintx, &v->arch.hvm.viridian->msg_pending);

        break;
    }
    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x (%016"PRIx64")\n",
                 __func__, idx, val);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_synic_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
    struct domain *d = v->domain;

    switch ( idx )
    {
    case HV_X64_MSR_EOI:
        return X86EMUL_EXCEPTION;

    case HV_X64_MSR_ICR:
    {
        uint32_t icr2 = vlapic_get_reg(vcpu_vlapic(v), APIC_ICR2);
        uint32_t icr = vlapic_get_reg(vcpu_vlapic(v), APIC_ICR);

        *val = ((uint64_t)icr2 << 32) | icr;
        break;
    }
    case HV_X64_MSR_TPR:
        *val = vlapic_get_reg(vcpu_vlapic(v), APIC_TASKPRI);
        break;

    case HV_X64_MSR_VP_ASSIST_PAGE:
        *val = v->arch.hvm.viridian->vp_assist.msr.raw;
        break;

    case HV_X64_MSR_SCONTROL:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = v->arch.hvm.viridian->scontrol;
        break;

    case HV_X64_MSR_SVERSION:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        /*
         * The specification says that the version number is 0x00000001
         * and should be in the lower 32-bits of the MSR, while the
         * upper 32-bits are reserved... but it doesn't say what they
         * should be set to. Assume everything but the bottom bit
         * should be zero.
         */
        *val = 1ul;
        break;

    case HV_X64_MSR_SIEFP:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = v->arch.hvm.viridian->siefp;
        break;

    case HV_X64_MSR_SIMP:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = v->arch.hvm.viridian->simp.msr.raw;
        break;

    case HV_X64_MSR_EOM:
        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = 0;
        break;

    case HV_X64_MSR_SINT0 ... HV_X64_MSR_SINT15:
    {
        unsigned int sintx = idx - HV_X64_MSR_SINT0;

        if ( !(viridian_feature_mask(d) & HVMPV_synic) )
            return X86EMUL_EXCEPTION;

        *val = v->arch.hvm.viridian->sint[sintx].raw;
        break;
    }
    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x\n", __func__, idx);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_synic_vcpu_init(struct vcpu *v)
{
    unsigned int i;

    /*
     * The specification says that all synthetic interrupts must be
     * initally masked.
     */
    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->sint); i++ )
        v->arch.hvm.viridian->sint[i].fields.mask = 1;

    /* Initialize the mapping array with invalid values */
    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->vector_to_sintx); i++ )
        v->arch.hvm.viridian->vector_to_sintx[i] =
            ARRAY_SIZE(v->arch.hvm.viridian->sint);

    return 0;
}

int viridian_synic_domain_init(struct domain *d)
{
    return 0;
}

void viridian_synic_vcpu_deinit(struct vcpu *v)
{
    viridian_unmap_guest_page(&v->arch.hvm.viridian->vp_assist);
    viridian_unmap_guest_page(&v->arch.hvm.viridian->simp);
}

void viridian_synic_domain_deinit(struct domain *d)
{
}

void viridian_synic_poll_messages(struct vcpu *v)
{
    viridian_time_poll_timers(v);
}

bool viridian_synic_deliver_timer_msg(struct vcpu *v, unsigned int sintx,
                                      unsigned int index,
                                      int64_t expiration, int64_t delivery)
{
    const union viridian_sint_msr *vs = &v->arch.hvm.viridian->sint[sintx];
    HV_MESSAGE *msg = v->arch.hvm.viridian->simp.ptr;
    struct {
        uint32_t TimerIndex;
        uint32_t Reserved;
        uint64_t ExpirationTime;
        uint64_t DeliveryTime;
    } payload = {
        .TimerIndex = index,
        .ExpirationTime = expiration,
        .DeliveryTime = delivery,
    };

    if ( test_bit(sintx, &v->arch.hvm.viridian->msg_pending) )
        return false;

    BUILD_BUG_ON(sizeof(*msg) != HV_MESSAGE_SIZE);
    msg += sintx;

    /*
     * To avoid using an atomic test-and-set this function must be called
     * in context of the vcpu receiving the message.
     */
    ASSERT(v == current);
    if ( msg->Header.MessageType != HvMessageTypeNone )
    {
        msg->Header.MessageFlags.MessagePending = 1;
        set_bit(sintx, &v->arch.hvm.viridian->msg_pending);
        return false;
    }

    msg->Header.MessageType = HvMessageTimerExpired;
    msg->Header.MessageFlags.MessagePending = 0;
    msg->Header.PayloadSize = sizeof(payload);
    memcpy(msg->Payload, &payload, sizeof(payload));

    if ( !vs->fields.mask )
        vlapic_set_irq(vcpu_vlapic(v), vs->fields.vector, 0);

    return true;
}

bool viridian_synic_is_auto_eoi_sint(struct vcpu *v, uint8_t vector)
{
    int sintx = v->arch.hvm.viridian->vector_to_sintx[vector];

    if ( sintx >= ARRAY_SIZE(v->arch.hvm.viridian->sint) )
        return false;

    return v->arch.hvm.viridian->sint[sintx].fields.auto_eoi;
}

void viridian_synic_ack_sint(struct vcpu *v, uint8_t vector)
{
    int sintx = v->arch.hvm.viridian->vector_to_sintx[vector];

    if ( sintx < ARRAY_SIZE(v->arch.hvm.viridian->sint) )
        clear_bit(sintx, &v->arch.hvm.viridian->msg_pending);
}

void viridian_synic_save_vcpu_ctxt(const struct vcpu *v,
                                   struct hvm_viridian_vcpu_context *ctxt)
{
    unsigned int i;

    BUILD_BUG_ON(ARRAY_SIZE(v->arch.hvm.viridian->sint) !=
                 ARRAY_SIZE(ctxt->sint_msr));

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->sint); i++ )
        ctxt->sint_msr[i] = v->arch.hvm.viridian->sint[i].raw;

    ctxt->simp_msr = v->arch.hvm.viridian->simp.msr.raw;

    ctxt->apic_assist_pending = v->arch.hvm.viridian->apic_assist_pending;
    ctxt->vp_assist_msr = v->arch.hvm.viridian->vp_assist.msr.raw;
}

void viridian_synic_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt)
{
    struct domain *d = v->domain;
    unsigned int i;

    v->arch.hvm.viridian->vp_assist.msr.raw = ctxt->vp_assist_msr;
    if ( v->arch.hvm.viridian->vp_assist.msr.fields.enabled )
        viridian_map_guest_page(d, &v->arch.hvm.viridian->vp_assist);

    v->arch.hvm.viridian->apic_assist_pending = ctxt->apic_assist_pending;

    v->arch.hvm.viridian->simp.msr.raw = ctxt->simp_msr;
    if ( v->arch.hvm.viridian->simp.msr.fields.enabled )
        viridian_map_guest_page(d, &v->arch.hvm.viridian->simp);

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->sint); i++ )
    {
        uint8_t vector;

        v->arch.hvm.viridian->sint[i].raw = ctxt->sint_msr[i];

        vector = v->arch.hvm.viridian->sint[i].fields.vector;
        if ( vector < 16 )
            continue;

        v->arch.hvm.viridian->vector_to_sintx[vector] = i;
    }
}

void viridian_synic_save_domain_ctxt(
    const struct domain *d, struct hvm_viridian_domain_context *ctxt)
{
}

void viridian_synic_load_domain_ctxt(
    struct domain *d, const struct hvm_viridian_domain_context *ctxt)
{
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

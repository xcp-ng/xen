/***************************************************************************
 * time.c
 *
 * An implementation of some time related Viridian enlightenments.
 * See Microsoft's Hypervisor Top Level Functional Specification.
 * for more information.
 */

#include <xen/domain_page.h>
#include <xen/hypercall.h>
#include <xen/sched.h>
#include <xen/version.h>

#include <asm/apic.h>
#include <asm/event.h>
#include <asm/hvm/support.h>

#include "private.h"

typedef struct _HV_REFERENCE_TSC_PAGE
{
    uint32_t TscSequence;
    uint32_t Reserved1;
    uint64_t TscScale;
    int64_t  TscOffset;
    uint64_t Reserved2[509];
} HV_REFERENCE_TSC_PAGE, *PHV_REFERENCE_TSC_PAGE;

static void update_reference_tsc(struct domain *d, bool initialize)
{
    const struct viridian_page *rt = &d->arch.hvm.viridian->reference_tsc;
    HV_REFERENCE_TSC_PAGE *p = rt->ptr;

    if ( initialize )
        clear_page(p);

    /*
     * This enlightenment must be disabled is the host TSC is not invariant.
     * However it is also disabled if vtsc is true (which means rdtsc is
     * being emulated). This generally happens when guest TSC freq and host
     * TSC freq don't match. The TscScale value could be adjusted to cope
     * with this, allowing vtsc to be turned off, but support for this is
     * not yet present in the hypervisor. Thus is it is possible that
     * migrating a Windows VM between hosts of differing TSC frequencies
     * may result in large differences in guest performance.
     */
    if ( !host_tsc_is_safe() || d->arch.vtsc )
    {
        /*
         * The specification states that valid values of TscSequence range
         * from 0 to 0xFFFFFFFE. The value 0xFFFFFFFF is used to indicate
         * this mechanism is no longer a reliable source of time and that
         * the VM should fall back to a different source.
         *
         * Server 2012 (6.2 kernel) and 2012 R2 (6.3 kernel) actually
         * violate the spec. and rely on a value of 0 to indicate that this
         * enlightenment should no longer be used.
         */
        p->TscSequence = 0;

        printk(XENLOG_G_INFO "d%d: VIRIDIAN REFERENCE_TSC: invalidated\n",
               d->domain_id);
        return;
    }

    /*
     * The guest will calculate reference time according to the following
     * formula:
     *
     * ReferenceTime = ((RDTSC() * TscScale) >> 64) + TscOffset
     *
     * Windows uses a 100ns tick, so we need a scale which is cpu
     * ticks per 100ns shifted left by 64.
     */
    p->TscScale = ((10000ul << 32) / d->arch.tsc_khz) << 32;

    p->TscSequence++;
    if ( p->TscSequence == 0xFFFFFFFF ||
         p->TscSequence == 0 ) /* Avoid both 'invalid' values */
        p->TscSequence = 1;
}

static int64_t raw_trc_val(struct domain *d)
{
    uint64_t tsc;
    struct time_scale tsc_to_ns;

    tsc = hvm_get_guest_tsc(pt_global_vcpu_target(d));

    /* convert tsc to count of 100ns periods */
    set_time_scale(&tsc_to_ns, d->arch.tsc_khz * 1000ul);
    return scale_delta(tsc, &tsc_to_ns) / 100ul;
}

static void time_ref_count_freeze(struct domain *d)
{
    struct viridian_time_ref_count *trc =
        &d->arch.hvm.viridian->time_ref_count;

    if ( test_and_clear_bit(_TRC_running, &trc->flags) )
        trc->val = raw_trc_val(d) + trc->off;
}

static void time_ref_count_thaw(struct domain *d)
{
    struct viridian_time_ref_count *trc =
        &d->arch.hvm.viridian->time_ref_count;

    if ( !d->is_shutting_down &&
         !test_and_set_bit(_TRC_running, &trc->flags) )
        trc->off = (int64_t)trc->val - raw_trc_val(d);
}

static int64_t time_ref_count(struct domain *d)
{
    struct viridian_time_ref_count *trc =
        &d->arch.hvm.viridian->time_ref_count;

    return raw_trc_val(d) + trc->off;
}

static int64_t time_now(struct domain *d)
{
    const struct viridian_page *rt = &d->arch.hvm.viridian->reference_tsc;
    HV_REFERENCE_TSC_PAGE *p = rt->ptr;
    uint32_t start, end;
    __int128_t tsc;
    __int128_t scale;
    int64_t offset;

    /*
     * If the reference TSC page is not enabled, or has been invalidated
     * fall back to the partition reference counter.
     */
    if ( !p || !p->TscSequence )
        return time_ref_count(d);

    /*
     * The following sampling algorithm for tsc, scale and offset is
     * documented in the specifiction.
     */
    start = p->TscSequence;

    do {
        tsc = rdtsc();
        scale = p->TscScale;
        offset = p->TscOffset;

        smp_mb();
        end = p->TscSequence;
    } while (end != start);

    /*
     * The specification says: "The partition reference time is computed
     * by the following formula:
     *
     * ReferenceTime = ((VirtualTsc * TscScale) >> 64) + TscOffset
     *
     * The multiplication is a 64 bit multiplication, which results in a
     * 128 bit number which is then shifted 64 times to the right to obtain
     * the high 64 bits."
     */
    return ((tsc * scale) >> 64) + offset;
}

static void stop_stimer(struct viridian_stimer *vs)
{
    struct vcpu *v = vs->v;
    unsigned int stimerx = vs - &v->arch.hvm.viridian->stimer[0];

    if ( !vs->started )
        return;

    stop_timer(&vs->timer);
    clear_bit(stimerx, &v->arch.hvm.viridian->stimer_pending);
    vs->started = false;
}

static void stimer_expire(void *data)
{
    struct viridian_stimer *vs = data;
    struct vcpu *v = vs->v;
    unsigned int stimerx = vs - &v->arch.hvm.viridian->stimer[0];

    if ( !vs->config.fields.enabled )
        return;

    set_bit(stimerx, &v->arch.hvm.viridian->stimer_pending);
    vcpu_kick(v);
}

static void start_stimer(struct viridian_stimer *vs)
{
    struct vcpu *v = vs->v;
    unsigned int stimerx = vs - &v->arch.hvm.viridian->stimer[0];
    int64_t now = time_now(v->domain);
    s_time_t timeout;

    if ( !test_and_set_bit(stimerx, &v->arch.hvm.viridian->stimer_enabled) )
        printk(XENLOG_G_INFO "%pv: VIRIDIAN STIMER%u: enabled\n", v,
               stimerx);

    if ( vs->config.fields.periodic )
    {
        unsigned int missed = 0;
        int64_t next;

        /*
         * If the timer has not been started yet, or is lazy, the simply
         * schedule it to expire 'count' ticks in the future.
         */
        if ( !vs->started || vs->config.fields.lazy )
        {
            next = now + vs->count;
        }
        else
        {
            /* Advance the timer expiration by one tick */
            vs->expiration += vs->count;

            /*
             * Check to see if any expirations have been missed.
             * The specification says that a non-zero missed count should
             * be used to reduce the period of the timer until it catches
             * up, unless the count has reached a 'significant number', in
             * which case the timer should also be treated as lazy (see
             * if clause above). Unfortunately the specification does not
             * state what that number is so the choice of number here is a
             * pure guess.
             */
            next = vs->expiration;
            while ( next - now <= 0 && missed <= 3 )
            {
                next += vs->count;
                missed++;
            }

            if ( next - now <= 0 )
            {
                next = now + vs->count;
                missed = 0;
            }
        }

        timeout = ((next - now) * 100ull) / (missed + 1);
    }
    else
    {
        vs->expiration = vs->count;
        if ( vs->count - now <= 0 )
        {
            set_bit(stimerx, &v->arch.hvm.viridian->stimer_pending);
            return;
        }

        timeout = (vs->expiration - now) * 100ull;
    }

    vs->started = true;
    migrate_timer(&vs->timer, smp_processor_id());
    set_timer(&vs->timer, timeout + NOW());
}

static void poll_stimer(struct vcpu *v, unsigned int stimerx)
{
    struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[stimerx];

    if ( !test_bit(stimerx, &v->arch.hvm.viridian->stimer_pending) )
        return;

    if ( !viridian_synic_deliver_timer_msg(v, vs->config.fields.sintx,
                                           stimerx, vs->expiration,
                                           time_now(v->domain)) )
        return;

    clear_bit(stimerx, &v->arch.hvm.viridian->stimer_pending);

    if ( vs->config.fields.periodic )
        start_stimer(vs);
    else
        vs->config.fields.enabled = 0;
}

void viridian_time_poll_timers(struct vcpu *v)
{
    unsigned int i;

    if ( !v->arch.hvm.viridian->stimer_pending )
       return;

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->stimer); i++ )
        poll_stimer(v, i);
}

void viridian_time_vcpu_freeze(struct vcpu *v)
{
    unsigned int i;

    if ( !v->arch.hvm.viridian )
        return;

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->stimer); i++ )
    {
        struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[i];

        if ( vs->started )
            stop_timer(&vs->timer);
    }
}

void viridian_time_vcpu_thaw(struct vcpu *v)
{
    unsigned int i;

    if ( !v->arch.hvm.viridian )
        return;

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->stimer); i++ )
    {
        struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[i];

        if ( vs->config.fields.enabled )
            start_stimer(vs);
    }
}

void viridian_time_domain_freeze(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        viridian_time_vcpu_freeze(v);

    if ( !d->arch.hvm.viridian )
        return;

    time_ref_count_freeze(d);
}

void viridian_time_domain_thaw(struct domain *d)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        viridian_time_vcpu_thaw(v);

    if ( !d->arch.hvm.viridian )
        return;

    time_ref_count_thaw(d);
}

int viridian_time_wrmsr(struct vcpu *v, uint32_t idx, uint64_t val)
{
    struct domain *d = v->domain;

    switch ( idx )
    {
    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(viridian_feature_mask(d) & HVMPV_reference_tsc) )
            return X86EMUL_EXCEPTION;

        viridian_unmap_guest_page(&d->arch.hvm.viridian->reference_tsc);
        d->arch.hvm.viridian->reference_tsc.msr.raw = val;
        viridian_dump_guest_page(v, "REFERENCE_TSC",
                                 &d->arch.hvm.viridian->reference_tsc);
        if ( d->arch.hvm.viridian->reference_tsc.msr.fields.enabled )
        {
            viridian_map_guest_page(d, &d->arch.hvm.viridian->reference_tsc);
            update_reference_tsc(d, true);
        }
        break;

    case HV_X64_MSR_TIME_REF_COUNT:
        return X86EMUL_EXCEPTION;

    case HV_X64_MSR_STIMER0_CONFIG:
    case HV_X64_MSR_STIMER1_CONFIG:
    case HV_X64_MSR_STIMER2_CONFIG:
    case HV_X64_MSR_STIMER3_CONFIG:
    {
        unsigned int stimerx = (idx - HV_X64_MSR_STIMER0_CONFIG) / 2;
        struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[stimerx];

        if ( !(viridian_feature_mask(d) & HVMPV_stimer) )
            return X86EMUL_EXCEPTION;

        stop_stimer(vs);

        vs->config.raw = val;

        if ( !vs->config.fields.sintx )
            vs->config.fields.enabled = 0;

        if ( vs->config.fields.enabled )
            start_stimer(vs);

        break;
    }
    case HV_X64_MSR_STIMER0_COUNT:
    case HV_X64_MSR_STIMER1_COUNT:
    case HV_X64_MSR_STIMER2_COUNT:
    case HV_X64_MSR_STIMER3_COUNT:
    {
        unsigned int stimerx = (idx - HV_X64_MSR_STIMER0_COUNT) / 2;
        struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[stimerx];

        if ( !(viridian_feature_mask(d) & HVMPV_stimer) )
            return X86EMUL_EXCEPTION;

        stop_stimer(vs);

        vs->count = val;

        if ( !vs->count  )
            vs->config.fields.enabled = 0;
        else if ( vs->config.fields.auto_enable )
            vs->config.fields.enabled = 1;

        if ( vs->config.fields.enabled )
            start_stimer(vs);

        break;
    }
    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x (%016"PRIx64")\n",
                 __func__, idx, val);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_time_rdmsr(const struct vcpu *v, uint32_t idx, uint64_t *val)
{
    struct domain *d = v->domain;

    switch ( idx )
    {
    case HV_X64_MSR_TSC_FREQUENCY:
        if ( viridian_feature_mask(d) & HVMPV_no_freq )
            return X86EMUL_EXCEPTION;

        *val = (uint64_t)d->arch.tsc_khz * 1000ull;
        break;

    case HV_X64_MSR_APIC_FREQUENCY:
        if ( viridian_feature_mask(d) & HVMPV_no_freq )
            return X86EMUL_EXCEPTION;

        *val = 1000000000ull / APIC_BUS_CYCLE_NS;
        break;

    case HV_X64_MSR_REFERENCE_TSC:
        if ( !(viridian_feature_mask(d) & HVMPV_reference_tsc) )
            return X86EMUL_EXCEPTION;

        *val = d->arch.hvm.viridian->reference_tsc.msr.raw;
        break;

    case HV_X64_MSR_TIME_REF_COUNT:
    {
        struct viridian_time_ref_count *trc =
            &d->arch.hvm.viridian->time_ref_count;

        if ( !(viridian_feature_mask(d) & HVMPV_time_ref_count) )
            return X86EMUL_EXCEPTION;

        if ( !test_and_set_bit(_TRC_accessed, &trc->flags) )
            printk(XENLOG_G_INFO "d%d: VIRIDIAN MSR_TIME_REF_COUNT: accessed\n",
                   d->domain_id);

        *val = time_ref_count(d);
        break;
    }

    case HV_X64_MSR_STIMER0_CONFIG:
    case HV_X64_MSR_STIMER1_CONFIG:
    case HV_X64_MSR_STIMER2_CONFIG:
    case HV_X64_MSR_STIMER3_CONFIG:
    {
        unsigned int stimerx = (idx - HV_X64_MSR_STIMER0_CONFIG) / 2;

        if ( !(viridian_feature_mask(d) & HVMPV_stimer) )
            return X86EMUL_EXCEPTION;

        *val = v->arch.hvm.viridian->stimer[stimerx].config.raw;
        break;
    }
    case HV_X64_MSR_STIMER0_COUNT:
    case HV_X64_MSR_STIMER1_COUNT:
    case HV_X64_MSR_STIMER2_COUNT:
    case HV_X64_MSR_STIMER3_COUNT:
    {
        unsigned int stimerx = (idx - HV_X64_MSR_STIMER0_COUNT) / 2;

        if ( !(viridian_feature_mask(d) & HVMPV_stimer) )
            return X86EMUL_EXCEPTION;

        *val = v->arch.hvm.viridian->stimer[stimerx].count;
        break;
    }
    default:
        gdprintk(XENLOG_INFO, "%s: unimplemented MSR %#x\n", __func__, idx);
        return X86EMUL_EXCEPTION;
    }

    return X86EMUL_OKAY;
}

int viridian_time_vcpu_init(struct vcpu *v)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->stimer); i++ )
    {
        struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[i];

        vs->v = v;
        init_timer(&vs->timer, stimer_expire, vs, v->processor);
    }

    return 0;
}

int viridian_time_domain_init(struct domain *d)
{
    return 0;
}

void viridian_time_vcpu_deinit(struct vcpu *v)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->stimer); i++ )
    {
        struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[i];

        kill_timer(&vs->timer);
        vs->v = NULL;
    }
}

void viridian_time_domain_deinit(struct domain *d)
{
    viridian_unmap_guest_page(&d->arch.hvm.viridian->reference_tsc);
}

void viridian_time_save_vcpu_ctxt(
    const struct vcpu *v, struct hvm_viridian_vcpu_context *ctxt)
{
    unsigned int i;

    BUILD_BUG_ON(ARRAY_SIZE(v->arch.hvm.viridian->stimer) !=
                 ARRAY_SIZE(ctxt->stimer_config_msr));
    BUILD_BUG_ON(ARRAY_SIZE(v->arch.hvm.viridian->stimer) !=
                 ARRAY_SIZE(ctxt->stimer_count_msr));

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->stimer); i++ )
    {
        struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[i];

        ctxt->stimer_config_msr[i] = vs->config.raw;
        ctxt->stimer_count_msr[i] = vs->count;
    }
}

void viridian_time_load_vcpu_ctxt(
    struct vcpu *v, const struct hvm_viridian_vcpu_context *ctxt)
{
    unsigned int i;

    for ( i = 0; i < ARRAY_SIZE(v->arch.hvm.viridian->stimer); i++ )
    {
        struct viridian_stimer *vs = &v->arch.hvm.viridian->stimer[i];

        vs->config.raw = ctxt->stimer_config_msr[i];
        vs->count = ctxt->stimer_count_msr[i];
    }
}

void viridian_time_save_domain_ctxt(
    const struct domain *d, struct hvm_viridian_domain_context *ctxt)
{
    ctxt->time_ref_count = d->arch.hvm.viridian->time_ref_count.val;
    ctxt->reference_tsc = d->arch.hvm.viridian->reference_tsc.msr.raw;
}

void viridian_time_load_domain_ctxt(
    struct domain *d, const struct hvm_viridian_domain_context *ctxt)
{
    d->arch.hvm.viridian->time_ref_count.val = ctxt->time_ref_count;
    d->arch.hvm.viridian->reference_tsc.msr.raw = ctxt->reference_tsc;

    if ( d->arch.hvm.viridian->reference_tsc.msr.fields.enabled )
    {
        viridian_map_guest_page(d, &d->arch.hvm.viridian->reference_tsc);
        update_reference_tsc(d, false);
    }
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

/******************************************************************************
 * arch/x86/hpet.c
 *
 * HPET management.
 */

#include <xen/lib.h>
#include <xen/init.h>
#include <xen/cpuidle.h>
#include <xen/errno.h>
#include <xen/softirq.h>
#include <xen/param.h>
#include <xen/sched.h>

#include <mach_apic.h>

#include <asm/fixmap.h>
#include <asm/div64.h>
#include <asm/hpet.h>

#define MAX_DELTA_NS MILLISECS(10*1000)
#define MIN_DELTA_NS MICROSECS(20)

#define HPET_EVT_DISABLE_BIT 1
#define HPET_EVT_DISABLE    (1 << HPET_EVT_DISABLE_BIT)
#define HPET_EVT_LEGACY_BIT  2
#define HPET_EVT_LEGACY     (1 << HPET_EVT_LEGACY_BIT)

struct hpet_event_channel
{
    unsigned long mult;
    int           shift;
    s_time_t      next_event;
    cpumask_var_t cpumask;
    spinlock_t    lock;
    unsigned int idx;   /* physical channel idx */
    unsigned int cpu;   /* msi target */
    struct msi_desc msi;/* msi state */
    unsigned int flags; /* HPET_EVT_x */
} __cacheline_aligned;
static struct hpet_event_channel *__read_mostly hpet_events;

/* msi hpet channels used for broadcast */
static unsigned int __read_mostly num_hpets_used;

/* High-priority vector for HPET interrupts */
static u8 __read_mostly hpet_vector;

/*
 * HPET channel used for idling.  Either the HPET channel this cpu owns
 * (indicated by channel->cpu pointing back), or the HPET channel belonging to
 * another cpu with which we have requested to be woken.
 */
static DEFINE_PER_CPU(struct hpet_event_channel *, hpet_channel);

/* Bitmap of currently-free HPET channels. */
static uint32_t free_channels;

/* Data from the HPET ACPI table */
unsigned long __initdata hpet_address;
int8_t __initdata opt_hpet_legacy_replacement = -1;
static bool __initdata opt_hpet = true;
u8 __initdata hpet_blockid;
u8 __initdata hpet_flags;

/*
 * force_hpet_broadcast: by default legacy hpet broadcast will be stopped
 * if RTC interrupts are enabled. Enable this option if want to always enable
 * legacy hpet broadcast for deep C state
 */
static bool __initdata force_hpet_broadcast;
boolean_param("hpetbroadcast", force_hpet_broadcast);

static int __init cf_check parse_hpet_param(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_bool(s, ss)) >= 0 )
            opt_hpet = val;
        else if ( (val = parse_boolean("broadcast", s, ss)) >= 0 )
            force_hpet_broadcast = val;
        else if ( (val = parse_boolean("legacy-replacement", s, ss)) >= 0 )
            opt_hpet_legacy_replacement = val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("hpet", parse_hpet_param);

/*
 * Calculate a multiplication factor for scaled math, which is used to convert
 * nanoseconds based values to clock ticks:
 *
 * clock_ticks = (nanoseconds * factor) >> shift.
 *
 * div_sc is the rearranged equation to calculate a factor from a given clock
 * ticks / nanoseconds ratio:
 *
 * factor = (clock_ticks << shift) / nanoseconds
 */
static inline unsigned long div_sc(unsigned long ticks, unsigned long nsec,
                                   int shift)
{
    return ((uint64_t)ticks << shift) / nsec;
}

/*
 * Convert nanoseconds based values to clock ticks:
 *
 * clock_ticks = (nanoseconds * factor) >> shift.
 */
static inline unsigned long ns2ticks(unsigned long nsec, int shift,
                                     unsigned long factor)
{
    uint64_t tmp = ((uint64_t)nsec * factor) >> shift;

    return (unsigned long) tmp;
}

/*
 * Program an HPET channels counter relative to now.  'delta' is specified in
 * ticks, and should be calculated with ns2ticks().  The channel lock should
 * be taken and interrupts must be disabled.
 */
static int hpet_set_counter(struct hpet_event_channel *ch, unsigned long delta)
{
    uint32_t cnt, cmp;
    unsigned long flags;

    local_irq_save(flags);
    cnt = hpet_read32(HPET_COUNTER);
    cmp = cnt + delta;
    hpet_write32(cmp, HPET_Tn_CMP(ch->idx));
    cmp = hpet_read32(HPET_COUNTER);
    local_irq_restore(flags);

    /* Are we within two ticks of the deadline passing? Then we may miss. */
    return ((cmp + 2 - cnt) > delta) ? -ETIME : 0;
}

/*
 * Set the time at which an HPET channel should fire.  The channel lock should
 * be held.
 */
static int hpet_program_time(struct hpet_event_channel *ch,
                             s_time_t expire, s_time_t now, int force)
{
    int64_t delta;
    int ret;

    if ( (ch->flags & HPET_EVT_DISABLE) || (expire == 0) )
        return 0;

    if ( unlikely(expire < 0) )
    {
        printk(KERN_DEBUG "reprogram: expire <= 0\n");
        return -ETIME;
    }

    delta = expire - now;
    if ( (delta <= 0) && !force )
        return -ETIME;

    ch->next_event = expire;

    if ( expire == STIME_MAX )
    {
        /* We assume it will take a long time for the timer to wrap. */
        hpet_write32(0, HPET_Tn_CMP(ch->idx));
        return 0;
    }

    delta = min_t(int64_t, delta, MAX_DELTA_NS);
    delta = max_t(int64_t, delta, MIN_DELTA_NS);
    delta = ns2ticks(delta, ch->shift, ch->mult);

    ret = hpet_set_counter(ch, delta);
    while ( ret && force )
    {
        delta += delta;
        ret = hpet_set_counter(ch, delta);
    }

    return ret;
}

/* Wake up all cpus in the channel mask.  Lock should be held. */
static void hpet_wake_cpus(struct hpet_event_channel *ch)
{
    cpuidle_wakeup_mwait(ch->cpumask);
    cpumask_raise_softirq(ch->cpumask, TIMER_SOFTIRQ);
}

/* HPET interrupt handler.  Wake all requested cpus.  Lock should be held. */
static void hpet_interrupt_handler(struct hpet_event_channel *ch)
{
    hpet_wake_cpus(ch);
    raise_softirq(TIMER_SOFTIRQ);
}

/* HPET interrupt entry.  This is set up as a high priority vector. */
static void cf_check do_hpet_irq(struct cpu_user_regs *regs)
{
    struct hpet_event_channel *ch = this_cpu(hpet_channel);

    if ( ch )
    {
        spin_lock(&ch->lock);
        if ( ch->cpu == smp_processor_id() )
        {
            ch->next_event = 0;
            hpet_interrupt_handler(ch);
        }
        spin_unlock(&ch->lock);
    }

    ack_APIC_irq();
}

/* Unmask an HPET MSI channel.  Lock should be held */
static void hpet_msi_unmask(struct hpet_event_channel *ch)
{
    u32 cfg;

    cfg = hpet_read32(HPET_Tn_CFG(ch->idx));
    cfg |= HPET_TN_ENABLE;
    hpet_write32(cfg, HPET_Tn_CFG(ch->idx));
    ch->msi.msi_attrib.host_masked = 0;
}

/* Mask an HPET MSI channel.  Lock should be held */
static void hpet_msi_mask(struct hpet_event_channel *ch)
{
    u32 cfg;

    cfg = hpet_read32(HPET_Tn_CFG(ch->idx));
    cfg &= ~HPET_TN_ENABLE;
    hpet_write32(cfg, HPET_Tn_CFG(ch->idx));
    ch->msi.msi_attrib.host_masked = 1;
}

/*
 * Set up the MSI for an HPET channel to point at the allocated cpu, including
 * interrupt remapping entries when appropriate.  The channel lock is expected
 * to be held, and the MSI must currently be masked.
 */
static int hpet_setup_msi(struct hpet_event_channel *ch)
{
    ASSERT(ch->cpu != -1);
    ASSERT(ch->msi.msi_attrib.host_masked == 1);

    msi_compose_msg(hpet_vector, cpumask_of(ch->cpu), &ch->msi.msg);

    if ( iommu_intremap )
    {
        int rc = iommu_update_ire_from_msi(&ch->msi, &ch->msi.msg);

        if ( rc )
            return rc;
    }

    hpet_write32(ch->msi.msg.data, HPET_Tn_ROUTE(ch->idx));
    hpet_write32(ch->msi.msg.address_lo, HPET_Tn_ROUTE(ch->idx) + 4);

    return 0;
}

static int __init hpet_init_msi(struct hpet_event_channel *ch)
{
    int ret;
    u32 cfg = hpet_read32(HPET_Tn_CFG(ch->idx));

    if ( iommu_intremap )
    {
        ch->msi.hpet_id = hpet_blockid;
        ret = iommu_setup_hpet_msi(&ch->msi);
        if ( ret )
            return ret;
    }

    /* set HPET Tn as oneshot */
    cfg &= ~(HPET_TN_LEVEL | HPET_TN_PERIODIC | HPET_TN_ENABLE);
    cfg |= HPET_TN_FSB | HPET_TN_32BIT;
    hpet_write32(cfg, HPET_Tn_CFG(ch->idx));
    ch->msi.msi_attrib.host_masked = 1;

    return 0;
}

static void __init hpet_init_channel(struct hpet_event_channel *ch)
{
    u64 hpet_rate = hpet_setup();

    /*
     * The period is a femto seconds value. We need to calculate the scaled
     * math multiplication factor for nanosecond to hpet tick conversion.
     */
    ch->mult = div_sc((unsigned long)hpet_rate,
                                     1000000000ul, 32);
    ch->shift = 32;
    ch->next_event = STIME_MAX;
    spin_lock_init(&ch->lock);

    ch->msi.irq = -1;
    ch->msi.msi_attrib.maskbit = 1;
    ch->msi.msi_attrib.pos = MSI_TYPE_HPET;
}

static void __init hpet_fsb_cap_lookup(void)
{
    u32 id;
    unsigned int i, num_chs;

    if ( unlikely(acpi_gbl_FADT.boot_flags & ACPI_FADT_NO_MSI) )
        return;

    id = hpet_read32(HPET_ID);

    num_chs = ((id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT);
    num_chs++; /* Value read out starts from 0 */

    hpet_events = xzalloc_array(struct hpet_event_channel, num_chs);
    if ( !hpet_events )
        return;

    alloc_direct_apic_vector(&hpet_vector, do_hpet_irq);

    for ( i = 0; i < num_chs && num_hpets_used < nr_cpu_ids; i++ )
    {
        struct hpet_event_channel *ch = &hpet_events[num_hpets_used];
        u32 cfg = hpet_read32(HPET_Tn_CFG(i));

        /* Only consider HPET timer with MSI support */
        if ( !(cfg & HPET_TN_FSB_CAP) )
            continue;

        if ( !zalloc_cpumask_var(&ch->cpumask) )
        {
            if ( !num_hpets_used )
            {
                xfree(hpet_events);
                hpet_events = NULL;
            }
            break;
        }

        hpet_init_channel(ch);

        ch->flags = 0;
        ch->idx = i;

        if ( hpet_init_msi(ch) == 0 )
            num_hpets_used++;
        else
            free_cpumask_var(ch->cpumask);
    }

    printk(XENLOG_INFO "HPET: %u timers usable for broadcast (%u total)\n",
           num_hpets_used, num_chs);
}

/*
 * Search for, and allocate, a free HPET channel.  Returns a pointer to the
 * channel, or NULL in the case that none were free.  The caller is
 * responsible for returning the channel to the free pool.
 */
static struct hpet_event_channel *hpet_get_free_channel(void)
{
    unsigned ch, tries;

    for ( tries = num_hpets_used; tries; --tries )
    {
        if ( (ch = ffs(free_channels)) == 0 )
            break;

        --ch;
        ASSERT(ch < num_hpets_used);

        if ( test_and_clear_bit(ch, &free_channels) )
            return &hpet_events[ch];
    }

    return NULL;
}

#include <asm/mc146818rtc.h>

void (*__read_mostly pv_rtc_handler)(uint8_t index, uint8_t value);

static void cf_check handle_rtc_once(uint8_t index, uint8_t value)
{
    if ( index != RTC_REG_B )
        return;

    /* RTC Reg B, contain PIE/AIE/UIE */
    if ( value & (RTC_PIE | RTC_AIE | RTC_UIE ) )
    {
        cpuidle_disable_deep_cstate();
        ACCESS_ONCE(pv_rtc_handler) = NULL;
    }
}

void __init hpet_broadcast_init(void)
{
    u64 hpet_rate = hpet_setup();
    u32 hpet_id, cfg;

    if ( hpet_rate == 0 || hpet_broadcast_is_available() )
        return;

    cfg = hpet_read32(HPET_CFG);

    hpet_fsb_cap_lookup();
    if ( num_hpets_used > 0 )
    {
        /* Stop HPET legacy interrupts */
        cfg &= ~HPET_CFG_LEGACY;
        free_channels = (u32)~0 >> (32 - num_hpets_used);
    }
    else
    {
        hpet_id = hpet_read32(HPET_ID);
        if ( !(hpet_id & HPET_ID_LEGSUP) )
            return;

        if ( !hpet_events )
            hpet_events = xzalloc(struct hpet_event_channel);
        if ( !hpet_events || !zalloc_cpumask_var(&hpet_events->cpumask) )
            return;

        hpet_init_channel(hpet_events);

        /* Start HPET legacy interrupts */
        cfg |= HPET_CFG_LEGACY;

        hpet_events->flags = HPET_EVT_LEGACY;

        if ( !force_hpet_broadcast )
            pv_rtc_handler = handle_rtc_once;
    }

    hpet_write32(cfg, HPET_CFG);

    if ( cfg & HPET_CFG_LEGACY )
    {
        /* set HPET T0 as oneshot */
        cfg = hpet_read32(HPET_Tn_CFG(0));
        cfg &= ~(HPET_TN_LEVEL | HPET_TN_PERIODIC);
        cfg |= HPET_TN_ENABLE | HPET_TN_32BIT;
        hpet_write32(cfg, HPET_Tn_CFG(0));
    }
}

void hpet_broadcast_resume(void)
{
    u32 cfg;
    unsigned int i, n;

    if ( !hpet_events )
        return;

    hpet_resume(NULL);

    cfg = hpet_read32(HPET_CFG);

    if ( num_hpets_used > 0 )
    {
        /* Stop HPET legacy interrupts */
        cfg &= ~HPET_CFG_LEGACY;
        n = num_hpets_used;
    }
    else if ( hpet_events->flags & HPET_EVT_DISABLE )
        return;
    else
    {
        /* Start HPET legacy interrupts */
        cfg |= HPET_CFG_LEGACY;
        n = 1;
    }

    hpet_write32(cfg, HPET_CFG);

    for ( i = 0; i < n; i++ )
    {
        /* set HPET Tn as oneshot */
        cfg = hpet_read32(HPET_Tn_CFG(hpet_events[i].idx));
        cfg &= ~(HPET_TN_LEVEL | HPET_TN_PERIODIC);
        cfg |= HPET_TN_32BIT;

        /*
         * Legacy HPET channel enabled here.  MSI channels enabled in
         * hpet_broadcast_init() when claimed by a cpu.
         */
        if ( hpet_events[i].flags & HPET_EVT_LEGACY )
            cfg |= HPET_TN_ENABLE;
        else
        {
            cfg &= ~HPET_TN_ENABLE;
            cfg |= HPET_TN_FSB;
            hpet_events[i].msi.msi_attrib.host_masked = 1;
        }

        hpet_write32(cfg, HPET_Tn_CFG(hpet_events[i].idx));

        hpet_events[i].next_event = STIME_MAX;
    }
}

void hpet_disable_legacy_broadcast(void)
{
    u32 cfg;
    unsigned long flags;

    if ( !hpet_events || !(hpet_events->flags & HPET_EVT_LEGACY) )
        return;

    spin_lock_irqsave(&hpet_events->lock, flags);

    hpet_events->flags |= HPET_EVT_DISABLE;

    /* disable HPET T0 */
    cfg = hpet_read32(HPET_Tn_CFG(0));
    cfg &= ~HPET_TN_ENABLE;
    hpet_write32(cfg, HPET_Tn_CFG(0));

    /* Stop HPET legacy interrupts */
    cfg = hpet_read32(HPET_CFG);
    cfg &= ~HPET_CFG_LEGACY;
    hpet_write32(cfg, HPET_CFG);

    spin_unlock_irqrestore(&hpet_events->lock, flags);

    smp_send_event_check_mask(&cpu_online_map);
}

void cf_check hpet_broadcast_enter(void)
{
    unsigned int cpu = smp_processor_id();
    struct hpet_event_channel *ch = per_cpu(hpet_channel, cpu);
    s_time_t deadline = per_cpu(timer_deadline, cpu);

    ASSERT(!local_irq_is_enabled());
    ASSERT(ch == NULL);

    if ( deadline == 0 )
        return;

    /* If using HPET in legacy timer mode */
    if ( num_hpets_used == 0 )
    {
        spin_lock(&hpet_events->lock);

        cpumask_set_cpu(cpu, hpet_events->cpumask);
        if ( deadline < hpet_events->next_event )
            hpet_program_time(hpet_events, deadline, NOW(), 1);

        spin_unlock(&hpet_events->lock);
        return;
    }

retry_free_channel:
    ch = hpet_get_free_channel();

    if ( ch )
    {
        spin_lock(&ch->lock);

        /* This really should be an MSI channel by this point */
        ASSERT(!(ch->flags & HPET_EVT_LEGACY));

        hpet_msi_mask(ch);

        ch->cpu = cpu;
        this_cpu(hpet_channel) = ch;
        cpumask_set_cpu(cpu, ch->cpumask);

        hpet_setup_msi(ch);
        hpet_program_time(ch, deadline, NOW(), 1);
        hpet_msi_unmask(ch);

        spin_unlock(&ch->lock);
    }
    else
    {
        s_time_t best_early_deadline = 0, best_late_deadline = STIME_MAX;
        unsigned int i, best_early_idx = -1, best_late_idx = -1;

        for ( i = 0; i < num_hpets_used; ++i )
        {
            ch = &hpet_events[i];
            spin_lock(&ch->lock);

            if ( ch->cpu == -1 )
                goto continue_search;

            /* This channel is going to expire early */
            if ( ch->next_event < deadline )
            {
                if ( ch->next_event > best_early_deadline )
                {
                    best_early_idx = i;
                    best_early_deadline = ch->next_event;
                }
                goto continue_search;
            }

            /* We can deal with being woken up 20us late */
            if ( ch->next_event <= deadline + MICROSECS(20) )
                break;

            /* Otherwise record the best late channel to program forwards */
            if ( ch->next_event <= best_late_deadline )
            {
                best_late_idx = i;
                best_late_deadline = ch->next_event;
            }

        continue_search:
            spin_unlock(&ch->lock);
            ch = NULL;
        }

        if ( ch )
        {
            /* Found HPET with an appropriate time.  Request to be woken up */
            cpumask_set_cpu(cpu, ch->cpumask);
            this_cpu(hpet_channel) = ch;
            spin_unlock(&ch->lock);
            goto done_searching;
        }

        /* Try and program the best late channel forwards a bit */
        if ( best_late_deadline < STIME_MAX && best_late_idx != -1 )
        {
            ch = &hpet_events[best_late_idx];
            spin_lock(&ch->lock);

            /* If this is still the same channel, good */
            if ( ch->next_event == best_late_deadline )
            {
                cpumask_set_cpu(cpu, ch->cpumask);
                hpet_program_time(ch, deadline, NOW(), 1);
                spin_unlock(&ch->lock);
                goto done_searching;
            }
            /* else it has fired and changed ownership. */
            else
            {
                spin_unlock(&ch->lock);
                goto retry_free_channel;
            }
        }

        /* Try to piggyback on an early channel in the hope that when we
           wake back up, our fortunes will improve. */
        if ( best_early_deadline > 0 && best_early_idx != -1 )
        {
            ch = &hpet_events[best_early_idx];
            spin_lock(&ch->lock);

            /* If this is still the same channel, good */
            if ( ch->next_event == best_early_deadline )
            {
                cpumask_set_cpu(cpu, ch->cpumask);
                spin_unlock(&ch->lock);
                goto done_searching;
            }
            /* else it has fired and changed ownership. */
            else
            {
                spin_unlock(&ch->lock);
                goto retry_free_channel;
            }
        }

        /* All else has failed, and we have wasted some time searching.
         * See whether another channel has become free. */
        goto retry_free_channel;
    }

done_searching:

    /* Disable LAPIC timer interrupts. */
    disable_APIC_timer();
}

void cf_check hpet_broadcast_exit(void)
{
    unsigned int cpu = smp_processor_id();
    struct hpet_event_channel *ch = this_cpu(hpet_channel);
    s_time_t deadline = per_cpu(timer_deadline, cpu);

    ASSERT(local_irq_is_enabled());

    if ( deadline == 0 )
        return;

    /* If using HPET in legacy timer mode */
    if ( num_hpets_used == 0 )
    {
        /* This is safe without the spinlock, and will reduce contention. */
        cpumask_clear_cpu(cpu, hpet_events->cpumask);
        return;
    }

    if ( !ch )
        return;

    spin_lock_irq(&ch->lock);

    cpumask_clear_cpu(cpu, ch->cpumask);

    /* If we own the channel, detach it */
    if ( ch->cpu == cpu )
    {
        hpet_msi_mask(ch);
        hpet_wake_cpus(ch);
        ch->cpu = -1;
        set_bit(ch->idx, &free_channels);
    }

    this_cpu(hpet_channel) = NULL;

    spin_unlock_irq(&ch->lock);

    /* Reprogram the deadline; trigger timer work now if it has passed. */
    enable_APIC_timer();
    if ( !reprogram_timer(deadline) )
        raise_softirq(TIMER_SOFTIRQ);
}

int hpet_broadcast_is_available(void)
{
    return ((hpet_events && (hpet_events->flags & HPET_EVT_LEGACY))
            || num_hpets_used > 0);
}

int hpet_legacy_irq_tick(void)
{
    this_cpu(irq_count)--;

    if ( !hpet_events ||
         (hpet_events->flags & (HPET_EVT_DISABLE|HPET_EVT_LEGACY)) !=
         HPET_EVT_LEGACY )
        return 0;

    spin_lock_irq(&hpet_events->lock);

    hpet_interrupt_handler(hpet_events);
    hpet_events->next_event = STIME_MAX;

    spin_unlock_irq(&hpet_events->lock);

    return 1;
}

static u32 *hpet_boot_cfg;
static uint64_t __initdata hpet_rate;
static __initdata struct {
    uint32_t cmp, cfg;
} pre_legacy_c0;

bool __init hpet_enable_legacy_replacement_mode(void)
{
    unsigned int cfg, c0_cfg, ticks, count;

    if ( !hpet_rate ||
         !(hpet_read32(HPET_ID) & HPET_ID_LEGSUP) ||
         ((cfg = hpet_read32(HPET_CFG)) & HPET_CFG_LEGACY) )
        return false;

    /* Stop the main counter. */
    hpet_write32(cfg & ~HPET_CFG_ENABLE, HPET_CFG);

    /* Stash channel 0's old CFG/CMP incase we need to undo. */
    pre_legacy_c0.cfg = c0_cfg = hpet_read32(HPET_Tn_CFG(0));
    pre_legacy_c0.cmp = hpet_read32(HPET_Tn_CMP(0));

    /* Reconfigure channel 0 to be 32bit periodic. */
    c0_cfg |= (HPET_TN_ENABLE | HPET_TN_PERIODIC | HPET_TN_SETVAL |
               HPET_TN_32BIT);
    hpet_write32(c0_cfg, HPET_Tn_CFG(0));

    /*
     * The exact period doesn't have to match a legacy PIT.  All we need
     * is an interrupt queued up via the IO-APIC to check routing.
     *
     * Use HZ as the frequency.
     */
    ticks = ((SECONDS(1) / HZ) * div_sc(hpet_rate, SECONDS(1), 32)) >> 32;

    count = hpet_read32(HPET_COUNTER);

    /*
     * HPET_TN_SETVAL above is atrociously documented in the spec.
     *
     * Periodic HPET channels have a main comparator register, and
     * separate "accumulator" register.  Despite being named accumulator
     * in the spec, this is not an accurate description of its behaviour
     * or purpose.
     *
     * Each time an interrupt is generated, the "accumulator" register is
     * re-added to the comparator set up the new period.
     *
     * Normally, writes to the CMP register update both registers.
     * However, under these semantics, it is impossible to set up a
     * periodic timer correctly without the main HPET counter being at 0.
     *
     * Instead, HPET_TN_SETVAL is a self-clearing control bit which we can
     * use for periodic timers to mean that the second write to CMP
     * updates the accumulator only, and not the absolute comparator
     * value.
     *
     * This lets us set a period when the main counter isn't at 0.
     */
    hpet_write32(count + ticks, HPET_Tn_CMP(0));
    hpet_write32(ticks,         HPET_Tn_CMP(0));

    /* Restart the main counter, and legacy mode. */
    hpet_write32(cfg | HPET_CFG_ENABLE | HPET_CFG_LEGACY, HPET_CFG);

    return true;
}

void __init hpet_disable_legacy_replacement_mode(void)
{
    unsigned int cfg = hpet_read32(HPET_CFG);

    ASSERT(hpet_rate);

    cfg &= ~(HPET_CFG_LEGACY | HPET_CFG_ENABLE);

    /* Stop the main counter and disable legacy mode. */
    hpet_write32(cfg, HPET_CFG);

    /* Restore pre-Legacy Replacement Mode settings. */
    hpet_write32(pre_legacy_c0.cfg, HPET_Tn_CFG(0));
    hpet_write32(pre_legacy_c0.cmp, HPET_Tn_CMP(0));

    /* Restart the main counter. */
    hpet_write32(cfg | HPET_CFG_ENABLE, HPET_CFG);
}

u64 __init hpet_setup(void)
{
    unsigned int hpet_id, hpet_period;
    unsigned int last, rem;

    if ( hpet_rate || !hpet_address || !opt_hpet )
        return hpet_rate;

    set_fixmap_nocache(FIX_HPET_BASE, hpet_address);

    hpet_id = hpet_read32(HPET_ID);
    if ( (hpet_id & HPET_ID_REV) == 0 )
    {
        printk("BAD HPET revision id.\n");
        return 0;
    }

    /* Check for sane period (100ps <= period <= 100ns). */
    hpet_period = hpet_read32(HPET_PERIOD);
    if ( (hpet_period > 100000000) || (hpet_period < 100000) )
    {
        printk("BAD HPET period %u.\n", hpet_period);
        return 0;
    }

    last = (hpet_id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT;
    hpet_boot_cfg = xmalloc_array(u32, 2 + last);
    hpet_resume(hpet_boot_cfg);

    hpet_rate = 1000000000000000ULL; /* 10^15 */
    rem = do_div(hpet_rate, hpet_period);
    if ( (rem * 2) > hpet_period )
        hpet_rate++;

    if ( opt_hpet_legacy_replacement > 0 )
        hpet_enable_legacy_replacement_mode();

    return hpet_rate;
}

void hpet_resume(u32 *boot_cfg)
{
    static u32 system_reset_latch;
    u32 hpet_id, cfg;
    unsigned int i, last;

    if ( system_reset_latch == system_reset_counter )
        return;
    system_reset_latch = system_reset_counter;

    cfg = hpet_read32(HPET_CFG);
    if ( boot_cfg )
        *boot_cfg = cfg;
    cfg &= ~(HPET_CFG_ENABLE | HPET_CFG_LEGACY);
    if ( cfg )
    {
        printk(XENLOG_WARNING
               "HPET: reserved bits %#x set in global config register\n",
               cfg);
        cfg = 0;
    }
    hpet_write32(cfg, HPET_CFG);

    hpet_id = hpet_read32(HPET_ID);
    last = (hpet_id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT;
    for ( i = 0; i <= last; ++i )
    {
        cfg = hpet_read32(HPET_Tn_CFG(i));
        if ( boot_cfg )
            boot_cfg[i + 1] = cfg;
        cfg &= ~HPET_TN_ENABLE;
        if ( cfg & HPET_TN_RESERVED )
        {
            printk(XENLOG_WARNING
                   "HPET: reserved bits %#x set in channel %u config register\n",
                   cfg & HPET_TN_RESERVED, i);
            cfg &= ~HPET_TN_RESERVED;
        }
        hpet_write32(cfg, HPET_Tn_CFG(i));
    }

    cfg = hpet_read32(HPET_CFG);
    cfg |= HPET_CFG_ENABLE;
    hpet_write32(cfg, HPET_CFG);
}

void hpet_disable(void)
{
    unsigned int i;
    u32 id;

    if ( !hpet_boot_cfg )
    {
        if ( hpet_broadcast_is_available() )
            hpet_disable_legacy_broadcast();
        return;
    }

    hpet_write32(*hpet_boot_cfg & ~HPET_CFG_ENABLE, HPET_CFG);

    id = hpet_read32(HPET_ID);
    for ( i = 0; i <= ((id & HPET_ID_NUMBER) >> HPET_ID_NUMBER_SHIFT); ++i )
        hpet_write32(hpet_boot_cfg[i + 1], HPET_Tn_CFG(i));

    if ( *hpet_boot_cfg & HPET_CFG_ENABLE )
        hpet_write32(*hpet_boot_cfg, HPET_CFG);
}

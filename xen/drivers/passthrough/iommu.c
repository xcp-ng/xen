/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/sched.h>
#include <xen/iommu.h>
#include <xen/paging.h>
#include <xen/guest_access.h>
#include <xen/event.h>
#include <xen/param.h>
#include <xen/softirq.h>
#include <xen/keyhandler.h>
#include <xsm/xsm.h>
#include <xen/lockdown.h>

#ifdef CONFIG_X86
#include <asm/e820.h>
#endif

unsigned int __read_mostly iommu_dev_iotlb_timeout = 1000;
integer_param("iommu_dev_iotlb_timeout", iommu_dev_iotlb_timeout);

bool __initdata iommu_enable = 1;
bool __read_mostly iommu_enabled;
bool __read_mostly force_iommu;
bool __read_mostly iommu_verbose;
static bool __read_mostly iommu_crash_disable;

#define IOMMU_quarantine_none         0 /* aka false */
#define IOMMU_quarantine_basic        1 /* aka true */
#define IOMMU_quarantine_scratch_page 2
#ifdef CONFIG_HAS_PCI
uint8_t __read_mostly iommu_quarantine =
# if defined(CONFIG_IOMMU_QUARANTINE_NONE)
    IOMMU_quarantine_none;
# elif defined(CONFIG_IOMMU_QUARANTINE_BASIC)
    IOMMU_quarantine_basic;
# elif defined(CONFIG_IOMMU_QUARANTINE_SCRATCH_PAGE)
    IOMMU_quarantine_scratch_page;
# endif
#else
# define iommu_quarantine IOMMU_quarantine_none
#endif /* CONFIG_HAS_PCI */

static bool __hwdom_initdata iommu_hwdom_none;
bool __hwdom_initdata iommu_hwdom_strict;
bool __read_mostly iommu_hwdom_passthrough;
bool __hwdom_initdata iommu_hwdom_inclusive;
bool __read_mostly iommu_hwdom_no_dma = false;
int8_t __hwdom_initdata iommu_hwdom_reserved = -1;

#ifndef iommu_hap_pt_share
bool __read_mostly iommu_hap_pt_share = true;
#endif

bool __read_mostly iommu_debug;

DEFINE_PER_CPU(bool, iommu_dont_flush_iotlb);

static int __init cf_check parse_iommu_param(const char *s)
{
    const char *ss;
    int val, rc = 0;

    do {
        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_bool(s, ss)) >= 0 )
            iommu_enable = val;
        else if ( (val = parse_boolean("force", s, ss)) >= 0 ||
                  (val = parse_boolean("required", s, ss)) >= 0 )
            force_iommu = val;
#ifdef CONFIG_HAS_PCI
        else if ( (val = parse_boolean("quarantine", s, ss)) >= 0 )
            iommu_quarantine = val;
        else if ( ss == s + 23 && !strncmp(s, "quarantine=scratch-page", 23) )
            iommu_quarantine = IOMMU_quarantine_scratch_page;
#endif
        else if ( (val = parse_boolean("igfx", s, ss)) >= 0 )
#ifdef CONFIG_INTEL_IOMMU
            iommu_igfx = val;
#else
            no_config_param("INTEL_IOMMU", "iommu", s, ss);
#endif
        else if ( (val = parse_boolean("qinval", s, ss)) >= 0 )
#ifdef CONFIG_INTEL_IOMMU
            iommu_qinval = val;
#else
            no_config_param("INTEL_IOMMU", "iommu", s, ss);
#endif
#ifdef CONFIG_X86
        else if ( (val = parse_boolean("superpages", s, ss)) >= 0 )
            iommu_superpages = val;
#endif
        else if ( (val = parse_boolean("verbose", s, ss)) >= 0 )
            iommu_verbose = val;
#ifndef iommu_snoop
        else if ( (val = parse_boolean("snoop", s, ss)) >= 0 )
            iommu_snoop = val;
#endif
#ifndef iommu_intremap
        else if ( (val = parse_boolean("intremap", s, ss)) >= 0 )
            iommu_intremap = val ? iommu_intremap_full : iommu_intremap_off;
#endif
#ifndef iommu_intpost
        else if ( (val = parse_boolean("intpost", s, ss)) >= 0 )
            iommu_intpost = val;
#endif
#ifdef CONFIG_KEXEC
        else if ( (val = parse_boolean("crash-disable", s, ss)) >= 0 )
            iommu_crash_disable = val;
#endif
        else if ( (val = parse_boolean("debug", s, ss)) >= 0 )
        {
            iommu_debug = val;
            if ( val )
                iommu_verbose = 1;
        }
        else if ( (val = parse_boolean("amd-iommu-perdev-intremap", s, ss)) >= 0 )
#ifdef CONFIG_AMD_IOMMU
            amd_iommu_perdev_intremap = val;
#else
            no_config_param("AMD_IOMMU", "iommu", s, ss);
#endif
        else if ( (val = parse_boolean("dom0-passthrough", s, ss)) >= 0 )
            iommu_hwdom_passthrough = val;
        else if ( (val = parse_boolean("dom0-strict", s, ss)) >= 0 )
            iommu_hwdom_strict = val;
#ifndef iommu_hap_pt_share
        else if ( (val = parse_boolean("sharept", s, ss)) >= 0 )
            iommu_hap_pt_share = val;
#endif
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("iommu", parse_iommu_param);

static int __init cf_check parse_dom0_iommu_param(const char *s)
{
    const char *ss;
    int rc = 0;

    do {
        int val;

        ss = strchr(s, ',');
        if ( !ss )
            ss = strchr(s, '\0');

        if ( (val = parse_boolean("passthrough", s, ss)) >= 0 )
            iommu_hwdom_passthrough = val;
        else if ( (val = parse_boolean("strict", s, ss)) >= 0 )
            iommu_hwdom_strict = val;
        else if ( (val = parse_boolean("map-inclusive", s, ss)) >= 0 )
            iommu_hwdom_inclusive = val;
        else if ( (val = parse_boolean("map-reserved", s, ss)) >= 0 )
            iommu_hwdom_reserved = val;
        else if ( !cmdline_strcmp(s, "none") )
            iommu_hwdom_none = true;
        else if ( (val = parse_boolean("dma", s, ss)) >= 0 )
            iommu_hwdom_no_dma = !val;
        else
            rc = -EINVAL;

        s = ss + 1;
    } while ( *ss );

    return rc;
}
custom_param("dom0-iommu", parse_dom0_iommu_param);

static void __hwdom_init check_hwdom_reqs(struct domain *d)
{
    d->iommu.no_dma = iommu_hwdom_no_dma;

    if ( iommu_hwdom_none || !is_hvm_domain(d) )
        return;

    iommu_hwdom_passthrough = false;
    iommu_hwdom_strict = true;

    arch_iommu_check_autotranslated_hwdom(d);
}


int iommu_domain_pviommu_init(struct domain *d, uint16_t nb_ctx, uint32_t arena_order)
{
    struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( nb_ctx == 0 ) /* sanity check (prevent underflow) */
        return -EINVAL;

    /*
     * hd->other_contexts.count is always reported as 0 during initialization
     * preventing misuse of partially initialized IOMMU contexts.
     */

    if ( atomic_cmpxchg(&hd->other_contexts.initialized, 0, 1) == 1 )
        return -EACCES;

    if ( (nb_ctx - 1) > 0 ) {
        /* Initialize context bitmap */
        size_t i;

        hd->other_contexts.bitmap = xzalloc_array(unsigned long,
                                                  BITS_TO_LONGS(nb_ctx - 1));

        if (!hd->other_contexts.bitmap)
        {
            rc = -ENOMEM;
            goto cleanup;
        }

        hd->other_contexts.map = xzalloc_array(struct iommu_context, nb_ctx - 1);

        if (!hd->other_contexts.map)
        {
            rc = -ENOMEM;
            goto cleanup;
        }

        for (i = 0; i < (nb_ctx - 1); i++)
            rspin_lock_init(&hd->other_contexts.map[i].lock);
    }

    rc = arch_iommu_pviommu_init(d, nb_ctx, arena_order);

    if ( rc )
        goto cleanup;

    /* Make sure initialization is complete before making it visible to other CPUs. */
    smp_wmb();

    hd->other_contexts.count = nb_ctx - 1;

    printk(XENLOG_INFO "Dom%d uses %lu IOMMU contexts (%llu pages arena)\n",
           d->domain_id, (unsigned long)nb_ctx, 1llu << arena_order);

    return 0;

cleanup:
    /* TODO: Reset hd->other_contexts.initialized */
    if ( hd->other_contexts.bitmap )
    {
        xfree(hd->other_contexts.bitmap);
        hd->other_contexts.bitmap = NULL;
    }

    if ( hd->other_contexts.map )
    {
        xfree(hd->other_contexts.map);
        hd->other_contexts.bitmap = NULL;
    }

    return rc;
}

int iommu_domain_pviommu_teardown(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    int i;
    /* FIXME: Potential race condition with remote_op ? */

    for (i = 0; i < hd->other_contexts.count; i++)
        WARN_ON(iommu_context_free(d, i, IOMMU_TEARDOWN_REATTACH_DEFAULT) != ENOENT);

    hd->other_contexts.count = 0;

    if ( hd->other_contexts.bitmap )
        xfree(hd->other_contexts.bitmap);

    if ( hd->other_contexts.map )
        xfree(hd->other_contexts.map);

    return 0;
}

int iommu_domain_init(struct domain *d, unsigned int opts)
{
    struct domain_iommu *hd = dom_iommu(d);
    int ret = 0;

    if ( is_hardware_domain(d) )
        check_hwdom_reqs(d); /* may modify iommu_hwdom_strict */

    if ( !is_iommu_enabled(d) )
        return 0;

#ifdef CONFIG_NUMA
    hd->node = NUMA_NO_NODE;
#endif

    rspin_lock_init(&hd->default_ctx.lock);

    ret = arch_iommu_domain_init(d);
    if ( ret )
        return ret;

    hd->platform_ops = iommu_get_ops();
    ret = iommu_call(hd->platform_ops, init, d);
    if ( ret || (is_system_domain(d) && d != dom_io) )
        return ret;

    /*
     * Use shared page tables for HAP and IOMMU if the global option
     * is enabled (from which we can infer the h/w is capable) and
     * the domain options do not disallow it. HAP must, of course, also
     * be enabled.
     */
    hd->hap_pt_share = hap_enabled(d) && iommu_hap_pt_share &&
        !(opts & XEN_DOMCTL_IOMMU_no_sharept);

    /*
     * NB: 'relaxed' h/w domains don't need the IOMMU mappings to be kept
     *     in-sync with their assigned pages because all host RAM will be
     *     mapped during hwdom_init().
     */
    if ( !is_hardware_domain(d) || iommu_hwdom_strict )
        hd->need_sync = !iommu_use_hap_pt(d);

    if ( hd->no_dma )
    {
        /* No-DMA mode is exclusive with HAP and sync_pt. */
        hd->hap_pt_share = false;
        hd->need_sync = false;
    }

    ASSERT(!(hd->need_sync && hd->hap_pt_share));

    hd->allow_pv_iommu = true;

    rspin_lock(&hd->default_ctx.lock);
    ret = iommu_context_init(d, &hd->default_ctx, 0, IOMMU_CONTEXT_INIT_default);
    rspin_unlock(&hd->default_ctx.lock);

    rwlock_init(&hd->other_contexts.lock);
    hd->other_contexts.initialized = (atomic_t)ATOMIC_INIT(0);
    hd->other_contexts.count = 0;
    hd->other_contexts.bitmap = NULL;
    hd->other_contexts.map = NULL;

    return ret;
}

static void cf_check iommu_dump_page_tables(unsigned char key)
{
    struct domain *d;

    ASSERT(iommu_enabled);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain(d)
    {
        if ( !is_iommu_enabled(d) )
            continue;

        if ( iommu_use_hap_pt(d) )
            printk("%pd sharing page tables\n", d);

        iommu_vcall(dom_iommu(d)->platform_ops, dump_page_tables, d);
    }

    rcu_read_unlock(&domlist_read_lock);
}

void __hwdom_init iommu_hwdom_init(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !is_iommu_enabled(d) )
        return;

    iommu_vcall(hd->platform_ops, hwdom_init, d);
}

void cf_check iommu_domain_destroy(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);
    struct pci_dev *pdev;

    if ( !is_iommu_enabled(d) )
        return;

    /*
     * During early domain creation failure, we may reach here with the
     * ops not yet initialized.
     */
    if ( !hd->platform_ops )
        return;

    /* Move all devices back to quarantine */
    /* TODO: Is it needed ? */
    for_each_pdev(d, pdev)
    {
        int rc = iommu_reattach_context(d, dom_io, pdev, 0);

        if ( rc )
        {
            printk(XENLOG_WARNING "Unable to quarantine device %pp (%d)\n", &pdev->sbdf, rc);
            pdev->broken = true;
        }
        else
            pdev->domain = dom_io;
    }

    iommu_vcall(hd->platform_ops, teardown, d);

    arch_iommu_domain_destroy(d);
}

bool cf_check iommu_check_context(struct domain *d, uint16_t ctx_id) {
    struct domain_iommu *hd = dom_iommu(d);

    if ( ctx_id == 0 )
        return true; /* Default context always exist. */

    if ( (ctx_id - 1) >= hd->other_contexts.count )
        return false; /* out of bounds */

    if ( ctx_id == IOMMU_INVALID_CONTEXT_ID )
        return false; /* Invalid ID */

    return test_bit(ctx_id - 1, hd->other_contexts.bitmap);
}

struct iommu_context * cf_check iommu_get_context(struct domain *d, uint16_t ctx_id) {
    struct domain_iommu *hd = dom_iommu(d);
    struct iommu_context *ctx;

    if ( !iommu_check_context(d, ctx_id) )
        return NULL;

    if (ctx_id == 0)
        ctx = &hd->default_ctx;
    else
        ctx = &hd->other_contexts.map[ctx_id - 1];

    rspin_lock(&ctx->lock);
    /* Check if the context is still valid at this point */
    if ( unlikely(!iommu_check_context(d, ctx_id)) )
    {
        /* Context has been destroyed in between */
        rspin_unlock(&ctx->lock);
        return NULL;
    }

    return ctx;
}

void cf_check iommu_put_context(struct iommu_context *ctx)
{
    rspin_unlock(&ctx->lock);
}

static unsigned int mapping_order(const struct domain_iommu *hd,
                                  dfn_t dfn, mfn_t mfn, unsigned long nr)
{
    unsigned long res = dfn_x(dfn) | mfn_x(mfn);
    unsigned long sizes = hd->platform_ops->page_sizes;
    unsigned int bit = ffsl(sizes) - 1, order = 0;

    ASSERT(bit == PAGE_SHIFT);

    while ( (sizes = (sizes >> bit) & ~1) )
    {
        unsigned long mask;

        bit = ffsl(sizes) - 1;
        mask = (1UL << bit) - 1;
        if ( nr <= mask || (res & mask) )
            break;
        order += bit;
        nr >>= bit;
        res >>= bit;
    }

    return order;
}

long iommu_map(struct domain *d, struct iommu_context *ctx, dfn_t dfn0,
               mfn_t mfn0, unsigned long page_count, unsigned int flags,
               unsigned int *flush_flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    unsigned int order, j = 0;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    ASSERT(rspin_is_locked(&ctx->lock));
    ASSERT(!IOMMUF_order(flags));

    for ( i = 0; i < page_count; i += 1UL << order )
    {
        dfn_t dfn = dfn_add(dfn0, i);
        mfn_t mfn = mfn_add(mfn0, i);

        order = mapping_order(hd, dfn, mfn, page_count - i);

        if ( (flags & IOMMUF_preempt) &&
             ((!(++j & 0xfff) && general_preempt_check()) ||
              i > LONG_MAX - (1UL << order)) )
            return i;

        rc = iommu_call(hd->platform_ops, map_page, d, ctx, dfn, mfn,
                        flags | IOMMUF_order(order), flush_flags);

        if ( likely(!rc) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU mapping dfn %"PRI_dfn" to mfn %"PRI_mfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), mfn_x(mfn), rc);

        /* while statement to satisfy __must_check */
        while ( iommu_unmap(d, ctx, dfn0, i, 0, flush_flags) )
            break;

        if ( !ctx->id && !is_hardware_domain(d) )
            domain_crash(d);

        break;
    }

    /*
     * Something went wrong so, if we were dealing with more than a single
     * page, flush everything and clear flush flags.
     */
    if ( page_count > 1 && unlikely(rc) &&
         !iommu_iotlb_flush_all(d, ctx, *flush_flags) )
        *flush_flags = 0;

    return rc;
}

int iommu_legacy_map(struct domain *d, dfn_t dfn, mfn_t mfn,
                     unsigned long page_count, unsigned int flags)
{
    struct iommu_context *ctx;
    unsigned int flush_flags = 0;
    int rc = 0;

    ASSERT(!(flags & IOMMUF_preempt));

    ctx = iommu_get_context(d, 0);

    if ( !ctx->opaque )
    {
        rc = iommu_map(d, ctx, dfn, mfn, page_count, flags, &flush_flags);

        if ( !this_cpu(iommu_dont_flush_iotlb) && !rc )
            rc = iommu_iotlb_flush(d, ctx, dfn, page_count, flush_flags);
    }

    iommu_put_context(ctx);

    return rc;
}

long iommu_unmap(struct domain *d, struct iommu_context *ctx, dfn_t dfn0,
                 unsigned long page_count, unsigned int flags,
                 unsigned int *flush_flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    unsigned long i;
    unsigned int order, j = 0;
    int rc = 0;

    if ( !is_iommu_enabled(d) )
        return 0;

    ASSERT(!(flags & ~IOMMUF_preempt));

    for ( i = 0; i < page_count; i += 1UL << order )
    {
        dfn_t dfn = dfn_add(dfn0, i);
        int err;

        order = mapping_order(hd, dfn, _mfn(0), page_count - i);

        if ( (flags & IOMMUF_preempt) &&
             ((!(++j & 0xfff) && general_preempt_check()) ||
              i > LONG_MAX - (1UL << order)) )
            return i;

        err = iommu_call(hd->platform_ops, unmap_page, d, ctx, dfn,
                         flags | IOMMUF_order(order), flush_flags);

        if ( likely(!err) )
            continue;

        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU unmapping dfn %"PRI_dfn" failed: %d\n",
                   d->domain_id, dfn_x(dfn), err);

        if ( !rc )
            rc = err;

        if ( !ctx->id && !is_hardware_domain(d) )
        {
            domain_crash(d);
            break;
        }
    }

    /*
     * Something went wrong so, if we were dealing with more than a single
     * page, flush everything and clear flush flags.
     */
    if ( page_count > 1 && unlikely(rc) &&
         !iommu_iotlb_flush_all(d, ctx, *flush_flags) )
        *flush_flags = 0;

    return rc;
}

int iommu_legacy_unmap(struct domain *d, dfn_t dfn, unsigned long page_count)
{
    unsigned int flush_flags = 0;
    struct iommu_context *ctx;
    int rc = 0;

    ctx = iommu_get_context(d, 0);

    if ( !ctx->opaque )
    {
        rc = iommu_unmap(d, ctx, dfn, page_count, 0, &flush_flags);

        if ( !this_cpu(iommu_dont_flush_iotlb) && !rc )
            rc = iommu_iotlb_flush(d, ctx, dfn, page_count, flush_flags);
    }

    iommu_put_context(ctx);

    return rc;
}

int iommu_lookup_page(struct domain *d, struct iommu_context *ctx, dfn_t dfn,
                      mfn_t *mfn, unsigned int *flags)
{
    const struct domain_iommu *hd = dom_iommu(d);

    if ( !is_iommu_enabled(d) || !hd->platform_ops->lookup_page )
        return -EOPNOTSUPP;

    return iommu_call(hd->platform_ops, lookup_page, d, ctx, dfn, mfn, flags);
}

int iommu_iotlb_flush(struct domain *d, struct iommu_context *ctx, dfn_t dfn,
                      unsigned long page_count, unsigned int flush_flags)
{
    const struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !is_iommu_enabled(d) || !hd->platform_ops->iotlb_flush ||
         !page_count || !flush_flags )
        return 0;

    if ( dfn_eq(dfn, INVALID_DFN) )
        return -EINVAL;

    rc = iommu_call(hd->platform_ops, iotlb_flush, d, ctx, dfn, page_count,
                    flush_flags);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU IOTLB flush failed: %d, dfn %"PRI_dfn", page count %lu flags %x\n",
                   d->domain_id, rc, dfn_x(dfn), page_count, flush_flags);

        if ( !ctx->id && !is_hardware_domain(d) )
            domain_crash(d);
    }

    return rc;
}

int iommu_iotlb_flush_all(struct domain *d, struct iommu_context *ctx,
                          unsigned int flush_flags)
{
    struct domain_iommu *hd = dom_iommu(d);
    int rc;

    if ( !is_iommu_enabled(d) || !hd->platform_ops->iotlb_flush ||
         !flush_flags )
        return 0;

    rc = iommu_call(hd->platform_ops, iotlb_flush, d, ctx, INVALID_DFN, 0,
                    flush_flags | IOMMU_FLUSHF_all);
    if ( unlikely(rc) )
    {
        if ( !d->is_shutting_down && printk_ratelimit() )
            printk(XENLOG_ERR
                   "d%d: IOMMU IOTLB flush all failed: %d\n",
                   d->domain_id, rc);

        if ( !is_hardware_domain(d) )
            domain_crash(d);
    }

    iommu_put_context(ctx);
    return rc;
}

int cf_check iommu_context_init(struct domain *d, struct iommu_context *ctx,
                                uint16_t ctx_id, unsigned int flags)
{
    if ( !dom_iommu(d)->platform_ops->context_init )
        return -ENOSYS;

    INIT_LIST_HEAD(&ctx->devices);
    ctx->id = ctx_id;
    ctx->dying = false;
    ctx->opaque = false; /* assume non-opaque by default */

    return iommu_call(dom_iommu(d)->platform_ops, context_init, d, ctx, flags);
}

int iommu_context_alloc(struct domain *d, uint16_t *ctx_id, unsigned int flags)
{
    unsigned int i;
    int ret;
    struct domain_iommu *hd = dom_iommu(d);
    struct iommu_context *ctx;

    do {
        i = find_first_zero_bit(hd->other_contexts.bitmap, hd->other_contexts.count);

        if ( i >= hd->other_contexts.count )
            return -ENOSPC;

        ctx = &hd->other_contexts.map[i];

        /* Try to lock the mutex, can fail on concurrent accesses */
        if ( !rspin_trylock(&ctx->lock) )
            continue;

        /* We can now set it as used, we keep the lock for initialization. */
        set_bit(i, hd->other_contexts.bitmap);
    } while (0);

    *ctx_id = i + 1;

    ret = iommu_context_init(d, ctx, *ctx_id, flags);

    if ( ret )
        clear_bit(*ctx_id, hd->other_contexts.bitmap);

    iommu_put_context(ctx);
    return ret;
}

/**
 * Attach dev phantom functions to ctx, override any existing
 * mapped context.
 */
static int cf_check iommu_reattach_phantom(struct domain *d, device_t *dev,
                                           struct iommu_context *ctx)
{
    int ret = 0;
    uint8_t devfn = dev->devfn;
    struct domain_iommu *hd = dom_iommu(d);

    while ( dev->phantom_stride )
    {
        devfn += dev->phantom_stride;

        if ( PCI_SLOT(devfn) != PCI_SLOT(dev->devfn) )
            break;

        ret = iommu_call(hd->platform_ops, add_devfn, d, dev, devfn, ctx);

        if ( ret )
            break;
    }

    return ret;
}

/**
 * Detach all device phantom functions.
 */
static int cf_check iommu_detach_phantom(struct domain *d, device_t *dev,
                                         struct iommu_context *prev_ctx)
{
    int ret = 0;
    uint8_t devfn = dev->devfn;
    struct domain_iommu *hd = dom_iommu(d);

    while ( dev->phantom_stride )
    {
        devfn += dev->phantom_stride;

        if ( PCI_SLOT(devfn) != PCI_SLOT(dev->devfn) )
            break;

        ret = iommu_call(hd->platform_ops, remove_devfn, d, dev, devfn, prev_ctx);

        if ( ret )
            break;
    }

    return ret;
}

int cf_check iommu_attach_context(struct domain *d, device_t *dev, uint16_t ctx_id)
{
    struct iommu_context *ctx = NULL;
    int ret = 0, rc;

    if ( dev->context == ctx_id )
        return 0;

    if ( !(ctx = iommu_get_context(d, ctx_id)) )
    {
        ret = -ENOENT;
        goto unlock;
    }

    pcidevs_lock();

    if ( ctx->dying )
    {
        ret = -EINVAL;
        goto unlock;
    }

    /* ignore attach operations on PCIe bridges */
    if ( dev->type != DEV_TYPE_PCIe_BRIDGE )
        ret = iommu_call(dom_iommu(d)->platform_ops, attach, d, dev, ctx);

    if ( ret )
        goto unlock;

    /* See iommu_reattach_context() */
    rc = iommu_reattach_phantom(d, dev, ctx);

    if ( rc )
    {
        printk(XENLOG_ERR "IOMMU: Unable to attach %pp phantom functions\n",
               &dev->sbdf);

        if( iommu_call(dom_iommu(d)->platform_ops, detach, d, dev, ctx)
            || iommu_detach_phantom(d, dev, ctx) )
        {
            printk(XENLOG_ERR "IOMMU: Improperly detached %pp\n", &dev->sbdf);
            WARN();
        }

        ret = -EIO;
        goto unlock;
    }

    dev->context = ctx_id;
    list_add(&dev->context_list, &ctx->devices);

unlock:
    pcidevs_unlock();

    if ( ctx )
        iommu_put_context(ctx);

    return ret;
}

int cf_check iommu_detach_context(struct domain *d, device_t *dev)
{
    struct iommu_context *ctx;
    int ret = 0, rc;

    if ( !dev->domain || dev->context == IOMMU_INVALID_CONTEXT_ID )
    {
        printk(XENLOG_WARNING "IOMMU: Trying to detach a non-attached device\n");
        WARN();
        return 0;
    }

    /* Make sure device is actually in the domain. */
    ASSERT(d == dev->domain);

    pcidevs_lock();

    ctx = iommu_get_context(d, dev->context);
    ASSERT(ctx); /* device is using an invalid context ?
                    dev->context invalid ? */

    /* ignore detach operations on PCIe bridges */
    if ( dev->type != DEV_TYPE_PCIe_BRIDGE )
        ret = iommu_call(dom_iommu(d)->platform_ops, detach, d, dev, ctx);

    if ( ret )
        goto unlock;

    rc = iommu_detach_phantom(d, dev, ctx);

    if ( rc )
        printk(XENLOG_WARNING "IOMMU: "
               "Improperly detached device functions (%d)\n", rc);

    list_del(&dev->context_list);

unlock:
    pcidevs_unlock();
    iommu_put_context(ctx);
    return ret;
}

int cf_check iommu_reattach_context(struct domain *prev_dom, struct domain *next_dom,
                                    device_t *dev, uint16_t ctx_id)
{
    uint16_t prev_ctx_id;
    device_t *ctx_dev;
    struct domain_iommu *prev_hd, *next_hd;
    struct iommu_context *prev_ctx = NULL, *next_ctx = NULL;
    int ret = 0, rc;
    bool same_domain;

    /* Make sure we actually are doing something meaningful */
    BUG_ON(!prev_dom && !next_dom);

    /* Device domain must be coherent with prev_dom. */
    ASSERT(!prev_dom || dev->domain == prev_dom);

    /// TODO: Do such cases exists ?
    // /* Platform ops must match */
    // if (dom_iommu(prev_dom)->platform_ops != dom_iommu(next_dom)->platform_ops)
    //     return -EINVAL;

    if ( !prev_dom )
        return iommu_attach_context(next_dom, dev, ctx_id);

    if ( !next_dom )
        return iommu_detach_context(prev_dom, dev);

    prev_hd = dom_iommu(prev_dom);
    next_hd = dom_iommu(next_dom);

    pcidevs_lock();

    same_domain = prev_dom == next_dom;

    prev_ctx_id = dev->context;

    if ( same_domain && (ctx_id == prev_ctx_id) )
    {
        printk(XENLOG_DEBUG
               "IOMMU: Reattaching %pp to same IOMMU context c%hu\n",
               &dev->sbdf, ctx_id);
        ret = 0;
        goto unlock;
    }

    if ( !(prev_ctx = iommu_get_context(prev_dom, prev_ctx_id)) )
    {
        ret = -ENOENT;
        goto unlock;
    }

    if ( !(next_ctx = iommu_get_context(next_dom, ctx_id)) )
    {
        ret = -ENOENT;
        goto unlock;
    }

    if ( next_ctx->dying )
    {
        ret = -EINVAL;
        goto unlock;
    }

    /* ignore reattach operations on PCIe bridges */
    if ( dev->type != DEV_TYPE_PCIe_BRIDGE )
        ret = iommu_call(prev_hd->platform_ops, reattach, next_dom, dev,
                         prev_ctx, next_ctx);

    if ( ret )
        goto unlock;

    /*
     * We need to do special handling for phantom devices as they
     * also use some other PCI functions behind the scenes.
     */
    rc = iommu_reattach_phantom(next_dom, dev, next_ctx);

    if ( rc )
    {
        /**
         * Device is being partially reattached (we have primary function and
         * maybe some phantom functions attached to next_ctx, some others to prev_ctx),
         * some functions of the device will be attached to next_ctx.
         */
        printk(XENLOG_WARNING "IOMMU: "
               "Device %pp improperly reattached due to phantom function"
               " reattach failure between %dd%dc and %dd%dc (%d)\n", dev,
               prev_dom->domain_id, prev_ctx->id, next_dom->domain_id,
               next_dom->domain_id, rc);

        /* Try reattaching to previous context, reverting into a consistent state. */
        if ( iommu_call(prev_hd->platform_ops, reattach, prev_dom, dev, next_ctx,
                        prev_ctx) || iommu_reattach_phantom(prev_dom, dev, prev_ctx) )
        {
            printk(XENLOG_ERR "Unable to reattach %pp back to %dd%dc\n",
                   &dev->sbdf, prev_dom->domain_id, prev_ctx->id);

            if ( !is_hardware_domain(prev_dom) )
                domain_crash(prev_dom);

            if ( prev_dom != next_dom && !is_hardware_domain(next_dom) )
                domain_crash(next_dom);

            rc = -EIO;
        }

        ret = rc;
        goto unlock;
    }

    /* Remove device from previous context, and add it to new one. */
    list_for_each_entry(ctx_dev, &prev_ctx->devices, context_list)
    {
        if ( ctx_dev == dev )
        {
            list_del(&ctx_dev->context_list);
            list_add(&ctx_dev->context_list, &next_ctx->devices);
            break;
        }
    }

    if (!ret)
        dev->context = ctx_id; /* update device context*/

unlock:
    pcidevs_unlock();

    if ( prev_ctx )
        iommu_put_context(prev_ctx);

    if ( next_ctx )
        iommu_put_context(next_ctx);

    return ret;
}

int cf_check iommu_context_teardown(struct domain *d, struct iommu_context *ctx, u32 flags)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !hd->platform_ops->context_teardown )
        return -ENOSYS;

    ctx->dying = true;

    /* first reattach devices back to default context if needed */
    if ( flags & IOMMU_TEARDOWN_REATTACH_DEFAULT )
    {
        struct pci_dev *device;
        list_for_each_entry(device, &ctx->devices, context_list)
            iommu_reattach_context(d, d, device, 0);
    }
    else if (!list_empty(&ctx->devices))
        return -EBUSY; /* there is a device in context */

    return iommu_call(hd->platform_ops, context_teardown, d, ctx, flags);
}

int cf_check iommu_context_free(struct domain *d, uint16_t ctx_id, u32 flags)
{
    int ret;
    struct domain_iommu *hd = dom_iommu(d);
    struct iommu_context *ctx;

    if ( ctx_id == 0 )
        return -EINVAL;

    if ( !(ctx = iommu_get_context(d, ctx_id)) )
        return -ENOENT;

    ret = iommu_context_teardown(d, ctx, flags);

    if ( !ret )
        clear_bit(ctx_id - 1, hd->other_contexts.bitmap);

    iommu_put_context(ctx);
    return ret;
}

int iommu_quarantine_dev_init(device_t *dev)
{
    int ret;
    uint16_t ctx_id;

    if ( !iommu_quarantine )
        return 0;

    ret = iommu_context_alloc(dom_io, &ctx_id, IOMMU_CONTEXT_INIT_quarantine);

    if ( ret )
        return ret;

    /** TODO: Setup scratch page, mappings... */

    ret = iommu_reattach_context(dev->domain, dom_io, dev, ctx_id);

    if ( ret )
    {
        ASSERT(!iommu_context_free(dom_io, ctx_id, 0));
        return ret;
    }

    return ret;
}

int __init iommu_quarantine_init(void)
{
    dom_io->options |= XEN_DOMCTL_CDF_iommu;

    return iommu_domain_init(dom_io, 0);
}

int __init iommu_setup(void)
{
    int rc = -ENODEV;
    bool force_intremap = force_iommu && iommu_intremap;

#ifdef CONFIG_HAS_PCI
    if ( is_locked_down() )
        iommu_quarantine = IOMMU_quarantine_scratch_page;
#endif

    if ( iommu_hwdom_strict )
        iommu_hwdom_passthrough = false;

    if ( iommu_enable )
    {
        const struct iommu_ops *ops = NULL;

        rc = iommu_hardware_setup();
        if ( !rc )
            ops = iommu_get_ops();
        if ( ops && (ISOLATE_LSB(ops->page_sizes)) != PAGE_SIZE )
        {
            printk(XENLOG_ERR "IOMMU: page size mask %lx unsupported\n",
                   ops->page_sizes);
            rc = ops->page_sizes ? -EPERM : -ENODATA;
        }
        iommu_enabled = (rc == 0);
    }

#ifndef iommu_intremap
    if ( !iommu_enabled )
        iommu_intremap = iommu_intremap_off;
#endif

    if ( (force_iommu && !iommu_enabled) ||
         (force_intremap && !iommu_intremap) )
        panic("Couldn't enable %s and iommu=required/force\n",
              !iommu_enabled ? "IOMMU" : "Interrupt Remapping");

#ifndef iommu_intpost
    if ( !iommu_intremap )
        iommu_intpost = false;
#endif

    printk("I/O virtualisation %sabled\n", iommu_enabled ? "en" : "dis");
    if ( !iommu_enabled )
    {
        iommu_hwdom_passthrough = false;
        iommu_hwdom_strict = false;
    }
    else
    {
        if ( iommu_quarantine_init() )
            panic("Could not set up quarantine\n");

        printk(" - Dom0 mode: %s\n",
               iommu_hwdom_passthrough ? "Passthrough" :
               iommu_hwdom_strict ? "Strict" : "Relaxed");
#ifndef iommu_intremap
        printk("Interrupt remapping %sabled\n", iommu_intremap ? "en" : "dis");
#endif

        register_keyhandler('o', &iommu_dump_page_tables,
                            "dump iommu page tables", 0);
    }

    return rc;
}

int iommu_suspend(void)
{
    if ( iommu_enabled )
        return iommu_call(iommu_get_ops(), suspend);

    return 0;
}

void iommu_resume(void)
{
    if ( iommu_enabled )
        iommu_vcall(iommu_get_ops(), resume);
}

int iommu_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    int ret = -ENODEV;

    if ( !(d ? is_iommu_enabled(d) : iommu_enabled) )
        return -EOPNOTSUPP;

#ifdef CONFIG_HAS_PCI
    ret = iommu_do_pci_domctl(domctl, d, u_domctl);
#endif

#ifdef CONFIG_HAS_DEVICE_TREE
    if ( ret == -ENODEV )
        ret = iommu_do_dt_domctl(domctl, d, u_domctl);
#endif

    return ret;
}

void iommu_crash_shutdown(void)
{
    if ( !iommu_crash_disable )
        return;

    if ( iommu_enabled )
        iommu_vcall(iommu_get_ops(), crash_shutdown);

    iommu_enabled = false;
#ifndef iommu_intremap
    iommu_intremap = iommu_intremap_off;
#endif
#ifndef iommu_intpost
    iommu_intpost = false;
#endif
}

void iommu_quiesce(void)
{
    const struct iommu_ops *ops;

    if ( !iommu_enabled )
        return;

    ops = iommu_get_ops();
    if ( ops->quiesce )
        iommu_vcall(ops, quiesce);
}

int iommu_get_reserved_device_memory(iommu_grdm_t *func, void *ctxt)
{
    const struct iommu_ops *ops;

    if ( !iommu_enabled )
        return 0;

    ops = iommu_get_ops();
    if ( !ops->get_reserved_device_memory )
        return 0;

    return iommu_call(ops, get_reserved_device_memory, func, ctxt);
}

bool iommu_has_feature(struct domain *d, enum iommu_feature feature)
{
    return is_iommu_enabled(d) && test_bit(feature, dom_iommu(d)->features);
}

uint64_t iommu_get_max_iova(struct domain *d)
{
    struct domain_iommu *hd = dom_iommu(d);

    if ( !hd->platform_ops->get_max_iova )
        return 0;

    return iommu_call(hd->platform_ops, get_max_iova, d);
}

#define MAX_EXTRA_RESERVED_RANGES 20
struct extra_reserved_range {
    unsigned long start;
    unsigned long nr;
    pci_sbdf_t sbdf;
    const char *name;
};
static unsigned int __initdata nr_extra_reserved_ranges;
static struct extra_reserved_range __initdata
    extra_reserved_ranges[MAX_EXTRA_RESERVED_RANGES];

int __init iommu_add_extra_reserved_device_memory(unsigned long start,
                                                  unsigned long nr,
                                                  pci_sbdf_t sbdf,
                                                  const char *name)
{
    unsigned int idx;

    if ( nr_extra_reserved_ranges >= MAX_EXTRA_RESERVED_RANGES )
        return -ENOMEM;

    idx = nr_extra_reserved_ranges++;
    extra_reserved_ranges[idx].start = start;
    extra_reserved_ranges[idx].nr = nr;
    extra_reserved_ranges[idx].sbdf = sbdf;
    extra_reserved_ranges[idx].name = name;

    return 0;
}

int __init iommu_get_extra_reserved_device_memory(iommu_grdm_t *func,
                                                  void *ctxt)
{
    unsigned int idx;
    int ret;

    for ( idx = 0; idx < nr_extra_reserved_ranges; idx++ )
    {
#ifdef CONFIG_X86
        paddr_t start = pfn_to_paddr(extra_reserved_ranges[idx].start);
        paddr_t end = pfn_to_paddr(extra_reserved_ranges[idx].start +
                                   extra_reserved_ranges[idx].nr);

        if ( !reserve_e820_ram(&e820, start, end) )
        {
            printk(XENLOG_ERR "Failed to reserve [%"PRIx64"-%"PRIx64") for %s, "
                   "skipping IOMMU mapping for it, some functionality may be broken\n",
                   start, end, extra_reserved_ranges[idx].name);
            continue;
        }
#endif
        ret = func(extra_reserved_ranges[idx].start,
                   extra_reserved_ranges[idx].nr,
                   extra_reserved_ranges[idx].sbdf.sbdf,
                   ctxt);
        if ( ret < 0 )
            return ret;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

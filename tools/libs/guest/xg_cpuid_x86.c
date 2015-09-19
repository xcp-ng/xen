/******************************************************************************
 * xc_cpuid_x86.c
 *
 * Compute cpuid of a domain.
 *
 * Copyright (c) 2008, Citrix Systems, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include "xg_private.h"
#include <xen/hvm/params.h>
#include <xen-tools/libs.h>

enum {
#define XEN_CPUFEATURE(name, value) X86_FEATURE_##name = value,
#include <xen/arch-x86/cpufeatureset.h>
};

#include <xen/asm/x86-vendors.h>

#define bitmaskof(idx)      (1u << ((idx) & 31))
#define featureword_of(idx) ((idx) >> 5)

/*
 * For each bit clear in @featureset which has dependent features, clear those
 * too.
 */
static void clear_deep_deps(uint32_t *featureset, size_t len /* words */)
{
    static const uint32_t deep_features[] = INIT_DEEP_FEATURES;

    uint32_t disabled_features[ARRAY_SIZE(deep_features)];
    size_t i, b;

    len = min(len, ARRAY_SIZE(deep_features));

    /* Identify disabled features that have dependent features. */
    for ( i = 0; i < len; ++i )
        disabled_features[i] = ~featureset[i] & deep_features[i];

    /* For each set bit in disabled that has dependent features ... */
    for ( b = 0; b < (len * 32); ++b )
    {
        const uint32_t *dfs;

        if ( !test_bit(b, disabled_features) ||
             !(dfs = x86_cpu_policy_lookup_deep_deps(b)) )
            continue;

        /* ... disable all those features too */
        for ( i = 0; i < len; ++i )
        {
            featureset[i] &= ~dfs[i];
            disabled_features[i] &= ~dfs[i];
        }
    }
}

int xc_get_cpu_levelling_caps(xc_interface *xch, uint32_t *caps)
{
    DECLARE_SYSCTL;
    int ret;

    sysctl.cmd = XEN_SYSCTL_get_cpu_levelling_caps;
    ret = do_sysctl(xch, &sysctl);

    if ( !ret )
        *caps = sysctl.u.cpu_levelling_caps.caps;

    return ret;
}

static int xc_get_cpu_featureset_(xc_interface *xch, uint32_t index,
                                  uint32_t *nr_features, uint32_t *featureset)
{
    DECLARE_SYSCTL;
    DECLARE_HYPERCALL_BOUNCE(featureset,
                             *nr_features * sizeof(*featureset),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret;

    if ( xc_hypercall_bounce_pre(xch, featureset) )
        return -1;

    sysctl.cmd = XEN_SYSCTL_get_cpu_featureset;
    sysctl.u.cpu_featureset.index = index;
    sysctl.u.cpu_featureset.nr_features = *nr_features;
    set_xen_guest_handle(sysctl.u.cpu_featureset.features, featureset);

    ret = do_sysctl(xch, &sysctl);

    xc_hypercall_bounce_post(xch, featureset);

    if ( !ret )
        *nr_features = sysctl.u.cpu_featureset.nr_features;

    return ret;
}

int xc_get_cpu_featureset(xc_interface *xch, uint32_t index,
                          uint32_t *nr, uint32_t *fs)
{
    uint32_t host_fs[FEATURESET_NR_ENTRIES] = {}, host_nr = ARRAY_SIZE(host_fs);
    unsigned int vendor;
    int ret;

    if ( index != XEN_SYSCTL_cpu_featureset_pv_max &&
         index != XEN_SYSCTL_cpu_featureset_hvm_max )
        return xc_get_cpu_featureset_(xch, index, nr, fs);

    /*
     * Augment a *_max featureset.
     *
     * This is used by xenopsd to pass to the toolstack of the incoming
     * domain, to allow it to establish migration safety.
     */
    ret = xc_get_cpu_featureset_(
        xch, XEN_SYSCTL_cpu_featureset_host, &host_nr, host_fs);
    if ( ret && errno != ENOBUFS )
        return ret;

    ret = xc_get_cpu_featureset_(xch, index, nr, fs);
    if ( ret )
        return ret;

    /*
     * Xen 4.7 had the common features duplicated.  4.8 changed this, to only
     * use the Intel range.  Undo this.
     */
    fs[2] |= (fs[0] & CPUID_COMMON_1D_FEATURES);

    if ( index == XEN_SYSCTL_cpu_featureset_hvm_max )
    {
        struct cpuid_leaf l;

        cpuid_leaf(0, &l);
        vendor = x86_cpuid_lookup_vendor(l.b, l.c, l.d);

        /*
         * Xen 4.7 used to falsely advertise IBS, and 4.8 fixed this.
         * However, the old xenopsd workaround fix for this didn't limit the
         * workaround to AMD systems, so the Last Boot Record of every HVM VM,
         * even on Intel, is wrong.
         */
        set_bit(X86_FEATURE_IBS, fs);

        switch ( vendor )
        {
        case X86_VENDOR_AMD:
        case X86_VENDOR_HYGON:
            /*
             * In order to mitigate Spectre, AMD dropped the LWP feature in
             * microcode, to make space for MSR_PRED_CMD.  No one used LWP, but it
             * was visible to guests at the time.
             */
            set_bit(X86_FEATURE_LWP, fs);

            /*
             * Xen 4.14 and earlier advertised SVM by default, but cleared it
             * behind the scenes when nested-virt wasn't configured.  Keep it
             * visible in Xapi's view.
             */
            set_bit(X86_FEATURE_SVM, fs);
            break;

        case X86_VENDOR_INTEL:
        case X86_VENDOR_CENTAUR:
            /*
             * Xen 4.14 and earlier advertised VMX by default, but cleared it
             * behind the scenes when nested-virt wasn't configured.  Keep it
             * visible in Xapi's view.
             */
            set_bit(X86_FEATURE_VMX, fs);
            break;
        }
    }

    return 0;
}

uint32_t xc_get_cpu_featureset_size(void)
{
    return FEATURESET_NR_ENTRIES;
}

const uint32_t *xc_get_static_cpu_featuremask(
    enum xc_static_cpu_featuremask mask)
{
    static const uint32_t masks[][FEATURESET_NR_ENTRIES] = {
#define MASK(x) [XC_FEATUREMASK_ ## x] = INIT_ ## x ## _FEATURES

        MASK(KNOWN),
        MASK(SPECIAL),
        MASK(PV_MAX),
        MASK(PV_DEF),
        MASK(HVM_SHADOW_MAX),
        MASK(HVM_SHADOW_DEF),
        MASK(HVM_HAP_MAX),
        MASK(HVM_HAP_DEF),

#undef MASK
    };

    if ( (unsigned int)mask >= ARRAY_SIZE(masks) )
        return NULL;

    return masks[mask];
}

int xc_cpu_policy_get_size(xc_interface *xch, uint32_t *nr_leaves,
                           uint32_t *nr_msrs)
{
    struct xen_sysctl sysctl = {};
    int ret;

    sysctl.cmd = XEN_SYSCTL_get_cpu_policy;

    ret = do_sysctl(xch, &sysctl);

    if ( !ret )
    {
        *nr_leaves = sysctl.u.cpu_policy.nr_leaves;
        *nr_msrs = sysctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

static int get_system_cpu_policy(xc_interface *xch, uint32_t index,
                                 uint32_t *nr_leaves, xen_cpuid_leaf_t *leaves,
                                 uint32_t *nr_msrs, xen_msr_entry_t *msrs)
{
    struct xen_sysctl sysctl = {};
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             *nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             *nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret = -1;

    if ( !xc_hypercall_bounce_pre(xch, leaves) &&
         !xc_hypercall_bounce_pre(xch, msrs) )
    {
        sysctl.cmd = XEN_SYSCTL_get_cpu_policy;
        sysctl.u.cpu_policy.index = index;
        sysctl.u.cpu_policy.nr_leaves = *nr_leaves;
        set_xen_guest_handle(sysctl.u.cpu_policy.leaves, leaves);
        sysctl.u.cpu_policy.nr_msrs = *nr_msrs;
        set_xen_guest_handle(sysctl.u.cpu_policy.msrs, msrs);

        ret = do_sysctl(xch, &sysctl);
    }

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( !ret )
    {
        *nr_leaves = sysctl.u.cpu_policy.nr_leaves;
        *nr_msrs = sysctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

static int get_domain_cpu_policy(xc_interface *xch, uint32_t domid,
                                 uint32_t *nr_leaves, xen_cpuid_leaf_t *leaves,
                                 uint32_t *nr_msrs, xen_msr_entry_t *msrs)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             *nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             *nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    int ret = -1;

    if ( !xc_hypercall_bounce_pre(xch, leaves) &&
         !xc_hypercall_bounce_pre(xch, msrs) )
    {
        domctl.cmd = XEN_DOMCTL_get_cpu_policy;
        domctl.domain = domid;
        domctl.u.cpu_policy.nr_leaves = *nr_leaves;
        set_xen_guest_handle(domctl.u.cpu_policy.leaves, leaves);
        domctl.u.cpu_policy.nr_msrs = *nr_msrs;
        set_xen_guest_handle(domctl.u.cpu_policy.msrs, msrs);

        ret = do_domctl(xch, &domctl);
    }

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( !ret )
    {
        *nr_leaves = domctl.u.cpu_policy.nr_leaves;
        *nr_msrs = domctl.u.cpu_policy.nr_msrs;
    }

    return ret;
}

int xc_set_domain_cpu_policy(xc_interface *xch, uint32_t domid,
                             uint32_t nr_leaves, xen_cpuid_leaf_t *leaves,
                             uint32_t nr_msrs, xen_msr_entry_t *msrs,
                             uint32_t *err_leaf_p, uint32_t *err_subleaf_p,
                             uint32_t *err_msr_p)
{
    DECLARE_DOMCTL;
    DECLARE_HYPERCALL_BOUNCE(leaves,
                             nr_leaves * sizeof(*leaves),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    DECLARE_HYPERCALL_BOUNCE(msrs,
                             nr_msrs * sizeof(*msrs),
                             XC_HYPERCALL_BUFFER_BOUNCE_IN);
    int ret = -1;

    domctl.u.cpu_policy.err_leaf = -1;
    domctl.u.cpu_policy.err_subleaf = -1;
    domctl.u.cpu_policy.err_msr = -1;

    if ( !xc_hypercall_bounce_pre(xch, leaves) &&
         !xc_hypercall_bounce_pre(xch, msrs) )
    {
        domctl.cmd = XEN_DOMCTL_set_cpu_policy;
        domctl.domain = domid;
        domctl.u.cpu_policy.nr_leaves = nr_leaves;
        set_xen_guest_handle(domctl.u.cpu_policy.leaves, leaves);
        domctl.u.cpu_policy.nr_msrs = nr_msrs;
        set_xen_guest_handle(domctl.u.cpu_policy.msrs, msrs);

        ret = do_domctl(xch, &domctl);
    }

    xc_hypercall_bounce_post(xch, leaves);
    xc_hypercall_bounce_post(xch, msrs);

    if ( err_leaf_p )
        *err_leaf_p = domctl.u.cpu_policy.err_leaf;
    if ( err_subleaf_p )
        *err_subleaf_p = domctl.u.cpu_policy.err_subleaf;
    if ( err_msr_p )
        *err_msr_p = domctl.u.cpu_policy.err_msr;

    return ret;
}

static int compare_leaves(const void *l, const void *r)
{
    const xen_cpuid_leaf_t *lhs = l;
    const xen_cpuid_leaf_t *rhs = r;

    if ( lhs->leaf != rhs->leaf )
        return lhs->leaf < rhs->leaf ? -1 : 1;

    if ( lhs->subleaf != rhs->subleaf )
        return lhs->subleaf < rhs->subleaf ? -1 : 1;

    return 0;
}

static xen_cpuid_leaf_t *find_leaf(
    xen_cpuid_leaf_t *leaves, unsigned int nr_leaves,
    const struct xc_xend_cpuid *xend)
{
    const xen_cpuid_leaf_t key = { xend->leaf, xend->subleaf };

    return bsearch(&key, leaves, nr_leaves, sizeof(*leaves), compare_leaves);
}

static int xc_cpuid_xend_policy(
    xc_interface *xch, uint32_t domid, const struct xc_xend_cpuid *xend)
{
    int rc;
    bool hvm;
    xc_domaininfo_t di;
    unsigned int nr_leaves, nr_msrs;
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    /*
     * Three full policies.  The host, default for the domain type,
     * and domain current.
     */
    xen_cpuid_leaf_t *host = NULL, *def = NULL, *cur = NULL;
    unsigned int nr_host, nr_def, nr_cur;

    if ( (rc = xc_domain_getinfo_single(xch, domid, &di)) < 0 )
    {
        PERROR("Failed to obtain d%d info", domid);
        rc = -errno;
        goto fail;
    }
    hvm = di.flags & XEN_DOMINF_hvm_guest;

    rc = xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs);
    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        rc = -errno;
        goto fail;
    }

    rc = -ENOMEM;
    if ( (host = calloc(nr_leaves, sizeof(*host))) == NULL ||
         (def  = calloc(nr_leaves, sizeof(*def)))  == NULL ||
         (cur  = calloc(nr_leaves, sizeof(*cur)))  == NULL )
    {
        ERROR("Unable to allocate memory for %u CPUID leaves", nr_leaves);
        goto fail;
    }

    /* Get the domain's current policy. */
    nr_msrs = 0;
    nr_cur = nr_leaves;
    rc = get_domain_cpu_policy(xch, domid, &nr_cur, cur, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain d%d current policy", domid);
        rc = -errno;
        goto fail;
    }

    /* Get the domain type's default policy. */
    nr_msrs = 0;
    nr_def = nr_leaves;
    rc = get_system_cpu_policy(xch, hvm ? XEN_SYSCTL_cpu_policy_hvm_default
                                        : XEN_SYSCTL_cpu_policy_pv_default,
                               &nr_def, def, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain %s def policy", hvm ? "hvm" : "pv");
        rc = -errno;
        goto fail;
    }

    /* Get the host policy. */
    nr_msrs = 0;
    nr_host = nr_leaves;
    rc = get_system_cpu_policy(xch, XEN_SYSCTL_cpu_policy_host,
                               &nr_host, host, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain host policy");
        rc = -errno;
        goto fail;
    }

    rc = -EINVAL;
    for ( ; xend->leaf != XEN_CPUID_INPUT_UNUSED; ++xend )
    {
        xen_cpuid_leaf_t *cur_leaf = find_leaf(cur, nr_cur, xend);
        const xen_cpuid_leaf_t *def_leaf = find_leaf(def, nr_def, xend);
        const xen_cpuid_leaf_t *host_leaf = find_leaf(host, nr_host, xend);

        if ( cur_leaf == NULL || def_leaf == NULL || host_leaf == NULL )
        {
            ERROR("Missing leaf %#x, subleaf %#x", xend->leaf, xend->subleaf);
            goto fail;
        }

        for ( unsigned int i = 0; i < ARRAY_SIZE(xend->policy); i++ )
        {
            uint32_t *cur_reg = &cur_leaf->a + i;
            const uint32_t *def_reg = &def_leaf->a + i;
            const uint32_t *host_reg = &host_leaf->a + i;

            if ( xend->policy[i] == NULL )
                continue;

            for ( unsigned int j = 0; j < 32; j++ )
            {
                bool val;

                if ( xend->policy[i][j] == '1' )
                    val = true;
                else if ( xend->policy[i][j] == '0' )
                    val = false;
                else if ( xend->policy[i][j] == 'x' )
                    val = test_bit(31 - j, def_reg);
                else if ( xend->policy[i][j] == 'k' ||
                          xend->policy[i][j] == 's' )
                    val = test_bit(31 - j, host_reg);
                else
                {
                    ERROR("Bad character '%c' in policy[%d] string '%s'",
                          xend->policy[i][j], i, xend->policy[i]);
                    goto fail;
                }

                clear_bit(31 - j, cur_reg);
                if ( val )
                    set_bit(31 - j, cur_reg);
            }
        }
    }

    /* Feed the transformed currrent policy back up to Xen. */
    rc = xc_set_domain_cpu_policy(xch, domid, nr_cur, cur, 0, NULL,
                                  &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        PERROR("Failed to set d%d's policy (err leaf %#x, subleaf %#x, msr %#x)",
               domid, err_leaf, err_subleaf, err_msr);
        rc = -errno;
        goto fail;
    }

    /* Success! */

 fail:
    free(cur);
    free(def);
    free(host);

    return rc;
}

static int compare_msr(const void *l, const void *r)
{
    const xen_msr_entry_t *lhs = l;
    const xen_msr_entry_t *rhs = r;

    if ( lhs->idx == rhs->idx )
        return 0;

    return lhs->idx < rhs->idx ? -1 : 1;
}

static xen_msr_entry_t *find_msr(
    xen_msr_entry_t *msrs, unsigned int nr_msrs,
    uint32_t index)
{
    const xen_msr_entry_t key = { .idx = index };

    return bsearch(&key, msrs, nr_msrs, sizeof(*msrs), compare_msr);
}


static int xc_msr_policy(xc_interface *xch, domid_t domid,
                         const struct xc_msr *msr)
{
    int rc;
    bool hvm;
    xc_domaininfo_t di;
    unsigned int nr_leaves, nr_msrs;
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    /*
     * Three full policies.  The host, default for the domain type,
     * and domain current.
     */
    xen_msr_entry_t *host = NULL, *def = NULL, *cur = NULL;
    unsigned int nr_host, nr_def, nr_cur;

    if ( (rc = xc_domain_getinfo_single(xch, domid, &di)) < 0 )
    {
        ERROR("Failed to obtain d%d info", domid);
        rc = -ESRCH;
        goto out;
    }
    hvm = di.flags & XEN_DOMINF_hvm_guest;

    rc = xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs);
    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        rc = -errno;
        goto out;
    }

    if ( (host = calloc(nr_msrs, sizeof(*host))) == NULL ||
         (def  = calloc(nr_msrs, sizeof(*def)))  == NULL ||
         (cur  = calloc(nr_msrs, sizeof(*cur)))  == NULL )
    {
        ERROR("Unable to allocate memory for %u CPUID leaves", nr_leaves);
        rc = -ENOMEM;
        goto out;
    }

    /* Get the domain's current policy. */
    nr_leaves = 0;
    nr_cur = nr_msrs;
    rc = get_domain_cpu_policy(xch, domid, &nr_leaves, NULL, &nr_cur, cur);
    if ( rc )
    {
        PERROR("Failed to obtain d%d current policy", domid);
        rc = -errno;
        goto out;
    }

    /* Get the domain type's default policy. */
    nr_leaves = 0;
    nr_def = nr_msrs;
    rc = get_system_cpu_policy(xch, hvm ? XEN_SYSCTL_cpu_policy_hvm_default
                                        : XEN_SYSCTL_cpu_policy_pv_default,
                               &nr_leaves, NULL, &nr_def, def);
    if ( rc )
    {
        PERROR("Failed to obtain %s def policy", hvm ? "hvm" : "pv");
        rc = -errno;
        goto out;
    }

    /* Get the host policy. */
    nr_leaves = 0;
    nr_host = nr_msrs;
    rc = get_system_cpu_policy(xch, XEN_SYSCTL_cpu_policy_host,
                               &nr_leaves, NULL, &nr_host, host);
    if ( rc )
    {
        PERROR("Failed to obtain host policy");
        rc = -errno;
        goto out;
    }

    for ( ; msr->index != XC_MSR_INPUT_UNUSED; ++msr )
    {
        xen_msr_entry_t *cur_msr = find_msr(cur, nr_cur, msr->index);
        const xen_msr_entry_t *def_msr = find_msr(def, nr_def, msr->index);
        const xen_msr_entry_t *host_msr = find_msr(host, nr_host, msr->index);
        unsigned int i;

        if ( cur_msr == NULL || def_msr == NULL || host_msr == NULL )
        {
            ERROR("Missing MSR %#x", msr->index);
            rc = -ENOENT;
            goto out;
        }

        for ( i = 0; i < ARRAY_SIZE(msr->policy) - 1; i++ )
        {
            bool val;

            if ( msr->policy[i] == '1' )
                val = true;
            else if ( msr->policy[i] == '0' )
                val = false;
            else if ( msr->policy[i] == 'x' )
                val = test_bit(63 - i, &def_msr->val);
            else if ( msr->policy[i] == 'k' )
                val = test_bit(63 - i, &host_msr->val);
            else
            {
                ERROR("MSR index %#x: bad character '%c' in policy string '%s'",
                      msr->index, msr->policy[i], msr->policy);
                rc = -EINVAL;
                goto out;
            }

            if ( val )
                set_bit(63 - i, &cur_msr->val);
            else
                clear_bit(63 - i, &cur_msr->val);
        }
    }

    /* Feed the transformed policy back up to Xen. */
    rc = xc_set_domain_cpu_policy(xch, domid, 0, NULL, nr_cur, cur,
                                  &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        PERROR("Failed to set d%d's policy (err leaf %#x, subleaf %#x, msr %#x)",
               domid, err_leaf, err_subleaf, err_msr);
        rc = -errno;
        goto out;
    }

    /* Success! */

 out:
    free(cur);
    free(def);
    free(host);

    return rc;
}

int xc_cpuid_apply_policy(xc_interface *xch, uint32_t domid, bool restore,
                          const uint32_t *featureset, unsigned int nr_features,
                          bool pae, bool itsc, bool nested_virt, unsigned int cps,
                          const struct xc_xend_cpuid *xend,
                          const struct xc_msr *msr)
{
    int rc;
    bool hvm;
    xc_domaininfo_t di;
    unsigned int i, nr_leaves, nr_msrs;
    xen_cpuid_leaf_t *leaves = NULL;
    struct cpu_policy *p = NULL;
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    uint32_t host_featureset[FEATURESET_NR_ENTRIES] = {};
    uint32_t len = ARRAY_SIZE(host_featureset);

    if ( (rc = xc_domain_getinfo_single(xch, domid, &di)) < 0 )
    {
        PERROR("Failed to obtain d%d info", domid);
        rc = -errno;
        goto out;
    }
    hvm = di.flags & XEN_DOMINF_hvm_guest;

    rc = xc_cpu_policy_get_size(xch, &nr_leaves, &nr_msrs);
    if ( rc )
    {
        PERROR("Failed to obtain policy info size");
        rc = -errno;
        goto out;
    }

    rc = -ENOMEM;
    if ( (leaves = calloc(nr_leaves, sizeof(*leaves))) == NULL ||
         (p = calloc(1, sizeof(*p))) == NULL )
        goto out;

    /* Get the host policy. */
    rc = xc_get_cpu_featureset(xch, XEN_SYSCTL_cpu_featureset_host,
                               &len, host_featureset);
    if ( rc )
    {
        /* Tolerate "buffer too small", as we've got the bits we need. */
        if ( errno == ENOBUFS )
            rc = 0;
        else
        {
            PERROR("Failed to obtain host featureset");
            rc = -errno;
            goto out;
        }
    }

    /* Get the domain's default policy. */
    nr_msrs = 0;
    rc = get_system_cpu_policy(xch, hvm ? XEN_SYSCTL_cpu_policy_hvm_default
                                        : XEN_SYSCTL_cpu_policy_pv_default,
                               &nr_leaves, leaves, &nr_msrs, NULL);
    if ( rc )
    {
        PERROR("Failed to obtain %s default policy", hvm ? "hvm" : "pv");
        rc = -errno;
        goto out;
    }

    rc = x86_cpuid_copy_from_buffer(p, leaves, nr_leaves,
                                    &err_leaf, &err_subleaf);
    if ( rc )
    {
        ERROR("Failed to deserialise CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
              err_leaf, err_subleaf, -rc, strerror(-rc));
        goto out;
    }

    if ( restore )
    {
        /*
         * Xen 4.14 introduced support to move the guest's CPUID data in the
         * migration stream.  Previously, the destination side would invent a
         * policy out of thin air in the hopes that it was ok.
         *
         * This restore path is used for incoming VMs with no CPUID data
         * i.e. originated on Xen 4.13 or earlier.  We must invent a policy
         * compatible with what Xen 4.13 would have done on the same hardware.
         *
         * Specifically:
         * - Clamp max leaves.
         * - Re-enable features which have become (possibly) off by default.
         */

        p->basic.rdrand = test_bit(X86_FEATURE_RDRAND, host_featureset);
        p->feat.hle = test_bit(X86_FEATURE_HLE, host_featureset);
        p->feat.rtm = test_bit(X86_FEATURE_RTM, host_featureset);

        if ( hvm )
        {
            p->feat.mpx = test_bit(X86_FEATURE_MPX, host_featureset);
        }

        p->basic.max_leaf = min(p->basic.max_leaf, 0xdu);
        p->feat.max_subleaf = 0;
        p->extd.max_leaf = min(p->extd.max_leaf, 0x8000001c);
    }

    if ( featureset )
    {
        uint32_t feat[FEATURESET_NR_ENTRIES] = {};
        unsigned int i;

        /*
         * The user supplied featureset may be shorter or longer than
         * FEATURESET_NR_ENTRIES.  Shorter is fine, and we will zero-extend.
         * Longer is fine, so long as it only padded with zeros.
         */
        unsigned int user_len = min(FEATURESET_NR_ENTRIES + 0u, nr_features);

        /* Check for truncated set bits. */
        rc = -EOPNOTSUPP;
        for ( i = user_len; i < nr_features; ++i )
            if ( featureset[i] != 0 )
                goto out;

        memcpy(feat, featureset, sizeof(*featureset) * user_len);

        clear_deep_deps(feat, user_len);

        x86_cpu_featureset_to_policy(feat, p);
    }
    else
    {
        p->extd.itsc = itsc;

        if ( hvm )
        {
            p->basic.pae = pae;
            p->basic.vmx = nested_virt;
            p->extd.svm = nested_virt;
        }
    }

    if ( !hvm )
    {
        /*
         * On hardware without CPUID Faulting, PV guests see real topology.
         * As a consequence, they also need to see the host htt/cmp fields.
         */
        p->basic.htt       = test_bit(X86_FEATURE_HTT, host_featureset);
        p->extd.cmp_legacy = test_bit(X86_FEATURE_CMP_LEGACY, host_featureset);
    }
    else
    {
        p->basic.htt = false;
        p->extd.cmp_legacy = false;

        switch ( p->x86_vendor )
        {
        case X86_VENDOR_INTEL:
            for ( i = 0; (p->cache.subleaf[i].type &&
                          i < ARRAY_SIZE(p->cache.raw)); ++i )
            {
                p->cache.subleaf[i].cores_per_package = 0;
                p->cache.subleaf[i].threads_per_cache = 0;
            }
            break;
        }

        /*
         * BODGE: XenServer legacy cores-per-socket.  Needs to remain like
         * this for backwards compatibility with migration streams which lack
         * CPUID data.
         */
        if ( cps > 0 )
        {
            p->basic.htt = true;

            /*
             * This (cps * 2) is wrong, and contrary to the statement in the
             * AMD manual.  However, Xen unconditionally offers Intel-style
             * APIC IDs (odd IDs for hyperthreads) which breaks the AMD APIC
             * Enumeration Requirements.
             *
             * Fake up cores-per-socket as a socket with twice as many cores
             * as expected, with every odd core offline.
             */
            p->basic.lppp = cps * 2;

            switch ( p->x86_vendor )
            {
            case X86_VENDOR_INTEL:
                for ( i = 0; (p->cache.subleaf[i].type &&
                              i < ARRAY_SIZE(p->cache.raw)); ++i )
                {
                    p->cache.subleaf[i].cores_per_package = (cps * 2) - 1;
                    p->cache.subleaf[i].threads_per_cache = 0;
                }
                break;

            case X86_VENDOR_AMD:
            case X86_VENDOR_HYGON:
                p->extd.cmp_legacy = true;
                p->extd.apic_id_size = 0;
                p->extd.nc = (cps * 2) - 1;
                break;
            }
        }
    }

    rc = x86_cpuid_copy_to_buffer(p, leaves, &nr_leaves);
    if ( rc )
    {
        ERROR("Failed to serialise CPUID (%d = %s)", -rc, strerror(-rc));
        goto out;
    }

    rc = xc_set_domain_cpu_policy(xch, domid, nr_leaves, leaves, 0, NULL,
                                  &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        PERROR("Failed to set d%d's policy (err leaf %#x, subleaf %#x, msr %#x)",
               domid, err_leaf, err_subleaf, err_msr);
        rc = -errno;
        goto out;
    }

    if ( xend && (rc = xc_cpuid_xend_policy(xch, domid, xend)) )
        goto out;

    if ( msr )
    {
        rc = xc_msr_policy(xch, domid, msr);
        if ( rc )
            goto out;
    }

    rc = 0;

out:
    free(p);
    free(leaves);

    return rc;
}

xc_cpu_policy_t *xc_cpu_policy_init(void)
{
    return calloc(1, sizeof(struct xc_cpu_policy));
}

void xc_cpu_policy_destroy(xc_cpu_policy_t *policy)
{
    if ( policy )
        free(policy);
}

static int deserialize_policy(xc_interface *xch, xc_cpu_policy_t *policy,
                              unsigned int nr_leaves, unsigned int nr_entries)
{
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    int rc;

    rc = x86_cpuid_copy_from_buffer(&policy->policy, policy->leaves,
                                    nr_leaves, &err_leaf, &err_subleaf);
    if ( rc )
    {
        if ( err_leaf != -1 )
            ERROR("Failed to deserialise CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
                  err_leaf, err_subleaf, -rc, strerror(-rc));
        return rc;
    }

    rc = x86_msr_copy_from_buffer(&policy->policy, policy->msrs,
                                  nr_entries, &err_msr);
    if ( rc )
    {
        if ( err_msr != -1 )
            ERROR("Failed to deserialise MSR (err MSR %#x) (%d = %s)",
                  err_msr, -rc, strerror(-rc));
        return rc;
    }

    return 0;
}

int xc_cpu_policy_get_system(xc_interface *xch, unsigned int policy_idx,
                             xc_cpu_policy_t *policy)
{
    unsigned int nr_leaves = ARRAY_SIZE(policy->leaves);
    unsigned int nr_msrs = ARRAY_SIZE(policy->msrs);
    int rc;

    rc = get_system_cpu_policy(xch, policy_idx, &nr_leaves, policy->leaves,
                               &nr_msrs, policy->msrs);
    if ( rc )
    {
        PERROR("Failed to obtain %u policy", policy_idx);
        return rc;
    }

    rc = deserialize_policy(xch, policy, nr_leaves, nr_msrs);
    if ( rc )
    {
        errno = -rc;
        rc = -1;
    }

    return rc;
}

int xc_cpu_policy_get_domain(xc_interface *xch, uint32_t domid,
                             xc_cpu_policy_t *policy)
{
    unsigned int nr_leaves = ARRAY_SIZE(policy->leaves);
    unsigned int nr_msrs = ARRAY_SIZE(policy->msrs);
    int rc;

    rc = get_domain_cpu_policy(xch, domid, &nr_leaves, policy->leaves,
                               &nr_msrs, policy->msrs);
    if ( rc )
    {
        PERROR("Failed to obtain domain %u policy", domid);
        return rc;
    }

    rc = deserialize_policy(xch, policy, nr_leaves, nr_msrs);
    if ( rc )
    {
        errno = -rc;
        rc = -1;
    }

    return rc;
}

int xc_cpu_policy_set_domain(xc_interface *xch, uint32_t domid,
                             xc_cpu_policy_t *policy)
{
    uint32_t err_leaf = -1, err_subleaf = -1, err_msr = -1;
    unsigned int nr_leaves = ARRAY_SIZE(policy->leaves);
    unsigned int nr_msrs = ARRAY_SIZE(policy->msrs);
    int rc;

    rc = xc_cpu_policy_serialise(xch, policy, policy->leaves, &nr_leaves,
                                 policy->msrs, &nr_msrs);
    if ( rc )
        return rc;

    rc = xc_set_domain_cpu_policy(xch, domid, nr_leaves, policy->leaves,
                                  nr_msrs, policy->msrs,
                                  &err_leaf, &err_subleaf, &err_msr);
    if ( rc )
    {
        ERROR("Failed to set domain %u policy (%d = %s)", domid, -rc,
              strerror(-rc));
        if ( err_leaf != -1 )
            ERROR("CPUID leaf %u subleaf %u", err_leaf, err_subleaf);
        if ( err_msr != -1 )
            ERROR("MSR index %#x\n", err_msr);
    }

    return rc;
}

int xc_cpu_policy_serialise(xc_interface *xch, const xc_cpu_policy_t *p,
                            xen_cpuid_leaf_t *leaves, uint32_t *nr_leaves,
                            xen_msr_entry_t *msrs, uint32_t *nr_msrs)
{
    int rc;

    if ( leaves )
    {
        rc = x86_cpuid_copy_to_buffer(&p->policy, leaves, nr_leaves);
        if ( rc )
        {
            ERROR("Failed to serialize CPUID policy");
            errno = -rc;
            return -1;
        }
    }

    if ( msrs )
    {
        rc = x86_msr_copy_to_buffer(&p->policy, msrs, nr_msrs);
        if ( rc )
        {
            ERROR("Failed to serialize MSR policy");
            errno = -rc;
            return -1;
        }
    }

    errno = 0;
    return 0;
}

int xc_cpu_policy_update_cpuid(xc_interface *xch, xc_cpu_policy_t *policy,
                               const xen_cpuid_leaf_t *leaves,
                               uint32_t nr)
{
    unsigned int err_leaf = -1, err_subleaf = -1;
    int rc = x86_cpuid_copy_from_buffer(&policy->policy, leaves, nr,
                                        &err_leaf, &err_subleaf);

    if ( rc )
    {
        if ( err_leaf != -1 )
            ERROR("Failed to update CPUID (err leaf %#x, subleaf %#x) (%d = %s)",
                  err_leaf, err_subleaf, -rc, strerror(-rc));
        errno = -rc;
        rc = -1;
    }

    return rc;
}

int xc_cpu_policy_update_msrs(xc_interface *xch, xc_cpu_policy_t *policy,
                              const xen_msr_entry_t *msrs, uint32_t nr)
{
    unsigned int err_msr = -1;
    int rc = x86_msr_copy_from_buffer(&policy->policy, msrs, nr, &err_msr);

    if ( rc )
    {
        if ( err_msr != -1 )
            ERROR("Failed to deserialise MSRS (err index %#x) (%d = %s)",
                  err_msr, -rc, strerror(-rc));
        errno = -rc;
        rc = -1;
    }

    return rc;
}

bool xc_cpu_policy_is_compatible(xc_interface *xch, xc_cpu_policy_t *host,
                                 xc_cpu_policy_t *guest)
{
    struct cpu_policy_errors err = INIT_CPU_POLICY_ERRORS;
    int rc = x86_cpu_policies_are_compatible(&host->policy, &guest->policy, &err);

    if ( !rc )
        return true;

    if ( err.leaf != -1 )
        ERROR("Leaf %#x subleaf %#x is not compatible", err.leaf, err.subleaf);
    if ( err.msr != -1 )
        ERROR("MSR index %#x is not compatible", err.msr);

    return false;
}

/*
 * Combine @p1 and @p2 which expected to be Guest PV/HVM default featuresets.
 *
 * Neither policy are necesserily relevant to this host, so no querying
 * Xen. The caller passes us 3 bitmaps (p1, p2, out) of @len words.
 *
 * This is mostly an intersection of p1 and p2, but a few features need
 * unioning, and some need calculating specifically.
 */
void xc_combine_cpu_featuresets(
    const uint32_t *p1, const uint32_t *p2, uint32_t *out, size_t len)
{
    static const uint32_t or[] = INIT_SIMPLE_OR;

    size_t i;

    /* Mostly an intersection.  A few features are unioned, although ... */
    for ( i = 0; i < len; ++i )
    {
        out[i] = p1[i] & p2[i];

        if ( i < ARRAY_SIZE(or) && or[i] )
            out[i] |= (or[i] & (p1[i] | p2[i]));
    }

    /* ... they might have unmet dependenices. */
    clear_deep_deps(out, len);

    /*
     * Recalculate the RSBA/RRSBA bit.  If either p1 or p2 suffer any form of
     * (R)RSBA, so must the resulting policy, and which depends on whether the
     * eIBRS is visible.
     */
    if ( len > (X86_FEATURE_EIBRS >> 5) &&
         test_bit(X86_FEATURE_ARCH_CAPS, out) &&
         (test_bit(X86_FEATURE_RSBA, p1) || test_bit(X86_FEATURE_RRSBA, p1) ||
          test_bit(X86_FEATURE_RSBA, p2) || test_bit(X86_FEATURE_RRSBA, p2)) )
    {
        bool eibrs = test_bit(X86_FEATURE_EIBRS, out);

        clear_bit(X86_FEATURE_RSBA, out);
        clear_bit(X86_FEATURE_RRSBA, out);

        set_bit(eibrs ? X86_FEATURE_RRSBA
                      : X86_FEATURE_RSBA, out);
    }
}

static const struct bit_name {
    const char *name;
    unsigned int bit;
} bit_names[] = INIT_BIT_NAMES;

static int compare_bit_name(const void *_l, const void *_r)
{
    const struct bit_name *l = _l, *r = _r;

    return l->bit - r->bit;
}

static const char *feat_name(unsigned int feat)
{
    struct bit_name key = { .bit = feat }, *res;

    res = bsearch(&key, bit_names, ARRAY_SIZE(bit_names),
                  sizeof(bit_names[0]), compare_bit_name);

    return res ? res->name : NULL;
}

/*
 * Check if @vm can run on @host.  The caller passes t bitmaps (vm, host) of
 * @len words, and some scratch space for an error string.
 *
 * Returns NULL on success, or a string describing the missing features on
 * error.
 */
const char *xc_cpu_featuresets_are_compatible(
    const uint32_t *vm, const uint32_t *host, size_t len, char err[128])
{
    size_t i, space = 128;
    uint32_t missing;
    char *p = err;

    for ( i = 0; i < len; ++i )
    {
        missing = vm[i] & ~host[i];
        if ( missing )
            goto not_compatible;
    }

    /* Compatible */
    return NULL;

 not_compatible:
    /* Not compatible.  Render the missing features. */

    while ( missing && (p - err) < 128 )
    {
        unsigned int bit = ffs(missing) - 1;
        uint32_t feat = i * 32 + bit;
        const char *name = feat_name(feat);
        int nr;

        if ( name )
            nr = snprintf(p, space, " %s", name);
        else
            nr = snprintf(p, space, " <%zu*32+%u>", i, bit);

        p += nr;
        missing &= ~(1u << bit);
    }
    err[127] = '\0';

    return err + 1; /* Trim leading space */
}

/*
 * Copyright (C) 2006-2009 Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "xg_internal.h"

#include <xen/hvm/hvm_info_table.h>
#include <xen/hvm/hvm_xs_strings.h>
#include <xen/hvm/params.h>
#include <xen/hvm/e820.h>

#include "libacpi/libacpi.h"

#include <xentoolcore_internal.h>

enum {
#define XEN_CPUFEATURE(name, value) X86_FEATURE_##name = value,
#include <xen/arch-x86/cpufeatureset.h>
};

char *xs_domain_path = NULL;
char *pci_passthrough_sbdf_list = NULL;

#define SYSFS_PCI_DEV "/sys/bus/pci/devices"
#define PCI_SBDF      "%04x:%02x:%02x.%01x"

static void failwith_oss_xc(const char *msg)
{
    const xc_error *error = xc_get_last_error(xch);

    if ( error->code == XC_ERROR_NONE )
        xg_err("xenguest: %s: [%d] %s\n", msg, errno, strerror(errno));
    else
        xg_err("xenguest: %s: [%d] %s\n", msg, error->code, error->message);

    exit(EXIT_FAILURE);
}

/*
 * The following boolean flags are all set by their value in the platform area
 * of xenstore. The only value that is considered true is the string 'true'
 */
struct flags {
    xc_domaininfo_t dominfo;
    int vcpus;
    int vcpus_current;
    char **vcpu_affinity;   /* 0 means unset */
    uint16_t vcpu_weight;   /* 0 means unset (0 is an illegal weight) */
    uint16_t vcpu_cap;      /* 0 is default (no cap) */
    int nx;
    int viridian;
    int viridian_time_ref_count;
    int viridian_reference_tsc;
    int viridian_hcall_remote_tlb_flush;
    int viridian_apic_assist;
    int viridian_crash_ctl;
    int viridian_stimer;
    int viridian_hcall_ipi;
    int pae;
    int acpi;
    int apic;
    int acpi_s3;
    int acpi_s4;
    int tsc_mode;
    int hpet;
    int nomigrate;
    int nested_virt;
    unsigned cores_per_socket;
    unsigned x87_fip_width;
    int64_t timeoffset;
};

char *xenstore_getsv(const char *fmt, va_list ap)
{
    char *s = NULL;
    int n, m;
    char key[1024] = { 0 };

    n = snprintf(key, sizeof(key), "%s/", xs_domain_path);
    if ( n < 0 )
        goto out;
    m = vsnprintf(key + n, sizeof(key) - n, fmt, ap);
    if ( m < 0 )
        goto out;

    s = xs_read(xsh, XBT_NULL, key, NULL);
out:
    return s;
}

char *xenstore_gets(const char *fmt, ...)
{
    char *s;
    va_list ap;

    va_start(ap, fmt);
    s = xenstore_getsv(fmt, ap);
    va_end(ap);

    return s;
}

uint64_t xenstore_get_value(bool *valid, const char *fmt, ...)
{
    char *s;
    uint64_t value = 0;
    va_list ap;
    bool got_value = true;

    va_start(ap, fmt);
    s = xenstore_getsv(fmt, ap);
    if ( s )
    {
        if ( !strcasecmp(s, "true") )
            value = 1;
        else if ( !strcasecmp(s, "false") )
            value = 0;
        else
        {
            errno = 0;
            value = strtoull(s, NULL, 0);
            if ( errno )
            {
                value = 0;
                got_value = false;
            }
        }
        free(s);
    }
    else
        got_value = false;

    if ( valid )
        *valid = got_value;
    va_end(ap);

    return value;
}

uint64_t xenstore_get(const char *fmt, ...)
{
    uint64_t value;
    va_list ap;

    va_start(ap, fmt);
    value = xenstore_get_value(NULL, fmt, ap);
    va_end(ap);

    return value;
}

int xenstore_putsv(const char *_key, const char *fmt, ...)
{
    int n, m, rc = -1;
    char key[512], val[512];
    va_list ap;

    n = snprintf(key, sizeof(key), "%s/%s", xs_domain_path, _key);
    if ( n < 0 )
        goto out;

    va_start(ap, fmt);
    m = vsnprintf(val, sizeof(val), fmt, ap);
    va_end(ap);

    if ( m < 0 )
        goto out;

    rc = xs_write(xsh, XBT_NULL, key, val, strlen(val));
out:
    return rc;
}

int xenstore_puts(const char *key, const char *val)
{
    return xenstore_putsv(key, "%s", val);
}

static uint32_t *host_featureset, *featureset, nr_features;

/*
 * Choose the featureset to use for a VM.
 *
 * The toolstack is expected to provide a featureset in the
 * platform/featureset xenstore key, fomatted as a bitmap of '-' delimited
 * 32bit hex-encoded words.  e.g.
 *
 *   aaaaaaaa-bbbbbbbb-cccccccc
 *
 * If no featureset is found, default to the host maximum.  It is important in
 * a heterogenous case to permit featuresets longer than this hosts maximum,
 * if they have been zero-extended to make a common longest length.
 */
static int get_vm_featureset(bool hvm)
{
    char *platform = xenstore_gets("platform/featureset");
    char *s = platform, *e;
    unsigned int i = 0;
    int rc = 0;

    if ( !platform )
    {
        xg_info("No featureset provided - using host maximum\n");

        return xc_get_cpu_featureset(xch,
                                     hvm ? XEN_SYSCTL_cpu_featureset_hvm
                                         : XEN_SYSCTL_cpu_featureset_pv,
                                     &nr_features, featureset);
    }
    else
        xg_info("Parsing '%s' as featureset\n", platform);

    while ( *s != '\0' )
    {
        unsigned long val;

        errno = 0;
        val = strtoul(s, &e, 16);
        if ( (errno != 0) ||            /* Error converting. */
             (val > ~(uint32_t)0) ||    /* Value out of range. */
             (e == s) ||                /* No digits found. */
                                        /* Bad following characters. */
             !(*e == '\0' || *e == '-' || *e == ':')
            )
        {
            xg_err("Bad '%s' in featureset\n", s);
            rc = -1;
            break;
        }

        if ( i < nr_features )
            featureset[i++] = val;
        else if ( val != 0 )
        {
            xg_err("Requested featureset '%s' truncated on this host\n", platform);
            rc = -1;
            break;
        }

        s = e;
        if ( *s == '-' || *s == ':' )
            s++;
    }

    free(platform);
    return rc;
}

static int construct_cpuid_policy(const struct flags *f, bool hvm, bool restore)
{
    int rc = -1;

    if ( xc_get_cpu_featureset(xch,
                               XEN_SYSCTL_cpu_featureset_host,
                               &nr_features, NULL) ||
         nr_features == 0 )
    {
        xg_err("Failed to obtain featureset size %d %s\n",
               errno, strerror(errno));
        goto out;
    }

    host_featureset = calloc(nr_features, sizeof(*host_featureset));
    featureset = calloc(nr_features, sizeof(*featureset));
    if ( !host_featureset || !featureset )
    {
        xg_err("Failed to allocate memory for featureset\n");
        goto out;
    }

    if ( xc_get_cpu_featureset(xch,
                               XEN_SYSCTL_cpu_featureset_host,
                               &nr_features, host_featureset) ||
         nr_features == 0 )
    {
        xg_err("Failed to obtain featureset size %d %s\n",
               errno, strerror(errno));
        goto out;
    }

    if ( get_vm_featureset(hvm) )
        goto out;

    if ( !f->nx )
        clear_bit(X86_FEATURE_NX, featureset);

    if ( !f->pae )
        clear_bit(X86_FEATURE_PAE, featureset);

    /*
     * Optionally advertise ITSC, given hardware support an a non-migratealbe
     * domain.
     */
    if ( f->nomigrate && test_bit(X86_FEATURE_ITSC, host_featureset) )
        set_bit(X86_FEATURE_ITSC, featureset);

    rc = xc_cpuid_apply_policy(xch, domid, restore, featureset, nr_features,
                               0, 0, f->nested_virt, f->cores_per_socket, NULL, NULL);

out:
    free(featureset);
    featureset = NULL;
    return rc;
}

static int hvmloader_flag(const char *key)
{
    /*
     * Params going to hvmloader need to convert "true" -> '1' as Xapi gets
     * this wrong when migrating from older hosts.
     */
    char *val = xenstore_gets("%s", key);
    int ret = -1;

    if ( val )
    {
        if ( !strcmp(val, "1") )
        {
            ret = 1;
            goto out;
        }
        else if ( !strcmp(val, "0") )
        {
            ret = 0;
            goto out;
        }
        if ( !strcasecmp(val, "true") )
            ret = 1;
        else
        {
            errno = 0;
            ret = strtol(val, NULL, 0);
            if ( errno )
                ret = 0;
        }

        xg_info("HVMLoader error: Fixing up key '%s' from '%s' to '%d'\n", key, val, ret);
        xenstore_putsv(key, "%d", !!ret);
    }
    else
        xenstore_puts(key, "0");

out:
    free(val);
    return ret;
}

static void get_flags(struct flags *f)
{
    char *tmp;
    int n;
    bool stimer_set;

    if ( xc_domain_getinfo_single(xch, domid, &f->dominfo) < 0 )
        failwith_oss_xc("xc_domain_getinfo");

    f->vcpus = xenstore_get("platform/vcpu/number");
    f->vcpu_affinity = malloc(sizeof(char*) * f->vcpus);

    for ( n = 0; n < f->vcpus; n++ )
        f->vcpu_affinity[n] = xenstore_gets("platform/vcpu/%d/affinity", n);

    f->vcpus_current = xenstore_get("platform/vcpu/current");
    f->vcpu_weight = xenstore_get("platform/vcpu/weight");
    f->vcpu_cap = xenstore_get("platform/vcpu/cap");
    f->nx       = xenstore_get("platform/nx");
    f->viridian = xenstore_get("platform/viridian");

    f->viridian_time_ref_count = xenstore_get("platform/viridian_time_ref_count");
    f->viridian_reference_tsc = xenstore_get("platform/viridian_reference_tsc");
    f->viridian_hcall_remote_tlb_flush = xenstore_get("platform/viridian_hcall_remote_tlb_flush");
    f->viridian_apic_assist = xenstore_get("platform/viridian_apic_assist");
    f->viridian_crash_ctl = xenstore_get("platform/viridian_crash_ctl");
    f->viridian_stimer = xenstore_get_value(&stimer_set, "platform/viridian_stimer");

    /*
     * For vGPU-enabled VMs, it is unsafe to migrate VMs with time_ref_count
     * or reference_tsc enabled, but not stimer.
     * If stimer has not been explicitly set, but one of the other two
     * have been enabled, default stimer to enabled.
     */
    if ( opt_vgpu && !stimer_set &&
         (f->viridian_reference_tsc || f->viridian_time_ref_count) )
    {
        xg_info("vgpu attached and stimer not set - defaulting to enabled.\n");
        f->viridian_stimer = 1;
    }

    f->apic     = xenstore_get("platform/apic");
    f->pae      = xenstore_get("platform/pae");
    f->tsc_mode = xenstore_get("platform/tsc_mode");
    f->x87_fip_width = xenstore_get("platform/x87-fip-width");
    f->nomigrate = xenstore_get("platform/nomigrate");

    if ( f->dominfo.flags & XEN_DOMINF_hvm_guest )
    {
        unsigned int cps = xenstore_get("platform/cores-per-socket");

        if ( cps && (f->vcpus % cps) != 0 )
            xg_fatal("Bad cores/socket setting: %u (nr vcpus %u)\n",
                     cps, f->vcpus);

        /*
         * Must remain 0 for compatiblity with PV guests, which previously
         * ignores their cores-per-socket setting.
         */
        f->cores_per_socket = cps;
    }

    /*
     * Follow 'nested-virt' if present.  Fall back to checking
     * 'exp-nested-hvm' for compatibility.
     */
    tmp = xenstore_gets("platform/nested-virt");
    f->nested_virt = tmp
        ? xenstore_get("platform/nested-virt")
        : xenstore_get("platform/exp-nested-hvm");
    free(tmp);

    /* Nested virt doesn't currently work with migration. */
    if ( f->nested_virt )
        f->nomigrate = 1;

    /* Params going to hvmloader - need to convert "true" -> '1' as Xapi gets
     * this wrong when migrating from older hosts. */
    f->acpi    = hvmloader_flag("platform/acpi");
    f->acpi_s4 = hvmloader_flag("platform/acpi_s4");
    f->acpi_s3 = hvmloader_flag("platform/acpi_s3");

    /*
     * HACK - Migrated VMs wont have this xs key set, so the naive action
     * would result in the HPET mysteriously disappearing.  If the key is not
     * present then enable the hpet to match its default.
     */
    tmp = xenstore_gets("platform/hpet");
    if ( tmp && strlen(tmp) )
        f->hpet = xenstore_get("platform/hpet");
    else
        f->hpet = 1;
    free(tmp);

    tmp = xenstore_gets("platform/timeoffset");
    if ( tmp )
    {
        sscanf(tmp, "%" PRId64, &f->timeoffset);
        free(tmp);
    }

    xg_info("Domain Properties: Type %s, hap %u\n",
            (f->dominfo.flags & XEN_DOMINF_hvm_guest) ? "HVM" : "PV",
            !!(f->dominfo.flags & XEN_DOMINF_hap));

    xg_info("Determined the following parameters from xenstore:\n");
    xg_info("vcpu/number:%d vcpu/weight:%d vcpu/cap:%d\n",
            f->vcpus, f->vcpu_weight, f->vcpu_cap);
    xg_info("nx: %d, pae %d, cores-per-socket %u, x86-fip-width %u, nested %u\n",
            f->nx, f->pae, f->cores_per_socket, f->x87_fip_width, f->nested_virt);
    xg_info("apic: %d acpi: %d acpi_s4: %d acpi_s3: %d tsc_mode: %d hpet: %d\n",
            f->apic, f->acpi, f->acpi_s4, f->acpi_s3, f->tsc_mode, f->hpet);
    xg_info("nomigrate %d, timeoffset %" PRId64 "\n",
            f->nomigrate, f->timeoffset);
    xg_info("viridian: %d, time_ref_count: %d, reference_tsc: %d "
            "hcall_remote_tlb_flush: %d apic_assist: %d "
            "crash_ctl: %d stimer: %d hcall_ipi: %d\n",
            f->viridian, f->viridian_time_ref_count, f->viridian_reference_tsc,
            f->viridian_hcall_remote_tlb_flush, f->viridian_apic_assist,
            f->viridian_crash_ctl, f->viridian_stimer, f->viridian_hcall_ipi);

    for ( n = 0; n < f->vcpus; n++ )
        xg_info("vcpu/%d/affinity:%s\n",
                n, f->vcpu_affinity[n] ?: "unset");
}

static void free_flags(struct flags *f)
{
    for ( int n = 0; n < f->vcpus; ++n )
        free(f->vcpu_affinity[n]);
    free(f->vcpu_affinity);
}

static void configure_vcpus(struct flags *f)
{
    struct xen_domctl_sched_credit sdom;
    int i, j, r, size, pcpus_supplied, min;
    xc_cpumap_t cpumap;

    size = xc_get_cpumap_size(xch) * 8; /* array is of uint8_t */

    for ( i = 0; i < f->vcpus; i++ )
    {
        if ( !f->vcpu_affinity[i] )
            continue;

        pcpus_supplied = strlen(f->vcpu_affinity[i]);
        min = (pcpus_supplied < size)?pcpus_supplied:size;
        cpumap = xc_cpumap_alloc(xch);
        if ( cpumap == NULL )
            failwith_oss_xc("xc_cpumap_alloc");

        for ( j = 0; j < min; j++ )
        {
            if ( f->vcpu_affinity[i][j] == '1' )
                cpumap[j / 8] |= 1 << (j & 7);
        }
        r = xc_vcpu_setaffinity(xch, domid, i, cpumap, NULL,
                                XEN_VCPUAFFINITY_HARD);
        free(cpumap);
        if ( r )
            failwith_oss_xc("xc_vcpu_setaffinity");
    }

    r = xc_sched_credit_domain_get(xch, domid, &sdom);
    /* This should only happen when a different scheduler is set */
    if ( r )
    {
        xg_info("Failed to get credit scheduler parameters: scheduler not enabled?\n");
        return;
    }

    if ( f->vcpu_weight )
        sdom.weight = f->vcpu_weight;
    if ( f->vcpu_cap)
        sdom.cap = f->vcpu_cap;

    /*
     * This shouldn't fail, if "get" above succeeds. This error is fatal to
     * highlight the need to investigate further.
     */
    r = xc_sched_credit_domain_set(xch, domid, &sdom);
    if ( r )
        failwith_oss_xc("xc_sched_credit_domain_set");
}

static uint64_t get_image_max_size(const char *type)
{
    char key[64];
    char *s;
    uint64_t max_size = 0;

    snprintf(key, sizeof(key), "/mh/limits/pv-%s-max_size", type);

    s = xs_read(xsh, XBT_NULL, key, NULL);
    if ( s )
    {
        errno = 0;
        max_size = strtoull(s, NULL, 0);
        if ( errno )
            max_size = 0;
        free(s);
    }

    return max_size ?: XC_DOM_DECOMPRESS_MAX;
}

static void configure_tsc(struct flags *f)
{
    int rc = xc_domain_set_tsc_info(xch, domid, f->tsc_mode, 0, 0, 0);

    if ( rc )
        failwith_oss_xc("xc_domain_set_tsc_info");
}


int stub_xc_pv_build(int c_mem_max_mib, int mem_start_mib,
                     const char *image_name, const char *ramdisk_name,
                     const char *cmdline, const char *features,
                     int flags, int store_evtchn, int store_domid,
                     int console_evtchn, int console_domid,
                     unsigned long *store_mfn, unsigned long *console_mfn,
                     char *protocol)
{
    struct xc_dom_image *dom;
    struct flags f = {};

    get_flags(&f);

    dom = xc_dom_allocate(xch, cmdline, features);
    if ( !dom )
        failwith_oss_xc("xc_dom_allocate");

    dom->container_type = XC_DOM_PV_CONTAINER;

    /* The default image size limits are too large. */
    if ( xc_dom_kernel_max_size(dom, get_image_max_size("kernel")) )
        failwith_oss_xc("xc_dom_kernel_max_size");
    if ( xc_dom_module_max_size(dom, get_image_max_size("ramdisk")) )
        failwith_oss_xc("xc_dom_module_max_size");

    configure_vcpus(&f);
    configure_tsc(&f);

    if ( xc_dom_kernel_file(dom, image_name) )
        failwith_oss_xc("xc_dom_kernel_file");
    if ( ramdisk_name && strlen(ramdisk_name) &&
         xc_dom_module_file(dom, ramdisk_name, NULL) )
        failwith_oss_xc("xc_dom_module_file");

    dom->flags = flags;
    dom->console_evtchn = console_evtchn;
    dom->console_domid = console_domid;
    dom->xenstore_evtchn = store_evtchn;
    dom->xenstore_domid = store_domid;

    if ( xc_dom_boot_xen_init(dom, xch, domid) )
        failwith_oss_xc("xc_dom_boot_xen_init");
    if ( xc_dom_parse_image(dom) )
        failwith_oss_xc("xc_dom_parse_image");
    if ( xc_dom_mem_init(dom, mem_start_mib) )
        failwith_oss_xc("xc_dom_mem_init");
    if ( xc_dom_boot_mem_init(dom) )
        failwith_oss_xc("xc_dom_boot_mem_init");
    if ( xc_dom_build_image(dom) )
        failwith_oss_xc("xc_dom_build_image");
    if ( xc_dom_boot_image(dom) )
        failwith_oss_xc("xc_dom_boot_image");
    if ( xc_dom_gnttab_init(dom) )
        failwith_oss_xc("xc_dom_gnttab_init");

    *console_mfn = xc_dom_p2m(dom, dom->console_pfn);
    *store_mfn = xc_dom_p2m(dom, dom->xenstore_pfn);

    if ( construct_cpuid_policy(&f, false, false) )
        failwith_oss_xc("construct_cpuid_policy");

    strncpy(protocol, xc_domain_get_native_protocol(xch, domid), 64);

    free_flags(&f);
    xc_dom_release(dom);

    return 0;
}

static void hvm_init_info_table(struct hvm_info_table *va_hvm, struct flags *f)
{
    uint32_t i;
    uint8_t sum;

    va_hvm->apic_mode = f->apic;
    va_hvm->nr_vcpus = f->vcpus;
    memset(va_hvm->vcpu_online, 0, sizeof(va_hvm->vcpu_online));

    for ( i = 0; i < f->vcpus_current; i++ )
        va_hvm->vcpu_online[i / 8] |= 1 << (i % 8);

    va_hvm->checksum = 0;

    for ( i = 0, sum = 0; i < va_hvm->length; i++ )
        sum += ((uint8_t *) va_hvm)[i];

    va_hvm->checksum = -sum;
}

/* ACPI bits and pieces */
/* Most of this is from libxl_x86_acpi.c */

/* Number of pages holding ACPI tables */
#define NUM_ACPI_PAGES 16
/* Store RSDP in the last 64 bytes of BIOS RO memory */
#define RSDP_ADDRESS (0x100000 - 64)

#define ACPI_INFO_PHYSICAL_ADDRESS 0xfc000000
#define LAPIC_BASE_ADDRESS         0xfee00000

#define ALIGN(p, a) (((p) + ((a) - 1)) & ~((a) - 1))

struct xenguest_acpi_ctxt {
    struct acpi_ctxt c;

    unsigned int page_size;
    unsigned int page_shift;

    /* Memory allocator */
    unsigned long guest_start;
    unsigned long guest_curr;
    unsigned long guest_end;
    void *buf;
};

extern const unsigned char dsdt_pvh[];
extern const unsigned int dsdt_pvh_len;

/* Assumes contiguous physical space */
static unsigned long virt_to_phys(struct acpi_ctxt *ctxt, void *v)
{
    struct xenguest_acpi_ctxt *xenguest_ctxt =
        CONTAINER_OF(ctxt, struct xenguest_acpi_ctxt, c);

    return xenguest_ctxt->guest_start + (v - xenguest_ctxt->buf);
}

static void *mem_alloc(struct acpi_ctxt *ctxt,
                       uint32_t size, uint32_t align)
{
    struct xenguest_acpi_ctxt *xenguest_ctxt =
        CONTAINER_OF(ctxt, struct xenguest_acpi_ctxt, c);
    unsigned long s, e;

    /* Align to at least 16 bytes. */
    if ( align < 16 )
        align = 16;

    s = ALIGN(xenguest_ctxt->guest_curr, align);
    e = s + size - 1;

    /* TODO: Reallocate memory */
    if ( (e < s) || (e >= xenguest_ctxt->guest_end) )
        return NULL;

    xenguest_ctxt->guest_curr = e;

    return xenguest_ctxt->buf + (s - xenguest_ctxt->guest_start);
}

static void acpi_mem_free(struct acpi_ctxt *ctxt,
                          void *v, uint32_t size)
{
}

static uint32_t acpi_lapic_id(unsigned cpu)
{
    return cpu * 2;
}

static int init_acpi_config(struct xc_dom_image *dom,
                            struct flags *f,
                            struct acpi_config *config)
{
    xc_domaininfo_t info;
    struct hvm_info_table *hvminfo;
    int r;

    config->dsdt_anycpu = config->dsdt_15cpu = dsdt_pvh;
    config->dsdt_anycpu_len = config->dsdt_15cpu_len = dsdt_pvh_len;

    r = xc_domain_getinfo_single(xch, domid, &info);
    if ( r < 0 )
    {
        xg_err("getdomaininfo failed (rc=%d)", r);

        return -1;
    }

    hvminfo = xc_dom_malloc(dom, sizeof(*hvminfo));
    if ( !hvminfo )
        return -ENOMEM;

    hvm_init_info_table(hvminfo, f);

    config->hvminfo = hvminfo;

    config->lapic_base_address = LAPIC_BASE_ADDRESS;
    config->lapic_id = acpi_lapic_id;
    config->acpi_revision = 5;

    return 0;
}

int xenguest_dom_load_acpi(struct xc_dom_image *dom,
                           struct flags *f)
{
    struct acpi_config config = {0};
    struct xenguest_acpi_ctxt xenguest_ctxt;
    int rc = 0, acpi_pages_num;

    xenguest_ctxt.page_size = XC_DOM_PAGE_SIZE(dom);
    xenguest_ctxt.page_shift =  XC_DOM_PAGE_SHIFT(dom);

    xenguest_ctxt.c.mem_ops.alloc = mem_alloc;
    xenguest_ctxt.c.mem_ops.v2p = virt_to_phys;
    xenguest_ctxt.c.mem_ops.free = acpi_mem_free;

    rc = init_acpi_config(dom, f, &config);
    if ( rc )
    {
        xg_err("init_acpi_config failed (rc=%d)", rc);
        goto out;
    }

    config.rsdp = (unsigned long)malloc(xenguest_ctxt.page_size);
    config.infop = (unsigned long)malloc(xenguest_ctxt.page_size);
    /* Pages to hold ACPI tables */
    xenguest_ctxt.buf = malloc(NUM_ACPI_PAGES * xenguest_ctxt.page_size);

    if ( !config.rsdp || !config.infop || !xenguest_ctxt.buf )
        return -ENOMEM;

    /*
     * Set up allocator memory.
     * Start next to acpi_info page to avoid fracturing e820.
     */
    xenguest_ctxt.guest_start = xenguest_ctxt.guest_curr = xenguest_ctxt.guest_end =
        ACPI_INFO_PHYSICAL_ADDRESS + xenguest_ctxt.page_size;

    xenguest_ctxt.guest_end += NUM_ACPI_PAGES * xenguest_ctxt.page_size;

    /* Build the tables. */
    rc = acpi_build_tables(&xenguest_ctxt.c, &config);
    if ( rc )
    {
        xg_err("acpi_build_tables failed with %d", rc);
        goto out;
    }

    /* Calculate how many pages are needed for the tables. */
    acpi_pages_num = (ALIGN(xenguest_ctxt.guest_curr, xenguest_ctxt.page_size) -
                      xenguest_ctxt.guest_start) >> xenguest_ctxt.page_shift;

    dom->acpi_modules[0].data = (void *)config.rsdp;
    dom->acpi_modules[0].length = 64;
    dom->acpi_modules[0].guest_addr_out = RSDP_ADDRESS;

    dom->acpi_modules[1].data = (void *)config.infop;
    dom->acpi_modules[1].length = 4096;
    dom->acpi_modules[1].guest_addr_out = ACPI_INFO_PHYSICAL_ADDRESS;

    dom->acpi_modules[2].data = xenguest_ctxt.buf;
    dom->acpi_modules[2].length = acpi_pages_num  << xenguest_ctxt.page_shift;
    dom->acpi_modules[2].guest_addr_out = ACPI_INFO_PHYSICAL_ADDRESS +
        xenguest_ctxt.page_size;

out:
    return rc;
}

static void hvm_set_viridian_features(struct flags *f)
{
    uint64_t feature_mask = HVMPV_base_freq | HVMPV_cpu_hotplug;

    xg_info("viridian base\n");

    if ( f->viridian_time_ref_count )
    {
        xg_info("+ time_ref_count\n");
        feature_mask |= HVMPV_time_ref_count;
    }

    if ( f->viridian_reference_tsc )
    {
        xg_info("+ reference_tsc\n");
        feature_mask |= HVMPV_reference_tsc;
    }

    if ( f->viridian_hcall_remote_tlb_flush )
    {
        xg_info("+ hcall_remote_tlb_flush\n");
        feature_mask |= HVMPV_hcall_remote_tlb_flush;
    }

    if ( f->viridian_apic_assist )
    {
        xg_info("+ apic_assist\n");
        feature_mask |= HVMPV_apic_assist;
    }

    if ( f->viridian_crash_ctl )
    {
        xg_info("+ crash_ctl\n");
        feature_mask |= HVMPV_crash_ctl;
    }

    if ( f->viridian_stimer )
    {
        xg_info("+ stimer\n");
        feature_mask |= HVMPV_synic | HVMPV_stimer;
    }

    if ( f->viridian_hcall_ipi )
    {
        xg_info("+ hcall_ipi\n");
        feature_mask |= HVMPV_hcall_ipi;
    }

    xc_set_hvm_param(xch, domid, HVM_PARAM_VIRIDIAN, feature_mask);
}

static int hvm_build_set_params(bool is_pvh, struct flags *f)
{
    struct hvm_info_table *va_hvm;
    uint8_t *va_map;
    int rc = 0;

    if ( !is_pvh )
    {
        va_map = xc_map_foreign_range(xch, domid,
                                      XC_PAGE_SIZE, PROT_READ | PROT_WRITE,
                                      HVM_INFO_PFN);
        if ( va_map == NULL )
            return -1;

        va_hvm = (struct hvm_info_table *)(va_map + HVM_INFO_OFFSET);
        hvm_init_info_table(va_hvm, f);
        munmap(va_map, XC_PAGE_SIZE);
    }

    if ( f->viridian )
        hvm_set_viridian_features(f);

    xc_set_hvm_param(xch, domid, HVM_PARAM_HPET_ENABLED, f->hpet);
    xc_set_hvm_param(xch, domid, HVM_PARAM_TRIPLE_FAULT_REASON, SHUTDOWN_crash);

    /*
     * If an specific FIP width is requested, only allow it to
     * override auto-mode.
     */
    if ( f->x87_fip_width )
    {
        uint64_t old = 0;

        xc_hvm_param_get(xch, domid, HVM_PARAM_X87_FIP_WIDTH, &old);
        if ( !old )
            xc_hvm_param_set(xch, domid, HVM_PARAM_X87_FIP_WIDTH, f->x87_fip_width);
    }

    rc = xc_domain_set_time_offset(xch, domid, f->timeoffset);

    return rc;
}

#ifdef OVMF_PATH
/*
 * Returns the path to the OVMF firmware. Caller must free() the path on
 * success. Returns 0 on success or -errno on failure.
 */
static int get_ovmf_path(char **path_out)
{
    char *key = xenstore_gets("platform/ovmf-override");

    if ( key )
    {
        char *dir, *path;
        int ret = 0;

        /* Check the xenstore key is a simple filename */
        if ( strchr(key, '/') )
        {
            xg_err("ovmf-override key '%s' must be a filename, not a path\n", key);
            free(key);
            return -EINVAL;
        }

        /* Construct a path relative to the directory of the default path */
        dir = strdup(OVMF_PATH);
        if ( !dir )
        {
            ret = -errno;
            free(key);
            return ret;
        }

        if ( asprintf(&path, "%s/%s", dirname(dir), key) == -1 )
        {
            ret = -errno;
            path = NULL;
        }

        free(dir);
        free(key);

        *path_out = path;
        return ret;
    }

    *path_out = strdup(OVMF_PATH);
    return *path_out ? 0 : -errno;
}
#endif

/*
 * Loads the appropriate firmware according to the xenstore key
 * "hvmloader/bios". Does nothing if the key is not present or empty.
 * Returns an error if requested to load an unknown firmware type.
 * Returns 0 on success or -errno on failure.
 */
static int hvm_load_firmware_module(struct xc_dom_image *dom)
{
    struct stat st;
    struct xc_hvm_firmware_module *m = &dom->system_firmware_module;
    char *tmp = xenstore_gets("hvmloader/bios");
    char *path = NULL;
    int ret, fd;

    if ( !tmp || !strcmp(tmp, "") )
        return 0;

    if ( strcmp(tmp, "ovmf") )
    {
        xg_err("Unsupported bios type '%s'\n", tmp);
        free(tmp);
        return -ENOTSUP;
    }
    free(tmp);

#ifdef OVMF_PATH
    ret = get_ovmf_path(&path);
    if ( ret )
        return ret;

    fd = open(path, O_RDONLY | O_NOFOLLOW);
    if ( fd == -1 )
    {
        ret = -errno;
        goto out;
    }

    if ( fstat(fd, &st) == -1 )
    {
        ret = -errno;
        goto out;
    }

    m->length = st.st_size;
    m->data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if ( m->data == MAP_FAILED )
    {
        ret = -errno;
        goto out;
    }

    xg_info("Loaded OVMF from %s\n", path);
    ret = 0;

out:
    free(path);
    if ( fd >= 0 )
        close(fd);

    return ret;
#else
    xg_err("Unsupported bios type 'ovmf'\n");
    return -ENOTSUP;
#endif
}

static int pci_get_id(uint16_t seg, uint8_t bus, uint8_t dev, uint8_t func,
                      const char *type, uint16_t *id)
{
    char namebuf[64], buf[32];
    FILE *file;

    snprintf(namebuf, sizeof(namebuf), SYSFS_PCI_DEV"/"PCI_SBDF"/%s",
             seg, bus, dev, func, type);

    file = fopen(namebuf, "r");
    if ( !file )
    {
        xg_err("Cannot open '%s': %s\n", namebuf, strerror(errno));
        return -1;
    }

    if ( !fgets(buf, sizeof(buf), file) )
    {
        xg_err("Cannot read %s id from '%s': %s\n",
               type, namebuf, strerror(errno));
        fclose(file);
        return -1;
    }

    if ( sscanf(buf, "%"SCNx16, id) != 1 )
    {
        xg_err("Invalid %s id\n", type);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

static int get_mmio_dev(uint16_t seg, uint8_t bus, uint8_t dev, uint8_t func,
                        uint64_t *mmio_dev)
{
    char namebuf[64], buf[256];
    FILE *file;
    int i, rc = 0;

    snprintf(namebuf, sizeof(namebuf), SYSFS_PCI_DEV"/"PCI_SBDF"/resource",
             seg, bus, dev, func);

    file = fopen(namebuf, "r");
    if ( !file )
    {
        xg_err("Cannot open '%s': %s\n", namebuf, strerror(errno));
        return -1;
    }

    *mmio_dev = 0;
    for ( i = 0; i < 7; i++ )
    {
        unsigned long long start, end, size, flags;

        if ( !fgets(buf, sizeof(buf), file) )
            break;

        if ( sscanf(buf, "%llx %llx %llx", &start, &end, &flags) != 3 )
        {
            xg_err("Syntax error in '%s'\n", namebuf);
            rc = -1;
            goto out;
        }

        if ( start )
            size = end - start + 1;
        else
            size = 0;

        *mmio_dev += size;
    }
out:
    fclose(file);
    return rc;
}

static int get_rdm(uint16_t seg, uint8_t bus, uint8_t devfn,
                   unsigned int *nr_entries,
                   struct xen_reserved_device_memory **xrdm)
{
    int rc = 0, r;

    *nr_entries = 0;
    r = xc_reserved_device_memory_map(xch, 0, seg, bus, devfn,
                                      NULL, nr_entries);
    /* "0" means we have no any rdm entry. */
    if ( !r )
        goto out;

    if ( errno != ENOBUFS )
    {
        rc = -1;
        goto out;
    }

    *xrdm = malloc(sizeof(**xrdm) * (*nr_entries));
    if ( !*xrdm )
        rc = -1;

    r = xc_reserved_device_memory_map(xch, 0, seg, bus, devfn,
                                      *xrdm, nr_entries);
    if ( r )
        rc = -1;
out:
    return rc;
}

/* Copied from xen hypervisor itself */
const char *parse_pci_sbdf(char *s, unsigned int *seg_p,
                           unsigned int *bus_p, unsigned int *dev_p,
                           unsigned int *func_p)
{
    unsigned long seg = strtoul(s, &s, 16), bus, dev, func;

    if ( *s != ':' )
        return NULL;
    bus = strtoul(s + 1, &s, 16);
    if ( *s == ':' )
        dev = strtoul(s + 1, &s, 16);
    else
    {
        dev = bus;
        bus = seg;
        seg = 0;
    }
    if ( func_p )
    {
        if ( *s != '.' )
            return NULL;
        func = strtoul(s + 1, &s, 0);
    }
    else
        func = 0;

    if ( seg_p )
        *seg_p = seg;
    *bus_p = bus;
    *dev_p = dev;
    if ( func_p )
        *func_p = func;

    return s;
}

#define MAX_RMRR_DEVICES E820MAX
#define ALLOW_MEMORY_RELOCATE 1
#define VRAM_RESERVED_ADDR_INIT 0xfb000000lu
#define VRAM_RESERVED_SIZE 0x1000000lu

int hvm_build_setup_mem(struct xc_dom_image *dom, uint64_t max_mem_mib,
                        uint64_t max_start_mib)
{
    uint64_t lowmem_end, highmem_start, highmem_end, mmio_start, mmio_size;
    uint64_t mmio_total = HVM_BELOW_4G_MMIO_LENGTH;
    unsigned int i, j, nr = 0;
    struct e820entry *e820;
    unsigned int nr_rdm_entries[MAX_RMRR_DEVICES] = {0};
    unsigned int nr_rmrr_devs = 0;
    struct xen_reserved_device_memory *xrdm[MAX_RMRR_DEVICES] = {0};
    unsigned long rmrr_overlapped_ram = 0;
    bool allow_memory_relocate = ALLOW_MEMORY_RELOCATE;
    bool apply_mxgpu_workaround = false;
    char *s;
    int ret;

    if ( pci_passthrough_sbdf_list )
    {
        s = strtok(pci_passthrough_sbdf_list , ",");

        while ( s != NULL )
        {
            unsigned int seg, bus, device, func;
            uint64_t mmio_dev;
            uint16_t vendor_id, device_id;

            if ( !parse_pci_sbdf(s, &seg, &bus, &device, &func) )
            {
                s = strtok (NULL, ",");
                continue;
            }

            xg_info("Getting RMRRs for device '%s'\n",s);
            if ( !get_rdm(seg, bus, (device << 3) + func,
                          &nr_rdm_entries[nr_rmrr_devs], &xrdm[nr_rmrr_devs]) )
            {
                if ( nr_rdm_entries[nr_rmrr_devs] != 0 )
                    nr_rmrr_devs++;

                if ( nr_rmrr_devs == MAX_RMRR_DEVICES )
                    xg_fatal("Error: hit limit of %d RMRR devices for domain\n",
                             MAX_RMRR_DEVICES);
            }

            xg_info("Getting total MMIO space occupied for device '%s'\n",s);

            if ( get_mmio_dev(seg, bus, device, func, &mmio_dev) )
                xg_fatal("Error: unable to get PCI MMIO info\n");

            mmio_total += mmio_dev;

            if ( !pci_get_id(seg, bus, device, func, "vendor", &vendor_id) &&
                 vendor_id == 0x1002 &&
                 !pci_get_id(seg, bus, device, func, "device", &device_id) &&
                 device_id == 0x692f )
            {
                xg_info("MxGPU device found. Applying MMIO hole workaround\n");
                apply_mxgpu_workaround = true;
            }

            s = strtok(NULL, ",");
        }
    }

    e820 = malloc(sizeof(*e820) * E820MAX);
    if ( !e820 )
	    return -ENOMEM;

    dom->target_pages = max_start_mib << (20 - XC_PAGE_SHIFT);

    lowmem_end  = max_mem_mib << 20;
    highmem_end = highmem_start = 1ull << 32;
    mmio_size   = HVM_BELOW_4G_MMIO_LENGTH;

    if ( opt_vgpu )
    {
        /*
         * Make additional room for vGPU BARs in low MMIO hole
         * as the existing NVIDIA drivers are unable to handle
         * 64-bit BARs properly.
         */
        xg_info("NVIDIA vGPU plugged in. Add extra 0x%lx to MMIO hole\n", mmio_size);
        mmio_total += mmio_size;
        mmio_size <<= 1;
    }

    if ( allow_memory_relocate )
    {
        while ( mmio_size < mmio_total && (uint32_t)(mmio_size << 1) != 0 )
            mmio_size <<= 1;

        if ( apply_mxgpu_workaround )
        {
            /*
             * The S7150x2 cards have buggy PLX bridges so boost the
             * low MMIO hole to at least 2G to make sure no guest RAM
             * aliases any ranges in use by those bridges.
             */
            if ( mmio_size < 0x80000000 )
                mmio_size = 0x80000000;
        }

        xg_info("Calculated provisional MMIO hole size as 0x%lx\n", mmio_size);
    }

    mmio_start  = highmem_start - mmio_size;

    if ( lowmem_end > mmio_start )
    {
        highmem_end = (1ull << 32) + (lowmem_end - mmio_start);
        lowmem_end = mmio_start;
    }

    /* Leave low 1MB to HVMLoader... */
    e820[nr].addr = 0x100000u;
    e820[nr].size = lowmem_end - 0x100000u;
    e820[nr].type = E820_RAM;
    nr++;

    /* RDM mapping */
    for ( i = 0; i < nr_rmrr_devs; i++ )
    {
        for ( j = 0; j < nr_rdm_entries[i] && nr < E820MAX - 2; j++ )
        {
            e820[nr].addr = xrdm[i][j].start_pfn << XC_PAGE_SHIFT;
            e820[nr].size = xrdm[i][j].nr_pages << XC_PAGE_SHIFT;
            e820[nr].type = E820_RESERVED;
            xg_info("Adding RMRR 0x%lx size 0x%lx\n", e820[nr].addr, e820[nr].size);

            if ( e820[nr].addr < lowmem_end )
            {
                rmrr_overlapped_ram += ( lowmem_end - e820[nr].addr );
                lowmem_end = e820[nr].addr;
            }
            nr++;
        }
        free(xrdm[i]);
    }

    if ( nr == E820MAX - 2 )
        xg_fatal("Error: too many E820 reserved entries for domain\n");

    e820[0].size -= rmrr_overlapped_ram;
    highmem_end += rmrr_overlapped_ram;
    mmio_size += rmrr_overlapped_ram;
    mmio_start -= rmrr_overlapped_ram;

    if ( highmem_end > highmem_start )
    {
        e820[nr].addr = highmem_start;
        e820[nr].size = highmem_end - e820[nr].addr;
        e820[nr].type = E820_RAM;
        nr++;
    }

    /* Select VRAM reserved region for vGPU within MMIO hole */
    if ( opt_vgpu )
    {
        uint64_t vram_reserved_addr = VRAM_RESERVED_ADDR_INIT;

        while ( vram_reserved_addr >= mmio_start )
        {
            for ( i = 0; i < nr; i++ )
                if ( (vram_reserved_addr + VRAM_RESERVED_SIZE > e820[i].addr) &&
                     (vram_reserved_addr < e820[i].addr + e820[i].size) )
                    break;
            if ( i == nr )
                break;
            vram_reserved_addr -= VRAM_RESERVED_SIZE;
        }

        if ( vram_reserved_addr < mmio_start )
            xg_fatal("Error: failed to allocate VRAM reserved region\n");

        e820[nr].addr = vram_reserved_addr;
        e820[nr].size = VRAM_RESERVED_SIZE;
        e820[nr].type = E820_RESERVED;
        nr++;

        xg_info("Reserve VRAM region at 0x%lx size 0x%lx for vGPU\n",
                vram_reserved_addr, VRAM_RESERVED_SIZE);
        /*
         * Put VRAM reserved region address and size to Xenstore so we could
         * read it later from DEMU
         */
        xenstore_putsv("vm-data/vram-reserved-addr", "%lx", vram_reserved_addr);
        xenstore_putsv("vm-data/vram-reserved-size", "%lu", VRAM_RESERVED_SIZE);
    }

    dom->lowmem_end = lowmem_end;
    dom->highmem_end = highmem_end;
    dom->mmio_size = mmio_size;
    dom->mmio_start = mmio_start;

    ret = hvm_load_firmware_module(dom);
    if ( ret )
        xg_fatal("xenguest: Failed to load firmware module: %s\n",
                 strerror(-ret));

    if ( xc_dom_mem_init(dom, max_mem_mib) )
        failwith_oss_xc("xc_dom_mem_init");
    if ( xc_dom_boot_mem_init(dom) )
        failwith_oss_xc("xc_dom_boot_mem_init");

    xg_info("Final lower MMIO hole size is 0x%lx\n", mmio_size);
    /*
     * Put the lower MMIO hole size to Xenstore so we could read it later from
     * QEMU wrapper
     */
    xenstore_putsv("vm-data/mmio-hole-size", "%lu", mmio_size);

    if ( xc_domain_set_memory_map(xch, domid, e820, nr) )
        failwith_oss_xc("xc_domain_set_memory_map");

    free(e820);

    return 0;
}

static int pvh_setup_mem(struct xc_dom_image *dom, uint64_t max_mem_mib,
                         uint64_t max_start_mib)
{
    uint64_t lowmem_end, highmem_start, highmem_end, mmio_start, mmio_size;

    if ( pci_passthrough_sbdf_list )
    {
        xg_err("PCI passthrough not supported under PVH");
        return -EINVAL;
    }

    dom->target_pages = max_start_mib << (20 - XC_PAGE_SHIFT);

    lowmem_end  = max_mem_mib << 20;
    highmem_end = highmem_start = 1ull << 32;
    mmio_size   = HVM_BELOW_4G_MMIO_LENGTH;

    mmio_start  = highmem_start - mmio_size;

    if ( lowmem_end > mmio_start )
    {
        highmem_end = (1ull << 32) + (lowmem_end - mmio_start);
        lowmem_end = mmio_start;
    }

    dom->lowmem_end = lowmem_end;
    dom->highmem_end = highmem_end;
    dom->mmio_size = mmio_size;
    dom->mmio_start = mmio_start;

    if ( xc_dom_mem_init(dom, max_mem_mib) )
        failwith_oss_xc("xc_dom_mem_init");
    if ( xc_dom_boot_mem_init(dom) )
        failwith_oss_xc("xc_dom_boot_mem_init");

    return 0;
}

static int pvh_setup_e820(struct xc_dom_image *dom)
{
    struct e820entry *e820;
    uint64_t lowmem_end, highmem_start, highmem_end;
    uint32_t lowmem_start = dom->device_model ? 0x100000u : 0;
    unsigned int i, nr = 0;

    lowmem_end = dom->lowmem_end;
    highmem_start = 1ull << 32;
    highmem_end = dom->highmem_end;

    e820 = malloc(sizeof(*e820) * E820MAX);
    if ( !e820 )
        return -ENOMEM;

    e820[nr].addr = lowmem_start;
    e820[nr].size = lowmem_end - lowmem_start;
    e820[nr].type = E820_RAM;
    nr++;

    for ( i = 0; i < MAX_ACPI_MODULES; i++ )
    {
        if ( dom->acpi_modules[i].length )
        {
            e820[nr].addr = dom->acpi_modules[i].guest_addr_out &
                            ~(XC_PAGE_SIZE - 1);
            e820[nr].size = dom->acpi_modules[i].length +
                (dom->acpi_modules[i].guest_addr_out & (XC_PAGE_SIZE - 1));
            e820[nr].type = E820_ACPI;
            nr++;
        }
    }

    if ( highmem_end > highmem_start )
    {
        e820[nr].addr = highmem_start;
        e820[nr].size = highmem_end - e820[nr].addr;
        e820[nr].type = E820_RAM;
        nr++;
    }

    if ( xc_domain_set_memory_map(xch, domid, e820, nr) )
        failwith_oss_xc("xc_domain_set_memory_map");

    free(e820);

    return 0;
}

static void hvm_safety_check(struct flags *f, bool pod)
{
    if ( force )
    {
        xg_info("--force in effect - skipping safety checks\n");
        return;
    }

    if ( pod )
    {
        if ( f->nested_virt )
            xg_fatal("Populate on Demand and Nested Virtualisation are mutually exclusive\n");

        if ( pci_passthrough_sbdf_list )
            xg_fatal("Populate on Demand and PCI Passthrough are mutually exclusive\n");
    }

    if ( !(f->dominfo.flags & XEN_DOMINF_hap) && f->nested_virt )
        xg_fatal("Shadow Paging and Nested Virtualisation are mutually exclusive\n");
}

int stub_xc_hvm_build(int mem_max_mib, int mem_start_mib,
                      const char *image_name, const char *cmdline,
                      const pvh_module *modules, int nmodules,
                      const char *features, int flags,
                      int store_evtchn, int store_domid,
                      int console_evtchn, int console_domid,
                      unsigned long *store_mfn, unsigned long *console_mfn,
                      bool is_pvh)
{
    int r, i;
    struct flags f = {};
    struct xc_dom_image *dom;

    get_flags(&f);

    hvm_safety_check(&f, mem_start_mib < mem_max_mib);

    configure_vcpus(&f);
    configure_tsc(&f);

    dom = xc_dom_allocate(xch, cmdline, NULL);
    if ( !dom )
        failwith_oss_xc("xc_dom_allocate");

    dom->container_type = XC_DOM_HVM_CONTAINER;
    dom->device_model = !is_pvh;
    dom->max_vcpus = f.vcpus;

    dom->console_evtchn = console_evtchn;
    dom->console_domid = console_domid;
    dom->xenstore_evtchn = store_evtchn;
    dom->xenstore_domid = store_domid;

    if ( is_pvh )
    {
        /* The default image size limits are too large. */
        if ( xc_dom_kernel_max_size(dom, get_image_max_size("kernel")) )
            failwith_oss_xc("xc_dom_kernel_max_size");
        if ( xc_dom_module_max_size(dom, get_image_max_size("ramdisk")) )
            failwith_oss_xc("xc_dom_module_max_size");
    }

    if ( xc_dom_kernel_file(dom, image_name) )
        failwith_oss_xc("xc_dom_kernel_file");

    if ( is_pvh )
    {
        for ( i = 0; i < nmodules; i++ )
        {
            if ( xc_dom_module_file(dom, modules[i].filename,
                                    modules[i].cmdline) )
                failwith_oss_xc("xc_dom_module_file");
        }
    }
    else /* HVM */
    {
        if ( xc_dom_module_file(dom, IPXE_PATH, "ipxe") )
            failwith_oss_xc("xc_dom_module_file");
    }

    if ( xc_dom_boot_xen_init(dom, xch, domid) )
        failwith_oss_xc("xc_dom_boot_xen_init");
    if ( xc_dom_parse_image(dom) )
        failwith_oss_xc("xc_dom_parse_image");

    if ( is_pvh )
    {
        r = pvh_setup_mem(dom, mem_max_mib, mem_start_mib);
        if ( r )
            failwith_oss_xc("pvh_setup_mem");

        r = xenguest_dom_load_acpi(dom, &f);
        if ( r )
            failwith_oss_xc("xenguest_dom_load_acpi");

        if ( pvh_setup_e820(dom) )
            failwith_oss_xc("pvh_setup_e820");
    }
    else /* HVM */
    {
        r = hvm_build_setup_mem(dom, mem_max_mib, mem_start_mib);
        if ( r )
            failwith_oss_xc("hvm_build_setup_mem");
    }

    if ( xc_dom_build_image(dom) )
        failwith_oss_xc("xc_dom_build_image");
    if ( xc_dom_boot_image(dom) )
        failwith_oss_xc("xc_dom_boot_image");
    if ( xc_dom_gnttab_init(dom) )
        failwith_oss_xc("xc_dom_gnttab_init");

    r = hvm_build_set_params(is_pvh, &f);
    if ( r )
        failwith_oss_xc("hvm_build_params");

    *store_mfn = dom->xenstore_pfn;
    *console_mfn = dom->console_pfn;

    r = construct_cpuid_policy(&f, !is_pvh, false);
    if ( r )
        failwith_oss_xc("construct_cpuid_policy");

    free_flags(&f);
    xc_dom_release(dom);

    return 0;
}

static int switch_qemu_logdirty(uint32_t _domid, unsigned enable, void *_data)
{
    /* qemu-upstream doesn't use xenguest to enable/disable logdirty. */
    return 0;
}

static void migration_safety_checks(void)
{
    if ( force )
    {
        xg_info("--force in effect - skipping safety checks\n");
        return;
    }

    if ( xenstore_get("platform/nomigrate") )
        xg_fatal("d%d is flagged as not being mobile\n", domid);
}

#define GENERATION_ID_ADDRESS "hvmloader/generation-id-address"

int emu_stub_xc_domain_save(int fd, void *data, int flags)
{
    int r;
    struct save_callbacks callbacks = {
        .suspend = emu_suspend_callback,
        .switch_qemu_logdirty = switch_qemu_logdirty,
        .data = data,
        .precopy_policy = xenguest_precopy_policy,
    };

    migration_safety_checks();

    r = xc_domain_save(xch, fd, domid, flags, &callbacks, XC_STREAM_PLAIN, -1);
    if ( r )
        failwith_oss_xc("xc_domain_save");

    return 0;
}

int stub_xc_domain_save(int fd, int flags)
{
    int r;
    struct save_callbacks callbacks = {
        .suspend = suspend_callback,
        .switch_qemu_logdirty = switch_qemu_logdirty,
        .data = NULL,
    };

    migration_safety_checks();

    r = xc_domain_save(xch, fd, domid, flags, &callbacks, XC_STREAM_PLAIN, -1);
    if ( r )
        failwith_oss_xc("xc_domain_save");

    return 0;
}

/* this is the slow version of resume for uncooperative domain,
 * the fast version is available in close source xc */
int stub_xc_domain_resume_slow(void)
{
    int r;

    /* hard code fast to 0, we only want to expose the slow version here */
    r = xc_domain_resume(xch, domid, 0);
    if ( r )
        failwith_oss_xc("xc_domain_resume");

    return 0;
}

static void set_genid(void)
{
    uint64_t paddr = 0;
    void *vaddr;
    char *genid_val_str;
    char *end;
    uint64_t genid[2];

    xc_get_hvm_param(xch, domid, HVM_PARAM_VM_GENERATION_ID_ADDR, &paddr);
    if ( paddr == 0 )
        return;

    genid_val_str = xenstore_gets("platform/generation-id");
    if ( !genid_val_str )
        return;

    errno = 0;
    genid[0] = strtoull(genid_val_str, &end, 0);
    genid[1] = 0;
    if ( end && end[0] == ':' )
        genid[1] = strtoull(end + 1, NULL, 0);

    if ( errno )
        xg_fatal("strtoull of '%s' failed: %s\n", genid_val_str, strerror(errno));

    if ( genid[0] == 0 || genid[1] == 0 )
        xg_fatal("'%s' is not a valid generation id\n", genid_val_str);

    free(genid_val_str);

    vaddr = xc_map_foreign_range(xch, domid, XC_PAGE_SIZE,
                                 PROT_READ | PROT_WRITE,
                                 paddr >> XC_PAGE_SHIFT);
    if ( vaddr == NULL )
        xg_fatal("Failed to map VM generation ID page: %s\n", strerror(errno));

    memcpy(vaddr + (paddr & ~XC_PAGE_MASK), genid, 2 * sizeof(*genid));
    munmap(vaddr, XC_PAGE_SIZE);

    /*
     * FIXME: Inject ACPI Notify event.
     */

    xg_info("Wrote generation ID %"PRId64":%"PRId64" at 0x%"PRIx64"\n",
            genid[0], genid[1], paddr);
}

static int static_data_done(unsigned int missing, void *data)
{
    const struct flags *f = data;

    if ( missing & XGR_SDD_MISSING_CPUID &&
         construct_cpuid_policy(f, f->dominfo.flags & XEN_DOMINF_hap, true) )
        failwith_oss_xc("construct_cpuid_policy");

    return 0;
}

int stub_xc_domain_restore(int fd, int store_evtchn, int console_evtchn,
                           int hvm,
                           unsigned long *store_mfn, unsigned long *console_mfn)
{
    int r = 0;
    struct flags f = {};
    struct restore_callbacks cbs = {
        .static_data_done = static_data_done,
        .data = &f,
    };

    get_flags(&f);

    if ( hvm )
    {
        xc_set_hvm_param(xch, domid, HVM_PARAM_HPET_ENABLED, f.hpet);

        r = xc_domain_set_time_offset(xch, domid, f.timeoffset);

        if ( r )
            failwith_oss_xc("xc_domain_set_time_offset");
    }

    configure_vcpus(&f);

    r = xc_domain_restore(xch, fd, domid,
                          store_evtchn, store_mfn, 0,
                          console_evtchn, console_mfn, 0,
                          XC_STREAM_PLAIN, &cbs, -1);
    if ( r )
        failwith_oss_xc("xc_domain_restore");

    free_flags(&f);

    if ( hvm )
        set_genid();

    return 0;
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

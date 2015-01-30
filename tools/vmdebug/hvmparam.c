#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>

#include <xenctrl.h>

#include <xen/hvm/params.h>

#include "vmdebug.h"

/* Format width for parameter names */
static const int name_width = 24;

typedef struct
{
    const char *name, *desc;
} hvmparam_desc_t;
static hvmparam_desc_t params[HVM_NR_PARAMS] =
{
#define PARAM(n, d) [ HVM_PARAM_ ## n ] = { #n, (d) }
    PARAM(CALLBACK_IRQ, "Event channel delivery settings"),
    PARAM(STORE_PFN, "Xenstore frame"),
    PARAM(STORE_EVTCHN, "Xenstore event channel"),
    PARAM(PAE_ENABLED, "Page Address Extenstions available?"),
    PARAM(IOREQ_PFN, "Device Model IO Request frame"),
    PARAM(BUFIOREQ_PFN, "Device Model Buffered IO Request frame"),
    PARAM(BUFIOREQ_EVTCHN, "Device Model Buffered IO Request event channel"),
    PARAM(VIRIDIAN, "Windows Viridian enlightenments"),
    PARAM(TIMER_MODE, "Timer tick delivery settings"),
    PARAM(HPET_ENABLED, "HPET available?"),
    PARAM(IDENT_PT, "Identity-map pagetable (Intel restricted real mode)"),
    PARAM(DM_DOMAIN, "Device Model domid"),
    PARAM(ACPI_S_STATE, "ACPI System State"),
    PARAM(VM86_TSS, "VM86 TSS (Intel restricted real mode)"),
    PARAM(VPT_ALIGN, "Align virtual timers?"),
    PARAM(CONSOLE_PFN, "PV console frame"),
    PARAM(CONSOLE_EVTCHN, "PV console event channel"),
    PARAM(ACPI_IOPORTS_LOCATION, "APCI PM1a control block location"),
    PARAM(MEMORY_EVENT_CR0, "Memory Event controls for CR0"),
    PARAM(MEMORY_EVENT_CR3, "Memory Event controls for CR3"),
    PARAM(MEMORY_EVENT_CR4, "Memory Event controls for CR4"),
    PARAM(MEMORY_EVENT_INT3, "Memory Event controls for INT3"),
    PARAM(MEMORY_EVENT_SINGLE_STEP, "Memory Event controls for single step"),
    PARAM(MEMORY_EVENT_MSR, "Memory Event controls for MSR access"),
    PARAM(NESTEDHVM, "Nested Virtualisation available?"),
    PARAM(PAGING_RING_PFN, "Memory Event Paging Ring frame"),
    PARAM(MONITOR_RING_PFN, "Memory Event Monitor Ring frame"),
    PARAM(SHARING_RING_PFN, "Memory Event Sharing Ring frame"),
    PARAM(TRIPLE_FAULT_REASON, "Action on triple fault"),
    PARAM(IOREQ_SERVER_PFN, "IO Request Server frame start"),
    PARAM(NR_IOREQ_SERVER_PAGES, "Number of IO Request Server frames"),
    PARAM(VM_GENERATION_ID_ADDR, "Windows Generation ID physical address"),
#undef PARAM
};

static void dump_param_index(void)
{
    unsigned i;

    printf("HVM Parameters:\n");
    for ( i = 0; i < ARRAY_SIZE(params); ++i )
    {
        if ( params[i].name )
            printf("%-3u %-*s %s\n",
                   i, name_width, params[i].name, params[i].desc);
    }
}

static int dump_all_params(xc_interface *xch, int domid)
{
    unsigned i;
    uint64_t val;
    int ret, rc = 0;

    for ( i = 0; i < ARRAY_SIZE(params); ++i )
    {
        if ( params[i].name )
        {
            ret = xc_hvm_param_get(xch, domid, i, &val);
            rc |= ret;

            if ( ret )
                printf("Get param %u failed: %d - %s\n",
                       i, errno, strerror(errno));
            else
                printf("%-3u %-*s 0x%016"PRIx64"\n",
                       i, name_width, params[i].name, val);
        }
    }

    return !!rc;
}

int main_hvmparam(int argc, char ** argv, const cmdopts_t *opts)
{
    unsigned i;
    xc_interface *xch;
    xc_domaininfo_t info = {};
    int ret, rc = 0;

    /* No domid must be an index request... */
    if ( opts->domid == -1 )
    {
        if ( argc == 1 || !strcmp(argv[1], "index") )
        {
            dump_param_index();
            return 0;
        }
        else
        {
            printf("No domain specified\n");
            return 1;
        }
    }

    /* Permit an index request even if a domid is specified */
    if ( argc > 1 && !strcmp(argv[1], "index") )
    {
        dump_param_index();
        return 0;
    }

    xch = get_xch();

    /* Check that the domain exists */
    if ( xc_domain_getinfo_single(xch, opts->domid, &info) < 0 )
    {
        printf("Unable to get dominfo for dom%d - %s (%d)\n",
               opts->domid, strerror(errno), errno);
        return 1;
    }

    /* Check that the domain is an HVM domain */
    if ( !(info.flags & XEN_DOMINF_hvm_guest) )
    {
        printf("dom%d is not an HVM domain\n", opts->domid);
        return 1;
    }

    /* An empty list with a valid domain is a request for all params */
    if ( argc == 1 )
        return dump_all_params(xch, opts->domid);

    /* Look at each parameter... */
    for ( i = 1; i < argc; ++i )
    {
        const char *cmd = argv[i];
        char *endp = NULL;
        unsigned param; uint64_t val;

        /* Parse the parameter index */
        errno = 0;
        param = strtoul(cmd, &endp, 0);
        if ( errno || endp == cmd )
        {
            printf("Bad HVM param '%s'\n", cmd);
            continue;
        }

        /* Check the param is within range */
        if ( param >= HVM_NR_PARAMS )
        {
            printf("Param %u out of range (0 -> %u)\n",
                   param, HVM_NR_PARAMS - 1);
            continue;
        }

        /* If there is '=' present, this is a set request */
        if ( *endp && endp[0] == '=' )
        {
            char *endv = NULL;

            endp++;

            errno = 0;
            val = strtoull(endp, &endv, 0);
            if ( errno || endv == endp )
            {
                printf("Bad value '%s' for param %u\n",
                       endp, param);
                continue;
            }

            ret = xc_hvm_param_set(xch, opts->domid, param, val);
            rc |= ret;

            if ( ret )
                printf("Set param %u = 0x%016"PRIx64" failed: %d - %s\n",
                       param, val, errno, strerror(errno));
            else
                printf("Set param %u = 0x%016"PRIx64"\n", param, val);

            continue;
        }
        else
        {
            ret = xc_hvm_param_get(xch, opts->domid, param, &val);
            rc |= ret;

            if ( ret )
                printf("Get param %u failed: %d - %s\n",
                       param, errno, strerror(errno));
            else
                printf("%-3u %-*s 0x%016"PRIx64"\n",
                       param, name_width, params[param].name, val);
        }
    }

    return !!rc;
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <syslog.h>
#include <unistd.h>

#include <xenctrl.h>
#include <xenguest.h>
#include <xenstore.h>

#include "xg_internal.h"

/*
 * Xapi uses a strange protocol to communicate which xenguest, which seems to
 * be a relic from the xend days.
 *
 * For all domain functions, Xapi expects on the controloutfd:
 *
 *   result:<xenstore mfn> <console mfn>[ <PV ABI>]\n
 *
 * with the xenstore and console mfn in decimal and a PV ABI for PV domains
 * only; HVM domains only require the two mfns.  This information is only
 * relevent when constructing and restoring domains, but must be present for
 * suspend as well, with 0 for both MFNs and no ABI.
 *
 * In addition for suspend only, Xapi expects to see the string "suspend:\n"
 * written to the controloutfd, and expects xenguest to wait until it
 * successfully reads a line from controlinfd.
 */

#define PVH_MODULE_MAX 10

enum xenguest_opts {
    XG_OPT_MODE, /* choice */
    XG_OPT_CONTROLINFD, /* int */
    XG_OPT_CONTROLOUTFD, /* int */
    XG_OPT_DEBUGLOG, /* str */
    XG_OPT_FAKE, /* bool */
    XG_OPT_FD, /* int */
    XG_OPT_IMAGE, /* str */
    XG_OPT_CMDLINE, /* str */
    XG_OPT_RAMDISK, /* str */
    XG_OPT_DOMID, /* int */
    XG_OPT_LIVE, /* bool */
    XG_OPT_DEBUG, /* bool */
    XG_OPT_STORE_PORT, /* str */
    XG_OPT_STORE_DOMID, /* str */
    XG_OPT_CONSOLE_PORT, /* str */
    XG_OPT_CONSOLE_DOMID, /* str */
    XG_OPT_FEATURES, /* str */
    XG_OPT_FLAGS, /* int */
    XG_OPT_MEM_MAX_MIB, /* int */
    XG_OPT_MEM_START_MIB, /* int */
    XG_OPT_FORK, /* bool */
    XG_OPT_NO_INC_GENID, /* bool */
    XG_OPT_SUPPORTS, /* str */
    XG_OPT_PCI_PASSTHROUGH, /* str */
    XG_OPT_FORCE, /* bool */
    XG_OPT_VGPU, /* bool */
    XG_OPT_MODULE, /* str */
};

static int opt_mode = -1;
static int opt_controlinfd = -1;
static int opt_controloutfd = -1;
static FILE *opt_debugfile;
static int opt_fd = -1;
static const char *opt_image;
static const char *opt_cmdline;
static const char *opt_ramdisk;
static int opt_store_port = -1;
static int opt_store_domid;
static int opt_console_port = -1;
static int opt_console_domid;
static const char *opt_features;
static int opt_mem_max_mib = -1;
static int opt_mem_start_mib = -1;
static pvh_module opt_modules[PVH_MODULE_MAX];
static int opt_nmodules;
static int opt_ncmdlines;

xc_interface *xch;
struct xs_handle *xsh;
int domid = -1;
bool force;
int opt_flags;
bool opt_vgpu;

void xg_err(const char *msg, ...)
{
    char *buf = NULL;
    va_list args;
    int rc;

    va_start(args, msg);
    rc = vasprintf(&buf, msg, args);
    va_end(args);

    if ( rc != -1 )
    {
        if ( opt_debugfile )
            fputs(buf, opt_debugfile);

        fputs(buf, stderr);

        syslog(LOG_ERR | LOG_DAEMON, "%s", buf);

        if ( opt_controloutfd != -1 )
        {
            static const char reply[] = "error:";

            write(opt_controloutfd, reply, strlen(reply));
            write(opt_controloutfd, buf, rc);
        }
    }

    free(buf);
}

void xg_info(const char *msg, ...)
{
    char *buf = NULL;
    va_list args;
    int rc;

    va_start(args, msg);
    rc = vasprintf(&buf, msg, args);
    va_end(args);

    if ( rc != -1 )
    {
        if ( opt_debugfile )
            fputs(buf, opt_debugfile);

        syslog(LOG_INFO | LOG_DAEMON, "%s", buf);
    }

    free(buf);
}

static void logfn(struct xentoollog_logger *logger,
                  xentoollog_level level,
                  int errnoval,
                  const char *context,
                  const char *format,
                  va_list al)
{
    char *buf = NULL;

    if ( level == XTL_DEBUG && !(opt_flags & XCFLAGS_DEBUG) )
        return;

    if ( vasprintf(&buf, format, al) != -1 )
        xg_info("%s: %s: %s\n", context, xtl_level_to_string(level), buf);

    free(buf);
}

static void progressfn(struct xentoollog_logger *logger,
                       const char *context, const char *doing_what,
                       int percent, unsigned long done, unsigned long total)
{
    static struct timeval lasttime;

    struct timeval curtime;
    uint64_t time_delta;

    gettimeofday(&curtime, NULL);
    time_delta = tv_delta_us(&curtime, &lasttime);

    send_emu_progress(done, total);

    if ( (time_delta > SEC(5)) ||
         ((done == 0 || done == total) && (time_delta > MSEC(500))) )
    {
        if ( done == 0 && total == 0 )
            xg_info("progress: %s\n", doing_what);
        else
            xg_info("progress: %s: %ld of %ld (%d%%)\n",
                    doing_what, done, total, percent);

        lasttime = curtime;
    }
}

static int parse_mode(const char *mode)
{
    static const char *const names[] = {
        [XG_MODE_HVM_BUILD]    = "hvm_build",
        [XG_MODE_PVH_BUILD]    = "pvh_build",
        [XG_MODE_LISTEN]       = "listen",
        [XG_MODE_HVM_SAVE]     = "hvm_save",
        [XG_MODE_HVM_RESTORE]  = "hvm_restore",
        [XG_MODE_PV_BUILD]     = "linux_build",
        [XG_MODE_PV_SAVE]      = "save",
        [XG_MODE_PV_RESTORE]   = "restore",
        [XG_MODE_RESUME_SLOW]  = "resume_slow",
    };

    for ( unsigned int i = 0; i < ARRAY_SIZE(names); i++ )
    {
        if ( strcmp(mode, names[i]) == 0 )
            return i;
    }

    xg_fatal("xenguest: unrecognized mode '%s'\n", mode);
}

static int parse_int(const char *str)
{
    char *end;
    long result;

    errno = 0;
    result = strtol(str, &end, 10);

    if ( errno || *end != '\0' || result != (int)result )
        xg_fatal("xenguest: '%s' is not a valid int\n", str);

    return result;
}

static void parse_options(int argc, char *const argv[])
{
    static const struct option opts[] = {
        { "mode", required_argument, NULL, XG_OPT_MODE, },
        { "controlinfd", required_argument, NULL, XG_OPT_CONTROLINFD, },
        { "controloutfd", required_argument, NULL, XG_OPT_CONTROLOUTFD, },
        { "debuglog", required_argument, NULL, XG_OPT_DEBUGLOG, },
        { "fake", no_argument, NULL, XG_OPT_FAKE, },

        { "fd", required_argument, NULL, XG_OPT_FD, },
        { "image", required_argument, NULL, XG_OPT_IMAGE, },
        { "cmdline", required_argument, NULL, XG_OPT_CMDLINE, },
        { "ramdisk", required_argument, NULL, XG_OPT_RAMDISK, },
        { "domid", required_argument, NULL, XG_OPT_DOMID, },
        { "live", no_argument, NULL, XG_OPT_LIVE, },
        { "debug", no_argument, NULL, XG_OPT_DEBUG, },
        { "store_port", required_argument, NULL, XG_OPT_STORE_PORT, },
        { "store_domid", required_argument, NULL, XG_OPT_STORE_DOMID, },
        { "console_port", required_argument, NULL, XG_OPT_CONSOLE_PORT, },
        { "console_domid", required_argument, NULL, XG_OPT_CONSOLE_DOMID, },
        { "features", required_argument, NULL, XG_OPT_FEATURES, },
        { "flags", required_argument, NULL, XG_OPT_FLAGS, },
        { "mem_max_mib", required_argument, NULL, XG_OPT_MEM_MAX_MIB, },
        { "mem_start_mib", required_argument, NULL, XG_OPT_MEM_START_MIB, },
        { "fork", no_argument, NULL, XG_OPT_FORK, },
        { "no_incr_generationid", no_argument, NULL, XG_OPT_NO_INC_GENID, },
        { "supports", required_argument, NULL, XG_OPT_SUPPORTS, },
        { "pci_passthrough", required_argument, NULL, XG_OPT_PCI_PASSTHROUGH, },
        { "force", no_argument, NULL, XG_OPT_FORCE, },
        { "vgpu", no_argument, NULL, XG_OPT_VGPU, },
        { "module", required_argument, NULL, XG_OPT_MODULE, },
        {},
    };

    for ( ;; )
    {
        int option_index = 0;
        int c = getopt_long_only(argc, argv, "", opts, &option_index);

        switch (c)
        {
        case -1:
            return;

        case XG_OPT_MODE:
            opt_mode = parse_mode(optarg);
            break;

        case XG_OPT_CONTROLINFD:
            opt_controlinfd = parse_int(optarg);
            break;

        case XG_OPT_CONTROLOUTFD:
            opt_controloutfd = parse_int(optarg);
            break;

        case XG_OPT_DEBUGLOG:
            if ( opt_debugfile && fclose(opt_debugfile) )
                xg_fatal("Unable to close existing debug file: %d %s\n",
                         errno, strerror(errno));

            opt_debugfile = fopen(optarg, "a");
            if ( !opt_debugfile )
                xg_fatal("Unable to open debug file '%s': %d %s\n",
                         optarg, errno, strerror(errno));
            break;

        case XG_OPT_FD:
            opt_fd = parse_int(optarg);
            break;

        case XG_OPT_IMAGE:
            opt_image = optarg;
            break;

        case XG_OPT_MODULE:
            opt_modules[opt_nmodules++].filename = optarg;
            break;

        case XG_OPT_CMDLINE:
            if ( opt_cmdline == NULL )
                opt_cmdline = optarg;
            else
                opt_modules[opt_ncmdlines++].cmdline = optarg;
            break;

        case XG_OPT_RAMDISK:
            opt_ramdisk = optarg;
            break;

        case XG_OPT_DOMID:
            domid = parse_int(optarg);
            break;

        case XG_OPT_LIVE:
            opt_flags |= XCFLAGS_LIVE;
            break;

        case XG_OPT_DEBUG:
            opt_flags |= XCFLAGS_DEBUG;
            break;

        case XG_OPT_STORE_PORT:
            opt_store_port = parse_int(optarg);
            break;

        case XG_OPT_STORE_DOMID:
            opt_store_domid = parse_int(optarg);
            break;

        case XG_OPT_CONSOLE_PORT:
            opt_console_port = parse_int(optarg);
            break;

        case XG_OPT_CONSOLE_DOMID:
            opt_console_domid = parse_int(optarg);
            break;

        case XG_OPT_FEATURES:
            opt_features = optarg;
            break;

        case XG_OPT_FLAGS:
            opt_flags = parse_int(optarg);
            break;

        case XG_OPT_MEM_MAX_MIB:
            opt_mem_max_mib = parse_int(optarg);
            break;

        case XG_OPT_MEM_START_MIB:
            opt_mem_start_mib = parse_int(optarg);
            break;

        case XG_OPT_SUPPORTS:
            if ( !strcmp("migration-v2", optarg) )
                printf("true\n");
            else
                printf("false\n");
            exit(0);
            break;

        case XG_OPT_PCI_PASSTHROUGH:
            pci_passthrough_sbdf_list = optarg;
            break;

        case XG_OPT_FORCE:
            force = true;
            break;

        case XG_OPT_VGPU:
            opt_vgpu = true;
            break;

        case XG_OPT_FAKE:
        case XG_OPT_FORK:
        case XG_OPT_NO_INC_GENID:
            /* ignored */
            break;

        default:
            xg_fatal("xenguest: invalid command line '%s'\n", argv[optind - 1]);
        }
    }
}

static void write_status(unsigned long store_mfn, unsigned long console_mfn,
                         const char *protocol)
{
    if ( opt_controloutfd != -1 )
    {
        char buf[64];
        size_t len;

        if ( protocol )
            len = snprintf(buf, sizeof(buf), "result:%lu %lu %s\n", store_mfn, console_mfn, protocol);
        else
            len = snprintf(buf, sizeof(buf), "result:%lu %lu\n", store_mfn, console_mfn);

        write(opt_controloutfd, buf, len);
        xg_info("Writing to control: '%s'\n", buf);
    }
    else
        xg_err("No control fd to write success to\n");
}

static void do_save(void)
{
    if ( domid == -1 || opt_fd == -1 )
        xg_fatal("xenguest: missing command line options\n");

    stub_xc_domain_save(opt_fd, opt_flags);

    write_status(0, 0, NULL);
}

static void do_restore(bool is_hvm)
{
    unsigned long store_mfn = 0, console_mfn = 0;

    if ( domid == -1 || opt_fd == -1 || opt_store_port == -1 ||
         opt_console_port == -1 )
        xg_fatal("xenguest: missing command line options\n");

    stub_xc_domain_restore(opt_fd, opt_store_port, opt_console_port, is_hvm,
                           &store_mfn, &console_mfn);

    write_status(store_mfn, console_mfn, NULL);
}

static void do_resume(void)
{
    if ( domid == -1 )
        xg_fatal("xenguest: missing command line options\n");

    stub_xc_domain_resume_slow();
    write_status(0, 0, NULL);
}

int suspend_callback(void *data)
{
    static const char suspend_message[] = "suspend:\n";

    write(opt_controloutfd, suspend_message, strlen(suspend_message));

    /* Read one line from control fd. */
    for ( ;; )
    {
        char buf[8];
        ssize_t len, i;

        len = read(opt_controlinfd, buf, sizeof(buf));
        if ( len < 0 && errno == EINTR )
            continue;

        if ( len < 0 )
        {
            xg_err("xenguest: read from control FD failed: %s\n", strerror(errno));
            return 0;
        }

        if ( len == 0 )
        {
            xg_err("xenguest: unexpected EOF on control FD\n");
            return 0;
        }

        for ( i = 0; i < len; ++i )
            if (buf[i] == '\n')
                return 1;
    }
}

static void do_pv_build(void)
{
    unsigned long store_mfn = 0, console_mfn = 0;
    char protocol[64];

    if ( domid == -1 || opt_mem_max_mib == -1 || opt_mem_start_mib == -1 ||
         !opt_image || !opt_ramdisk || !opt_cmdline || !opt_features ||
         opt_flags == -1 || opt_store_port == -1 || opt_store_domid == -1 ||
         opt_console_port == -1 || opt_console_domid == -1 )
        xg_fatal("xenguest: missing command line options\n");

    stub_xc_pv_build(opt_mem_max_mib, opt_mem_start_mib,
                     opt_image, opt_ramdisk,
                     opt_cmdline, opt_features, opt_flags,
                     opt_store_port, opt_store_domid,
                     opt_console_port, opt_console_domid,
                     &store_mfn, &console_mfn, protocol);

    write_status(store_mfn, console_mfn, protocol);
}

static void do_hvm_build(void)
{
    unsigned long store_mfn = 0, console_mfn = 0;

    if ( domid == -1 || opt_mem_max_mib == -1 || opt_mem_start_mib == -1 ||
         !opt_image || opt_store_port == -1 || opt_store_domid == -1 ||
         opt_console_port == -1 || opt_console_domid == -1 )
        xg_fatal("xenguest: missing command line options\n");

    stub_xc_hvm_build(opt_mem_max_mib, opt_mem_start_mib,
                      opt_image, NULL,
                      NULL, 0,
                      NULL, 0,
                      opt_store_port, opt_store_domid,
                      opt_console_port, opt_console_domid,
                      &store_mfn, &console_mfn,
                      false);

    write_status(store_mfn, console_mfn, NULL);
}

static void do_pvh_build(void)
{
    unsigned long store_mfn = 0, console_mfn = 0;

    if ( domid == -1 || opt_mem_max_mib == -1 || opt_mem_start_mib == -1 ||
         !opt_image || !opt_cmdline || !opt_features || opt_flags == -1 ||
         opt_store_port == -1 || opt_store_domid == -1 ||
         opt_console_port == -1 || opt_console_domid == -1 )
        xg_fatal("xenguest: missing command line options\n");

    for ( int i = opt_ncmdlines; i < opt_nmodules; i++ )
        opt_modules[i].cmdline = "";

    stub_xc_hvm_build(opt_mem_max_mib, opt_mem_start_mib,
                      opt_image, opt_cmdline,
                      opt_modules, opt_nmodules,
                      opt_features, opt_flags,
                      opt_store_port, opt_store_domid,
                      opt_console_port, opt_console_domid,
                      &store_mfn, &console_mfn,
                      true);

    write_status(store_mfn, console_mfn, NULL);
}

int main(int argc, char *const argv[])
{
    static xentoollog_logger logger = { logfn, progressfn, NULL };
    static char ident[32];

    char *cmdline = NULL;

    {   /* Conjoin the command line into a single string for logging */
        size_t sum, s;
        int i;
        char *ptr;

        sum = argc - 1; /* Account for spaces and null */
        for ( i = 1; i < argc; ++i )
            sum += strlen(argv[i]);

        ptr = cmdline = malloc(sum);

        if ( !cmdline )
            xg_fatal("Out of Memory\n");

        for ( i = 1; i < argc; ++i )
        {
            s = strlen(argv[i]);
            memcpy(ptr, argv[i], s);
            ptr[s] = ' ';
            ptr = &ptr[s + 1];
        }
        ptr[-1] = '\0';
    }

    parse_options(argc, argv);

    /* Set up syslog with the domid and action in the ident string */
    if ( domid >= 0 )
    {
        const char *suffix;

        switch ( opt_mode )
        {
        case XG_MODE_PV_SAVE:
        case XG_MODE_HVM_SAVE:
            suffix = "-save";
            break;

        case XG_MODE_LISTEN:
            suffix = "-emp";
            break;

        case XG_MODE_PV_RESTORE:
        case XG_MODE_HVM_RESTORE:
            suffix = "-restore";
            break;

        case XG_MODE_RESUME_SLOW:
            suffix = "-resume";
            break;

        case XG_MODE_PV_BUILD:
        case XG_MODE_HVM_BUILD:
        case XG_MODE_PVH_BUILD:
            suffix = "-build";
            break;

        default:
            suffix = "";
            break;
        }

        snprintf(ident, sizeof(ident), "xenguest-%d%s", domid, suffix);
    }
    else
        strncpy(ident, "xenguest", sizeof(ident));

    openlog(ident, LOG_NDELAY | LOG_PID, LOG_DAEMON);

    xg_info("Command line: %s\n", cmdline);
    free(cmdline);

    xch = xc_interface_open(&logger, &logger, 0);
    if ( !xch )
        xg_fatal("xenguest: Failed to open xc interface\n");

    xsh = xs_open(0);
    if ( !xsh )
        xg_fatal("xenguest: Failed to open xenstore interface\n");

    if ( domid > 0 )
    {
        xs_domain_path = xs_get_domain_path(xsh, domid);

        if ( !xs_domain_path )
            xg_fatal("Failed to obtain XenStore domain path\n");
    }

    switch ( opt_mode )
    {
    case -1:
        xg_fatal("xenguest: no '-mode' option specified\n");

    case XG_MODE_PV_SAVE:
    case XG_MODE_HVM_SAVE:
        do_save();
        break;

    case XG_MODE_PV_RESTORE:
    case XG_MODE_HVM_RESTORE:
        do_restore(opt_mode == XG_MODE_HVM_RESTORE);
        break;

    case XG_MODE_RESUME_SLOW:
        do_resume();
        break;

    case XG_MODE_PV_BUILD:
        do_pv_build();
        break;

    case XG_MODE_HVM_BUILD:
        do_hvm_build();
        break;

    case XG_MODE_PVH_BUILD:
        do_pvh_build();
        break;

    case XG_MODE_LISTEN:
        emp_do_listen();
        break;
    }

    free(xs_domain_path);

    xs_close(xsh);
    xc_interface_close(xch);

    xg_info("All done\n");
    if ( opt_debugfile )
        fclose(opt_debugfile);

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

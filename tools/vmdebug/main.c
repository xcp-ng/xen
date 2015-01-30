#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <ctype.h>

#include <getopt.h>

#include "vmdebug.h"

/* Locate a command in the command table by name. */
static const cmdspec_t *find_command(const char *name)
{
    unsigned i;

    for ( i = 0; cmdtable[i].name; ++i )
        if ( !strcmp(cmdtable[i].name, name) )
            return &cmdtable[i];

    return NULL;
}

static void basic_help(void)
{
    unsigned i;

    static const char intro[] =
        "xen-vmdebug - A developer tool for poking virtual machines\n"
        "\n"
        "WARNING: incorrect use of this tool can break your VM in\n"
        "interesting ways.  You get to keep any resulting pieces.\n"
        "\n"
        "Typical usage:\n"
        "    xen-vmdebug <domid> <command> [<args>]\n"
        "\n"
        "Available commands:\n"
        ;
    const int name_width = 18;

    printf(intro);
    for ( i = 0; cmdtable[i].name; ++i )
        printf("    %-*s %s\n", name_width, cmdtable[i].name, cmdtable[i].desc);
    exit(0);
}

int main_help(int argc, char **argv, const cmdopts_t *opts)
{
    const cmdspec_t *cmd;
    unsigned i;

    if ( argc == 1 )
        basic_help();

    for ( i = 1; i < argc; ++i )
    {
        cmd = find_command(argv[i]);

        if ( !cmd )
        {
            printf("No such command '%s'\n", argv[i]);
            continue;
        }

        printf("Command %s: %s\n", cmd->name, cmd->desc);
        if ( cmd->detail )
            printf("%s\n", cmd->detail);
        printf("\n");
    }

    return 0;
}

static void parse_cmdline(int argc, char **argv)
{
    static const char shortops[] = "h";
    static const struct option opts[] =
    {
        { "help", no_argument, NULL, 'h', },
        { NULL }
    };

    int c, index;

    if ( argc == 1 )
        basic_help();

    for (;;)
    {
        c = getopt_long(argc, argv, shortops, opts, &index);

        switch ( c )
        {
        case -1:
            return;

        case 'h':
            basic_help();
            break;
        }
    }
}

int main(int argc, char **argv)
{
    int ret;
    struct cmdopts opts = { 0 };

    atexit(lazy_cleanup);

    parse_cmdline(argc, argv);
    /* -h, --help and such out of the way */

    assert(argc > optind);

    if ( isdigit(argv[optind][0]) )
    {
        errno = 0;
        opts.domid = strtoul(argv[optind], NULL, 10);
        if ( errno )
        {
            fprintf(stderr, "Failed to parse '%s' as domid: %d, %s\n",
                    argv[1], errno, strerror(errno));
            exit(1);
        }

        optind++;
    }
    else
        opts.domid = -1;

    if ( optind == argc )
    {
        printf("No command specified\n");
        return 1;
    }
    else
    {
        const cmdspec_t *cmd = find_command(argv[optind]);

        if ( cmd )
            ret = cmd->main(argc - optind, &argv[optind], &opts);
        else
        {
            printf("No such command '%s'\n", argv[optind]);
            return 1;
        }
    }

    return ret;
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

#include "vmdebug.h"

const struct cmdspec cmdtable[] =
{
    {
        "help",
        &main_help,
        "Provide more information about a command",
        "  xen-vmdebug help <command>",
    },
    {
        "hvmparam",
        &main_hvmparam,
        "Get or set a domains HVM parameters",

        "  xen-vmdebug hvmparam index\n"
        "    Print an index of HVM parameters\n"
        "\n"
        "  xen-vmdebug <domid> hvmparam\n"
        "    Get all HVM params for a domain\n"
        "\n"
        "  xen-vmdebug <domid> hvmparam <param> [<param>]\n"
        "    Get selected HVM params for a domain\n"
        "\n"
        "  xen-vmdebug <domid> hvmparam <param>=<val> [<param>=<val>]\n"
        "    Set a domains HVM params to the given values\n"
    },
    { 0 }
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

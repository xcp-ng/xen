#define _GNU_SOURCE

#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <string.h>

#include <xenctrl.h>

void show_help(void)
{
    fprintf(stdout,
            "xen-spec-ctrl: Xen speculation control tool\n"
            "Usage: xen-spec-ctrl update\n");
}

int main(int argc, char *argv[])
{
    struct xen_sysctl sysctl = {
        .interface_version = XEN_SYSCTL_INTERFACE_VERSION,
        .cmd = XEN_SYSCTL_spec_ctrl,
        .u.spec_ctrl.op = XENPF_spec_ctrl_update,
    };
    xc_interface *xch;
    int ret;

    if ( argc < 2 || strcmp(argv[1], "update") != 0 )
    {
        show_help();
        return 1;
    }

    xch = xc_interface_open(NULL, NULL, 0);
    if ( xch == NULL )
        err(1, "xc_interface_open");

    ret = xc_sysctl(xch, &sysctl);

    if ( ret == 0 )
        fprintf(stdout, "Features updated\n");
    else if ( ret == -1 && errno == ENOEXEC )
        fprintf(stdout, "No new features found\n");
    else
        err(1, "Unexpected error: ");

    xc_interface_close(xch);

    return 0;
}

#define _GNU_SOURCE

#include <stdio.h>
#include <err.h>
#include <errno.h>
#include <string.h>

#include <xenctrl.h>

void show_help(void)
{
    fprintf(stderr,
            "xen-spec-ctrl: Xen speculation control tool\n"
            "Usage: xen-spec-ctrl update\n");
}

int main(int argc, char *argv[])
{
    int ret;
    struct xen_sysctl sysctl = {0};
    xc_interface *xch;
    char *str = "Mitigations have been updated! "
                "Check xen-cpuid output for the details.";

    if ( argc < 2 || strcmp(argv[1], "update") != 0 )
    {
        show_help();
        return 1;
    }

    xch = xc_interface_open(NULL, NULL, 0);
    if ( xch == NULL )
        err(1, "xc_interface_open");

    sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    sysctl.cmd = XEN_SYSCTL_spec_ctrl;
    sysctl.u.spec_ctrl.op = XENPF_spec_ctrl_update;

    ret = xc_sysctl(xch, &sysctl);
    if ( ret != 0 )
    {
        switch ( errno )
        {
        case ENOEXEC:
            str = "No new H/W features have been found. "
                  "Did you forget to update the microcode with xen-ucode?";
            break;

        default:
            str = strerror(errno);
            break;
        }
    }

    fprintf(stderr, "Status: %s\n", str);

    xc_interface_close(xch);

    return 0;
}

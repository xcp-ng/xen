/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <xen/efi.h>
#include <xen/kernel.h>
#include <xen/lockdown.h>
#include <xen/param.h>
#include <xen/string.h>

static bool __ro_after_init lockdown = IS_ENABLED(CONFIG_LOCKDOWN_DEFAULT);
ignore_param("lockdown");

bool is_locked_down(void)
{
    return lockdown;
}

void __init lockdown_init(const char *cmdline)
{
#ifdef CONFIG_PV_SHIM
    lockdown = false;
#else
    if ( efi_secure_boot )
    {
        printk("Enabling lockdown mode because Secure Boot is enabled\n");
        lockdown = true;
    }
    else
    {
        while ( *cmdline )
        {
            size_t param_len, name_len;
            int ret;

            cmdline += strspn(cmdline, " \n\r\t");
            param_len = strcspn(cmdline, " \n\r\t");
            name_len = strcspn(cmdline, "= \n\r\t");

            if ( !strncmp(cmdline, "lockdown", max(name_len, strlen("lockdown"))) ||
                 !strncmp(cmdline, "no-lockdown", max(name_len, strlen("no-lockdown"))) )
            {
                ret = parse_boolean("lockdown", cmdline, cmdline + param_len);
                if ( ret >= 0 )
                {
                    lockdown = ret;
                    printk("Lockdown mode set from command-line\n");
                    break;
                }
            }

            cmdline += param_len;
        }
    }

    printk("Lockdown mode is %s\n", lockdown ? "enabled" : "disabled");
#endif
}

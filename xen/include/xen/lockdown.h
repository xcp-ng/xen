#ifndef XEN__LOCKDOWN_H
#define XEN__LOCKDOWN_H

#include <xen/types.h>

bool is_locked_down(void);
void lockdown_init(const char *cmdline);

/*
 * Filtering code versioning.
 * Dom0 kernel should define this in the ELF notes.
 * Xen, if Secure Boot (or lockdown) is enabled will check that the
 * version is in a given range; this to prevent loading kernel not
 * properly filtering hypercalls from userspace (potentially possible
 * in case of OEM signed kernels).
 *
 * The current schema is 0xMMmmnn where "MM" is the XenServer major "mm"
 * is XenServer minor and "nn" is an incremental number.
 * If we update the hypercall ABI in a way that is not compatible with
 * the kernel filtering code "nn" should be increased.
 */

/* XCP-ng vendor ID */
#define FILTER_VENDOR_XCPNG  (1UL << 31)

#define PRIVCMD_FILTERING_ABI_VERSION \
    (FILTER_VENDOR_XCPNG | _AC(0x90001, UL))

#endif /* XEN__LOCKDOWN_H */

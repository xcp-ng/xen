/* SPDX-License-Identifier: MIT */
#ifndef __XEN_PUBLIC_FASTABI_H__
#define __XEN_PUBLIC_FASTABI_H__

#if defined(__x86_64__)
#define __HYPERVISOR_FASTABI_MASK 0x40000000U

enum xen_hypercall_vendor {
    Intel,
    Amd
};
#else
#define __HYPERVISOR_FASTABI_MASK 0

enum xen_hypercall_vendor {
    Native
};
#endif

#endif

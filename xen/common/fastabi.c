/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/errno.h>
#include <xen/fastabi.h>
#include <xen/sched.h>

#include <public/xen.h>

void fastabi_make_continuation(void)
{
    current->hcall_preempted = true;
}

void fastabi_dispatch(unsigned long index, struct cpu_user_regs *regs)
{
    switch (index) {
    /* Wrappers over traditional hypercalls */
    case __HYPERVISOR_xen_version:
        do_xen_version_fast_op(regs);
        break;

    case __HYPERVISOR_vcpu_op:
        do_vcpu_fast_op(regs);
        break;

    case __HYPERVISOR_sched_op:
        do_sched_fast_op(regs);
        break;

    case __HYPERVISOR_event_channel_op:
        do_event_channel_fast_op(regs);
        break;

    case __HYPERVISOR_hvm_op:
        do_hvm_fast_op(regs);
        break;

    default:
        fastabi_value_n(regs, 0) = -ENOSYS;
        break;
    }
}

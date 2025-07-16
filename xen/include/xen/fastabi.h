/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef XEN_FASTABI_H
#define XEN_FASTABI_H

#include <asm/fastabi.h>

void fastabi_dispatch(unsigned long index, struct cpu_user_regs *regs);
void fastabi_make_continuation(void);

void do_event_channel_fast_op(struct cpu_user_regs *regs);

long common_vcpu_fast_op(struct cpu_user_regs *regs, int cmd, struct vcpu *v);
void do_vcpu_fast_op(struct cpu_user_regs *regs);
void do_hvm_fast_op(struct cpu_user_regs *regs);
void do_sched_fast_op(struct cpu_user_regs *regs);
void do_xen_version_fast_op(struct cpu_user_regs *regs);

#endif /* XEN_FASTABI_H */

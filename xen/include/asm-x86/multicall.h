/******************************************************************************
 * asm-x86/multicall.h
 */

#ifndef __ASM_X86_MULTICALL_H__
#define __ASM_X86_MULTICALL_H__

#include <xen/errno.h>

enum mc_disposition {
    mc_continue,
    mc_exit,
    mc_preempt,
};

#define multicall_ret(call)                                  \
    (unlikely((call)->op == __HYPERVISOR_iret)               \
     ? mc_exit                                               \
     : likely(guest_kernel_mode(current,                     \
                                guest_cpu_user_regs()))      \
     ? mc_continue : mc_preempt)

enum mc_disposition arch_do_multicall_call(struct mc_state *state);

#endif /* __ASM_X86_MULTICALL_H__ */

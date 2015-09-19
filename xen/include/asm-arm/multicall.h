#ifndef __ASM_ARM_MULTICALL_H__
#define __ASM_ARM_MULTICALL_H__

extern enum mc_disposition {
    mc_continue,
    mc_exit,
    mc_preempt,
} arch_do_multicall_call(struct mc_state *state);

#endif /* __ASM_ARM_MULTICALL_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

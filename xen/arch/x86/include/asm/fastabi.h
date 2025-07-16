#ifndef XEN_ASM_FASTABI_H
#define XEN_ASM_FASTABI_H

#include <asm/current.h>

#define fastabi_param_reg0 rax
#define fastabi_param_reg1 rdi
#define fastabi_param_reg2 rsi
#define fastabi_param_reg3 r8
#define fastabi_param_reg4 r9
#define fastabi_param_reg5 r10
#define fastabi_param_reg6 r11
#define fastabi_param_reg7 r12

#define fastabi_value_n(regs, n) (regs)->fastabi_param_reg##n

#endif /* XEN_ASM_FASTABI_H */
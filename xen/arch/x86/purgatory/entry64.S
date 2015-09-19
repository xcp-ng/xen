/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2003,2004  Eric Biederman (ebiederm@xmission.com)
 * Copyright (C) 2014  Red Hat Inc.
 * Copyright (C) 2024  Cloud Software Group Inc.

 * Author(s): Vivek Goyal <vgoyal@redhat.com>
 *
 * This code has been adapted from kexec-tools and Linux.
 */

#include "config.h"

    .text
    .code64

BALIGN(16)
GLOBAL(entry64)
    /* Setup a gdt that should be preserved */
    lgdt gdt(%rip)

    /* load the data segments */
    movl    $0x18, %eax     /* data segment */
    movl    %eax, %ds
    movl    %eax, %es
    movl    %eax, %ss
    movl    %eax, %fs
    movl    %eax, %gs

    /* Setup new stack */
    leaq    stack_init(%rip), %rsp
    pushq   $0x10 /* CS */
    leaq    new_cs_exit(%rip), %rax
    pushq   %rax
    lretq
ENTRY(new_cs_exit)

    /* Load the registers */
    movq    rax(%rip), %rax
    movq    rbx(%rip), %rbx
    movq    rcx(%rip), %rcx
    movq    rdx(%rip), %rdx
    movq    rsi(%rip), %rsi
    movq    rdi(%rip), %rdi
    movq    rsp(%rip), %rsp
    movq    rbp(%rip), %rbp
    movq    r8(%rip), %r8
    movq    r9(%rip), %r9
    movq    r10(%rip), %r10
    movq    r11(%rip), %r11
    movq    r12(%rip), %r12
    movq    r13(%rip), %r13
    movq    r14(%rip), %r14
    movq    r15(%rip), %r15

    /* Jump to the new code... */
    jmpq    *rip(%rip)
END(entry64)

    .section ".rodata"

BALIGN(4)
GLOBAL(entry64_regs)
rax:    .quad 0x0
rbx:    .quad 0x0
rcx:    .quad 0x0
rdx:    .quad 0x0
rsi:    .quad 0x0
rdi:    .quad 0x0
rsp:    .quad 0x0
rbp:    .quad 0x0
r8:     .quad 0x0
r9:     .quad 0x0
r10:    .quad 0x0
r11:    .quad 0x0
r12:    .quad 0x0
r13:    .quad 0x0
r14:    .quad 0x0
r15:    .quad 0x0
rip:    .quad 0x0
END(entry64_regs)
    .size entry64_regs, entry64_regs_end - entry64_regs

    /* GDT */
    .section ".rodata"

BALIGN(16)
ENTRY(gdt)
    /*
     * 0x00 unusable segment
     * 0x08 unused
     * so use them as gdt ptr
     */
    .word gdt_end - gdt - 1
    .quad gdt
    .word 0, 0, 0

    /* 0x10 4GB flat code segment */
    .word 0xFFFF, 0x0000, 0x9A00, 0x00AF

    /* 0x18 4GB flat data segment */
    .word 0xFFFF, 0x0000, 0x9200, 0x00CF
END(gdt)

ENTRY(stack)
    .quad   0, 0
END(stack)
ENTRY(stack_init)

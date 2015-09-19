/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (C) 2024 Cloud Software Group Inc.
 */

#ifndef __PURGATORY_CONFIG_H__
#define __PURGATORY_CONFIG_H__

#define BALIGN(size) .balign size

#undef ENTRY
#define ENTRY(name)         \
    name:

#define END(name)           \
    name##_end:

#undef GLOBAL
#define GLOBAL(name)        \
    .globl name;            \
    ENTRY(name)

#define GLOBAL_END(name)    \
    .globl name##_end;      \
    END(name)

#define SYM_T_DATA 1

#define ASM_INT(name, val)  \
    .type name, SYM_T_DATA; \
    BALIGN(4);              \
    .hidden name;           \
    GLOBAL(name)            \
    .long (val);            \
    .size name, . - name

#endif // __PURGATORY_CONFIG_H__

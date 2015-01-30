/*
 * reloc.c
 *
 * 32-bit flat memory-map routines for relocating Multiboot structures
 * and modules. This is most easily done early with paging disabled.
 *
 * Copyright (c) 2009, Citrix Systems, Inc.
 *
 * Authors:
 *    Keir Fraser <keir@xen.org>
 */

/* entered with %eax = BOOT_TRAMPOLINE */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    call 1f                       \n"
    "1:  pop  %ebx                     \n"
    "    mov  %eax,alloc-1b(%ebx)      \n"
    "    jmp  reloc                    \n"
    );

/*
 * This is our data. Because the code must be relocatable, no BSS is
 * allowed. All data is accessed PC-relative with inline assembly.
 */
asm (
    "alloc:                            \n"
    "    .long 0                       \n"
    );

typedef unsigned int u32;
#include "../../../include/xen/multiboot.h"

static u32 alloc_struct(u32 bytes)
{
    u32 s;

    asm(
    "    call 1f                      \n"
    "1:  pop  %%edx                   \n"
    "    mov  alloc-1b(%%edx),%0      \n"
    "    sub  %1,%0                   \n"
    "    and  $~15,%0                 \n"
    "    mov  %0,alloc-1b(%%edx)      \n"
       : "=&r" (s) : "r" (bytes) : "edx", "memory");

    return s;
}

static u32 copy_struct(u32 src, u32 bytes)
{
    u32 dst, dst_asm;

    dst = alloc_struct(bytes);
    dst_asm = dst;

    asm volatile("rep movsb" : "+S" (src), "+D" (dst_asm), "+c" (bytes) : : "memory");

    return dst;
}

static u32 copy_string(u32 src)
{
    char *p;

    if ( src == 0 )
        return 0;

    for ( p = (char *)src; *p != '\0'; p++ )
        continue;

    return copy_struct(src, p - (char *)src + 1);
}

multiboot_info_t *reloc(multiboot_info_t *mbi_old)
{
    multiboot_info_t *mbi = (multiboot_info_t *)copy_struct((u32)mbi_old, sizeof(*mbi));
    int i;

    if ( mbi->flags & MBI_CMDLINE )
        mbi->cmdline = copy_string(mbi->cmdline);

    if ( mbi->flags & MBI_MODULES )
    {
        module_t *mods = (module_t *)copy_struct(
            mbi->mods_addr, mbi->mods_count * sizeof(module_t));

        mbi->mods_addr = (u32)mods;

        for ( i = 0; i < mbi->mods_count; i++ )
        {
            if ( mods[i].string )
                mods[i].string = copy_string(mods[i].string);
        }
    }

    if ( mbi->flags & MBI_MEMMAP )
        mbi->mmap_addr = copy_struct(mbi->mmap_addr, mbi->mmap_length);

    if ( mbi->flags & MBI_LOADERNAME )
        mbi->boot_loader_name = copy_string(mbi->boot_loader_name);

    /* Mask features we don't understand or don't relocate. */
    mbi->flags &= (MBI_MEMLIMITS |
                   MBI_CMDLINE |
                   MBI_MODULES |
                   MBI_MEMMAP |
                   MBI_LOADERNAME);

    return mbi;
}

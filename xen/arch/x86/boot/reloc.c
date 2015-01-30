/*
 * reloc.c
 *
 * 32-bit flat memory-map routines for relocating Multiboot structures
 * and modules. This is most easily done early with paging disabled.
 *
 * Copyright (c) 2009, Citrix Systems, Inc.
 * Copyright (c) 2013, 2014, 2015 Oracle Corp.
 *
 * Authors:
 *    Keir Fraser <keir@xen.org>
 *    Daniel Kiper
 */

/*
 * This entry point is entered from xen/arch/x86/boot/head.S with:
 *   - %eax = MULTIBOOT_MAGIC,
 *   - %ebx = MULTIBOOT_INFORMATION_ADDRESS,
 *   - %ecx = BOOT_TRAMPOLINE.
 */
asm (
    "    .text                         \n"
    "    .globl _start                 \n"
    "_start:                           \n"
    "    call 1f                       \n"
    "1:  pop  %ebx                     \n"
    "    mov  %ecx,alloc-1b(%ebx)      \n"
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
typedef unsigned long long u64;

#include "../../../include/xen/compiler.h"
#include "../../../include/xen/multiboot.h"
#include "../../../include/xen/multiboot2.h"

#define ALIGN_UP(addr, align) \
                (((addr) + (typeof(addr))(align) - 1) & ~((typeof(addr))(align) - 1))

#define get_mb2_data(tag, type, member) (((type *)(tag))->member)

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

static void zero_struct(u32 s, u32 bytes)
{
    asm volatile("rep stosb" : "+D" (s), "+c" (bytes) : "a" (0) : "memory");
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

static multiboot_info_t *mbi_mbi(void *mbi_in)
{
    int i;
    multiboot_info_t *mbi_out;

    mbi_out = (multiboot_info_t *)copy_struct((u32)mbi_in, sizeof(*mbi_out));

    if ( mbi_out->flags & MBI_CMDLINE )
        mbi_out->cmdline = copy_string(mbi_out->cmdline);

    if ( mbi_out->flags & MBI_MODULES )
    {
        module_t *mods = (module_t *)copy_struct(
            mbi_out->mods_addr, mbi_out->mods_count * sizeof(module_t));

        mbi_out->mods_addr = (u32)mods;

        for ( i = 0; i < mbi_out->mods_count; i++ )
        {
            if ( mods[i].string )
                mods[i].string = copy_string(mods[i].string);
        }
    }

    if ( mbi_out->flags & MBI_MEMMAP )
        mbi_out->mmap_addr = copy_struct(mbi_out->mmap_addr, mbi_out->mmap_length);

    if ( mbi_out->flags & MBI_LOADERNAME )
        mbi_out->boot_loader_name = copy_string(mbi_out->boot_loader_name);

    /* Mask features we don't understand or don't relocate. */
    mbi_out->flags &= (MBI_MEMLIMITS |
                       MBI_CMDLINE |
                       MBI_MODULES |
                       MBI_MEMMAP |
                       MBI_LOADERNAME);

    return mbi_out;
}

static multiboot_info_t *mbi2_mbi(void *mbi_in)
{
    module_t *mbi_out_mods;
    memory_map_t *mmap_dst;
    multiboot2_memory_map_t *mmap_src;
    multiboot2_tag_t *tag;
    multiboot_info_t *mbi_out;
    u32 ptr;
    unsigned int i, mod_idx = 0;

    mbi_out = (multiboot_info_t *)alloc_struct(sizeof(*mbi_out));
    zero_struct((u32)mbi_out, sizeof(*mbi_out));

    /* Skip Multiboot2 information fixed part. */
    tag = mbi_in + sizeof(multiboot2_fixed_t);

    for ( ; ; )
    {
        if ( tag->type == MULTIBOOT2_TAG_TYPE_MODULE )
            ++mbi_out->mods_count;
        else if ( tag->type == MULTIBOOT2_TAG_TYPE_END )
        {
            mbi_out->flags = MBI_MODULES;
            mbi_out->mods_addr = alloc_struct(mbi_out->mods_count * sizeof(module_t));
            mbi_out_mods = (module_t *)mbi_out->mods_addr;
            break;
        }

        /* Go to next Multiboot2 information tag. */
        tag = (multiboot2_tag_t *)(ALIGN_UP((u32)tag + tag->size, MULTIBOOT2_TAG_ALIGN));
    }

    /* Skip Multiboot2 information fixed part. */
    tag = mbi_in + sizeof(multiboot2_fixed_t);

    for ( ; ; )
    {
        switch ( tag->type )
        {
        case MULTIBOOT2_TAG_TYPE_BOOT_LOADER_NAME:
            mbi_out->flags |= MBI_LOADERNAME;
            ptr = (u32)get_mb2_data(tag, multiboot2_tag_string_t, string);
            mbi_out->boot_loader_name = copy_string(ptr);
            break;

        case MULTIBOOT2_TAG_TYPE_CMDLINE:
            mbi_out->flags |= MBI_CMDLINE;
            ptr = (u32)get_mb2_data(tag, multiboot2_tag_string_t, string);
            mbi_out->cmdline = copy_string(ptr);
            break;

        case MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO:
            mbi_out->flags |= MBI_MEMLIMITS;
            mbi_out->mem_lower = get_mb2_data(tag, multiboot2_tag_basic_meminfo_t, mem_lower);
            mbi_out->mem_upper = get_mb2_data(tag, multiboot2_tag_basic_meminfo_t, mem_upper);
            break;

        case MULTIBOOT2_TAG_TYPE_MMAP:
            mbi_out->flags |= MBI_MEMMAP;
            mbi_out->mmap_length = get_mb2_data(tag, multiboot2_tag_mmap_t, size);
            mbi_out->mmap_length -= sizeof(multiboot2_tag_mmap_t);
            mbi_out->mmap_length += sizeof(((multiboot2_tag_mmap_t){0}).entries);
            mbi_out->mmap_length /= get_mb2_data(tag, multiboot2_tag_mmap_t, entry_size);
            mbi_out->mmap_length *= sizeof(memory_map_t);

            mbi_out->mmap_addr = alloc_struct(mbi_out->mmap_length);

            mmap_src = get_mb2_data(tag, multiboot2_tag_mmap_t, entries);
            mmap_dst = (memory_map_t *)mbi_out->mmap_addr;

            for ( i = 0; i < mbi_out->mmap_length / sizeof(memory_map_t); ++i )
            {
                mmap_dst[i].size = sizeof(memory_map_t);
                mmap_dst[i].size -= sizeof(((memory_map_t){0}).size);
                mmap_dst[i].base_addr_low = (u32)mmap_src[i].addr;
                mmap_dst[i].base_addr_high = (u32)(mmap_src[i].addr >> 32);
                mmap_dst[i].length_low = (u32)mmap_src[i].len;
                mmap_dst[i].length_high = (u32)(mmap_src[i].len >> 32);
                mmap_dst[i].type = mmap_src[i].type;
            }
            break;

        case MULTIBOOT2_TAG_TYPE_MODULE:
            mbi_out_mods[mod_idx].mod_start = get_mb2_data(tag, multiboot2_tag_module_t, mod_start);
            mbi_out_mods[mod_idx].mod_end = get_mb2_data(tag, multiboot2_tag_module_t, mod_end);
            ptr = (u32)get_mb2_data(tag, multiboot2_tag_module_t, cmdline);
            mbi_out_mods[mod_idx].string = copy_string(ptr);
            mbi_out_mods[mod_idx].reserved = 0;
            ++mod_idx;
            break;

        case MULTIBOOT2_TAG_TYPE_END:
            return mbi_out;

        default:
            break;
        }

        /* Go to next Multiboot2 information tag. */
        tag = (multiboot2_tag_t *)(ALIGN_UP((u32)tag + tag->size, MULTIBOOT2_TAG_ALIGN));
    }
}

static multiboot_info_t __used *reloc(void *mbi_in, u32 mb_magic)
{
    if ( mb_magic == MULTIBOOT2_BOOTLOADER_MAGIC )
        return mbi2_mbi(mbi_in);
    else
        return mbi_mbi(mbi_in);
}

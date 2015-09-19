/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2024, Cloud Software Group
 *
 * Parts have been derived from Linux's arch/x86/kernel/machine_kexec_64.c
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/elfstructs.h>
#include <xen/kimage.h>

int arch_kexec_apply_relocations_add(struct purgatory_info *pi,
                                     Elf_Shdr *section, const Elf_Shdr *relsec,
                                     const Elf_Shdr *symtabsec)
{
    unsigned int i;
    Elf64_Rela *rel;
    Elf64_Sym *sym;
    void *location;
    unsigned long address, sec_base, value;
    const char *strtab, *name, *shstrtab;
    const Elf_Shdr *sechdrs;
    const Elf_Ehdr *ehdr = (const Elf_Ehdr *)kexec_purgatory;

    /* String & section header string table */
    sechdrs = (void *)ehdr + ehdr->e_shoff;
    strtab = (char *)ehdr + sechdrs[symtabsec->sh_link].sh_offset;
    shstrtab = (char *)ehdr + sechdrs[ehdr->e_shstrndx].sh_offset;

    rel = (void *)ehdr + relsec->sh_offset;

    dprintk(XENLOG_DEBUG, "Applying relocate section %s to %u\n",
            shstrtab + relsec->sh_name, relsec->sh_info);

    for ( i = 0; i < relsec->sh_size / sizeof(*rel); i++) {

        /*
         * rel[i].r_offset contains byte offset from beginning
         * of section to the storage unit affected.
         *
         * This is location to update. This is temporary buffer
         * where section is currently loaded. This will finally be
         * loaded to a different address later, pointed to by
         * ->sh_addr. kimage_purgatory_move takes care of moving it
         */
        location = pi->buffer;
        location += section->sh_offset;
        location += rel[i].r_offset;

        /* Final address of the location */
        address = section->sh_addr + rel[i].r_offset;

        /*
         * rel[i].r_info contains information about symbol table index
         * w.r.t which relocation must be made and type of relocation
         * to apply. ELF64_R_SYM() and ELF64_R_TYPE() macros get
         * these respectively.
         */
        sym = (void *)ehdr + symtabsec->sh_offset;
        sym += ELF64_R_SYM(rel[i].r_info);

        if ( sym->st_name )
            name = strtab + sym->st_name;
        else
            name = shstrtab + sechdrs[sym->st_shndx].sh_name;

        dprintk(XENLOG_DEBUG, "Symbol: %s info: %02x shndx: %02x value=%lx size: %lx\n",
                name, sym->st_info, sym->st_shndx, sym->st_value,
                sym->st_size);

        if ( sym->st_shndx == SHN_UNDEF ) {
            printk("Undefined symbol: %s\n", name);
            return -ENOEXEC;
        }

        if ( sym->st_shndx == SHN_COMMON ) {
            printk("symbol '%s' in common section\n", name);
            return -ENOEXEC;
        }

        if ( sym->st_shndx == SHN_ABS )
            sec_base = 0;
        else if ( sym->st_shndx >= ehdr->e_shnum ) {
            printk("Invalid section %d for symbol %s\n",
                    sym->st_shndx, name);
            return -ENOEXEC;
        } else
            sec_base = pi->sechdrs[sym->st_shndx].sh_addr;

        value = sym->st_value;
        value += sec_base;
        value += rel[i].r_addend;

        switch ( ELF64_R_TYPE(rel[i].r_info) ) {
            case R_X86_64_NONE:
                break;
            case R_X86_64_64:
                *(u64 *)location = value;
                break;
            case R_X86_64_PC32:
            case R_X86_64_PLT32:
                value -= (u64)address;
                *(u32 *)location = value;
                break;
            default:
                printk("Unknown rela relocation: %lu\n",
                        ELF64_R_TYPE(rel[i].r_info));
                return -ENOEXEC;
        }
    }

    return 0;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

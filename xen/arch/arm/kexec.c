/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2024, Cloud Software Group
 */

#include <xen/types.h>
#include <xen/errno.h>
#include <xen/elfstructs.h>
#include <xen/kimage.h>

int arch_kexec_apply_relocations_add(struct purgatory_info *pi,
                                     Elf_Shdr *section, const Elf_Shdr *relsec,
                                     const Elf_Shdr *symtabsec)
{
    return -ENOSYS;
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

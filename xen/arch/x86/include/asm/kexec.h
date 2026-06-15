/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef ASM_X86_KEXEC_H
#define ASM_X86_KEXEC_H

struct kexec_image;
int64_t kimage_find_kernel_entry_maddr(struct kexec_image *image);

#endif /* ASM_X86_KEXEC_H */

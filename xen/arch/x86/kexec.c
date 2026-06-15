/* SPDX-License-Identifier: GPL-2.0-only */

#include <xen/kexec.h>
#include <xen/kimage.h>
#include <xen/guest_access.h>
#include <asm/bzimage.h>

/*
 * Find the entry point to the new kernel, we need to map the crash region into
 * memory in order to read the kernel header.
 */
#define KERNEL_SEGMENT_IDX 0
int64_t kimage_find_kernel_entry_maddr(struct kexec_image *image)
{
    uint64_t dest_maddr;
    uint32_t alignment, magic;
    uint16_t version;
    void *dest_va;
    const struct bzimage_header *hdr;
    int setup_sects;
    size_t kern16_size;

    dest_maddr = image->segments[KERNEL_SEGMENT_IDX].dest_maddr +
                 image->segments[KERNEL_SEGMENT_IDX].dest_offset;

    dest_va = map_domain_page(maddr_to_mfn(dest_maddr));

    hdr = (const struct bzimage_header *)dest_va;
    magic = hdr->header;
    version = hdr->version;
    alignment = hdr->kernel_alignment;
    setup_sects = hdr->setup_sects == 0 ? 4 : hdr->setup_sects;
    kern16_size = (setup_sects + 1 )  * 512;

    unmap_domain_page(dest_va);

    if ( magic != 0x53726448 || version < 0x0202 )
        return -EINVAL;

    /*
     * Ensure the kernel alignment is a valid LOAD_PHYSICAL_ADDR,
     * which ranges from 0x200000 (2MiB) to 0x1000000 (16MiB) on 64-bit systems
     * as defined in the kernel x86 Kconfig
     */
    if ( alignment % 0x200000 != 0 ||
         alignment < 0x200000 ||
         alignment > 0x1000000 )
        return -EINVAL;

    if ( (dest_maddr + kern16_size) % alignment )
    {
        printk(XENLOG_WARNING "kernel dest addr 0x%lx is not aligend to 0x%x\n",
               dest_maddr + kern16_size, alignment);
        return -EINVAL;
    }

    return dest_maddr + kern16_size + 0x200;
}

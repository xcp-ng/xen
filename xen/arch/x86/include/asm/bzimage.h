#ifndef __X86_BZIMAGE_H__
#define __X86_BZIMAGE_H__

#include <xen/init.h>

unsigned long bzimage_headroom(void *image_start, unsigned long image_length);

int bzimage_parse(void *image_base, void **image_start,
                  unsigned long *image_len);

struct __packed bzimage_header {
        uint8_t         _pad0[0x1f1];           /* skip uninteresting stuff */
        uint8_t         setup_sects;
        uint16_t        root_flags;
        uint32_t        syssize;
        uint16_t        ram_size;
        uint16_t        vid_mode;
        uint16_t        root_dev;
        uint16_t        boot_flag;
        uint16_t        jump;
        uint32_t        header;
#define HDR_MAGIC               "HdrS"
#define HDR_MAGIC_SZ    4
        uint16_t        version;
#define VERSION(h,l)    (((h)<<8) | (l))
        uint32_t        realmode_swtch;
        uint16_t        start_sys;
        uint16_t        kernel_version;
        uint8_t         type_of_loader;
        uint8_t         loadflags;
        uint16_t        setup_move_size;
        uint32_t        code32_start;
        uint32_t        ramdisk_image;
        uint32_t        ramdisk_size;
        uint32_t        bootsect_kludge;
        uint16_t        heap_end_ptr;
        uint16_t        _pad1;
        uint32_t        cmd_line_ptr;
        uint32_t        initrd_addr_max;
        uint32_t        kernel_alignment;
        uint8_t         relocatable_kernel;
        uint8_t         _pad2[3];
        uint32_t        cmdline_size;
        uint32_t        hardware_subarch;
        uint64_t        hardware_subarch_data;
        uint32_t        payload_offset;
        uint32_t        payload_length;
    };

static inline size_t kernel_alignment_offset(void)
{
    return offsetof(struct bzimage_header, kernel_alignment);
}

#endif /* __X86_BZIMAGE_H__ */

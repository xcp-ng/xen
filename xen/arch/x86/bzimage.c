#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/gunzip.h>
#include <xen/decompress.h>
#include <xen/libelf.h>
#include <xen/x86-linux.h>
#include <asm/bzimage.h>

static __init unsigned long output_length(void *image, unsigned long image_len)
{
    return *(uint32_t *)(image + image_len - 4);
}

static __init int bzimage_check(struct setup_header *hdr, unsigned long len)
{
    if ( len < sizeof(struct setup_header) )
        return 0;

    if ( memcmp(&hdr->header, HDR_MAGIC, HDR_MAGIC_SZ) != 0 )
        return 0;

    if ( hdr->version < VERSION(2,8) ) {
        printk("Cannot load bzImage v%d.%02d at least v2.08 is required\n",
           hdr->version >> 8, hdr->version & 0xff);
        return -EINVAL;
    }
    return 1;
}

static unsigned long __initdata orig_image_len;

unsigned long __init bzimage_headroom(void *image_start,
                                      unsigned long image_length)
{
    struct setup_header *hdr = (struct setup_header *)image_start;
    int err;
    unsigned long headroom;

    err = bzimage_check(hdr, image_length);
    if ( err < 0 )
        return 0;

    if ( err > 0 )
    {
        image_start += (hdr->setup_sects + 1) * 512 + hdr->payload_offset;
        image_length = hdr->payload_length;
    }

    if ( elf_is_elfbinary(image_start, image_length) )
        return 0;

    orig_image_len = image_length;
    headroom = output_length(image_start, image_length);
    if (gzip_check(image_start, image_length))
    {
        headroom += headroom >> 12; /* Add 8 bytes for every 32K input block */
        headroom += (32768 + 18); /* Add 32K + 18 bytes of extra headroom */
    } else
        headroom += image_length;
    headroom = (headroom + 4095) & ~4095;

    return headroom;
}

int __init bzimage_parse(void *image_base, void **image_start,
                         unsigned long *image_len)
{
    struct setup_header *hdr = (struct setup_header *)(*image_start);
    int err = bzimage_check(hdr, *image_len);
    unsigned long output_len;

    if ( err < 0 )
        return err;

    if ( err > 0 )
    {
        *image_start += (hdr->setup_sects + 1) * 512 + hdr->payload_offset;
        *image_len = hdr->payload_length;
    }

    if ( elf_is_elfbinary(*image_start, *image_len) )
        return 0;

    BUG_ON(!(image_base < *image_start));

    output_len = output_length(*image_start, orig_image_len);

    if ( (err = perform_gunzip(image_base, *image_start, orig_image_len)) > 0 )
        err = decompress(*image_start, orig_image_len, image_base);

    if ( !err )
    {
        *image_start = image_base;
        *image_len = output_len;
    }

    return err > 0 ? 0 : err;
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

#ifndef __XEN_KIMAGE_H__
#define __XEN_KIMAGE_H__

#define IND_DESTINATION  0x1
#define IND_INDIRECTION  0x2
#define IND_DONE         0x4
#define IND_SOURCE       0x8
#define IND_ZERO        0x10

#ifndef __ASSEMBLY__

#include <xen/list.h>
#include <xen/mm.h>
#include <xen/elfstructs.h>
#include <public/kexec.h>

#define KEXEC_SEGMENT_MAX 16

extern const char kexec_purgatory[];
extern const unsigned int kexec_purgatory_size;

typedef paddr_t kimage_entry_t;

struct purgatory_info {
    uint64_t dest;
    void *buffer;
    uint64_t bufsz;
    uint64_t memsz;
    uint64_t buf_align;
    Elf_Shdr *sechdrs;
};

struct kexec_image {
    uint8_t type;
    uint16_t arch;
    uint64_t entry_maddr;
    uint32_t nr_segments;
    xen_kexec_segment_t *segments;

    kimage_entry_t head;
    struct page_info *entry_page;
    unsigned next_entry;

    struct page_info *control_code_page;
    struct page_info *aux_page;

    struct page_list_head control_pages;
    struct page_list_head dest_pages;
    struct page_list_head unusable_pages;

    /* Address of next control page to allocate for crash kernels. */
    paddr_t next_crash_page;

    struct purgatory_info pi;
    xen_kexec_regs_t regs;
};

int kimage_alloc(struct kexec_image **rimage, uint8_t type, uint16_t arch,
                 uint64_t entry_maddr,
                 uint32_t nr_segments, xen_kexec_segment_t *segment);
void kimage_free(struct kexec_image *image);
int kimage_load_segments(struct kexec_image *image);
struct page_info *kimage_alloc_control_page(struct kexec_image *image,
                                            unsigned memflags);

kimage_entry_t *kimage_entry_next(kimage_entry_t *entry, bool compat);
mfn_t kimage_entry_mfn(kimage_entry_t *entry, bool compat);
unsigned long kimage_entry_ind(kimage_entry_t *entry, bool compat);
int kimage_build_ind(struct kexec_image *image, mfn_t ind_mfn,
                     bool compat);
int kimage_setup_purgatory(struct kexec_image *image, uint64_t parameters);
void kimage_terminate(struct kexec_image *image);

int arch_kexec_apply_relocations_add(struct purgatory_info *pi,
                                     Elf_Shdr *section, const Elf_Shdr *relsec,
                                     const Elf_Shdr *symtabsec);

#endif /* __ASSEMBLY__ */

#endif /* __XEN_KIMAGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

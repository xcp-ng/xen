#include <xen/config.h>
#include <xen/multiboot.h>
#include <xen/multiboot2.h>
#include <public/xen.h>
#include <asm/asm_defns.h>
#include <asm/desc.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/msr.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>

        .text
        .code32

#define sym_phys(sym)     ((sym) - __XEN_VIRT_START)

#define BOOT_CS32        0x0008
#define BOOT_CS64        0x0010
#define BOOT_DS          0x0018
#define BOOT_PSEUDORM_CS 0x0020
#define BOOT_PSEUDORM_DS 0x0028

ENTRY(start)
        jmp     __start

        .align 4
multiboot1_header_start:       /*** MULTIBOOT1 HEADER ****/
#define MULTIBOOT_HEADER_FLAGS (MULTIBOOT_HEADER_MODS_ALIGNED | \
                                MULTIBOOT_HEADER_WANT_MEMORY)
        /* Magic number indicating a Multiboot header. */
        .long   MULTIBOOT_HEADER_MAGIC
        /* Flags to bootloader (see Multiboot spec). */
        .long   MULTIBOOT_HEADER_FLAGS
        /* Checksum: must be the negated sum of the first two fields. */
        .long   -(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_HEADER_FLAGS)
multiboot1_header_end:

/*** MULTIBOOT2 HEADER ****/
/* Some ideas are taken from grub-2.00/grub-core/tests/boot/kernel-i386.S file. */
        .align  MULTIBOOT2_HEADER_ALIGN

.Lmultiboot2_header:
        /* Magic number indicating a Multiboot2 header. */
        .long   MULTIBOOT2_HEADER_MAGIC
        /* Architecture: i386. */
        .long   MULTIBOOT2_ARCHITECTURE_I386
        /* Multiboot2 header length. */
        .long   .Lmultiboot2_header_end - .Lmultiboot2_header
        /* Multiboot2 header checksum. */
        .long   -(MULTIBOOT2_HEADER_MAGIC + MULTIBOOT2_ARCHITECTURE_I386 + \
                        (.Lmultiboot2_header_end - .Lmultiboot2_header))

        /* Multiboot2 tags... */
.Lmultiboot2_info_req:
        /* Multiboot2 information request tag. */
        .short  MULTIBOOT2_HEADER_TAG_INFORMATION_REQUEST
        .short  MULTIBOOT2_HEADER_TAG_REQUIRED
        .long   .Lmultiboot2_info_req_end - .Lmultiboot2_info_req
        .long   MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO
        .long   MULTIBOOT2_TAG_TYPE_MMAP
        .long   MULTIBOOT2_TAG_TYPE_EFI_BS
        .long   MULTIBOOT2_TAG_TYPE_EFI64
        .long   MULTIBOOT2_TAG_TYPE_EFI64_IH
.Lmultiboot2_info_req_end:

        .align  MULTIBOOT2_TAG_ALIGN
        .short  MULTIBOOT2_HEADER_TAG_MODULE_ALIGN
        .short  MULTIBOOT2_HEADER_TAG_REQUIRED
        .long   8 /* Tag size. */

        /* Console flags tag. */
        .align  MULTIBOOT2_TAG_ALIGN
        .short  MULTIBOOT2_HEADER_TAG_CONSOLE_FLAGS
        .short  MULTIBOOT2_HEADER_TAG_OPTIONAL
        .long   12 /* Tag size. */
        .long   MULTIBOOT2_CONSOLE_FLAGS_EGA_TEXT_SUPPORTED

        /* Framebuffer tag. */
        .align  MULTIBOOT2_TAG_ALIGN
        .short  MULTIBOOT2_HEADER_TAG_FRAMEBUFFER
        .short  MULTIBOOT2_HEADER_TAG_OPTIONAL
        .long   20 /* Tag size. */
        .long   0 /* Number of the columns - no preference. */
        .long   0 /* Number of the lines - no preference. */
        .long   0 /* Number of bits per pixel - no preference. */

        /* Do not disable EFI boot services. */
        .align  MULTIBOOT2_TAG_ALIGN
        .short  MULTIBOOT2_HEADER_TAG_EFI_BS
        .short  MULTIBOOT2_HEADER_TAG_OPTIONAL
        .long   8 /* Tag size. */

        /* EFI64 entry point. */
        .align  MULTIBOOT2_TAG_ALIGN
        .short  MULTIBOOT2_HEADER_TAG_ENTRY_ADDRESS_EFI64
        .short  MULTIBOOT2_HEADER_TAG_OPTIONAL
        .long   12 /* Tag size. */
        .long   sym_phys(__efi64_start)

        /* Multiboot2 header end tag. */
        .align  MULTIBOOT2_TAG_ALIGN
        .short  MULTIBOOT2_HEADER_TAG_END
        .short  0
        .long   8 /* Tag size. */
.Lmultiboot2_header_end:

        .section .init.rodata, "a", @progbits
        .align 4

        .word   0
gdt_boot_descr:
        .word   6*8-1
        .long   sym_phys(trampoline_gdt)
        .long   0 /* Needed for 64-bit lgdt */

cs32_switch_addr:
        .long   sym_phys(cs32_switch)
        .long   BOOT_CS32

efi_st:
        .quad   0

efi_ih:
        .quad   0

.Lbad_cpu_msg: .asciz "ERR: Not a 64-bit CPU!"
.Lbad_ldr_msg: .asciz "ERR: Not a Multiboot bootloader!"

        .section .init.text, "ax", @progbits

bad_cpu:
        mov     $(sym_phys(.Lbad_cpu_msg)),%esi # Error message
        jmp     print_err
not_multiboot:
        mov     $(sym_phys(.Lbad_ldr_msg)),%esi # Error message
print_err:
        mov     $0xB8000,%edi  # VGA framebuffer
1:      mov     (%esi),%bl
        test    %bl,%bl        # Terminate on '\0' sentinel
        je      .Lhalt
        mov     $0x3f8+5,%dx   # UART Line Status Register
2:      in      %dx,%al
        test    $0x20,%al      # Test THR Empty flag
        je      2b
        mov     $0x3f8+0,%dx   # UART Transmit Holding Register
        mov     %bl,%al
        out     %al,%dx        # Send a character over the serial line
        movsb                  # Write a character to the VGA framebuffer
        mov     $7,%al
        stosb                  # Write an attribute to the VGA framebuffer
        jmp     1b
.Lhalt: hlt
        jmp     .Lhalt

        .code64

__efi64_start:
        cld

        /* Bootloaders may set multiboot[12].mem_lower to a nonzero value */
        xor     %edx,%edx

        /* Check for Multiboot2 bootloader */
        cmp     $MULTIBOOT2_BOOTLOADER_MAGIC,%eax
        je      efi_multiboot2_proto

        jmp     not_multiboot

efi_multiboot2_proto:
        /* Skip Multiboot2 information fixed part */
        lea     MB2_fixed_sizeof(%ebx),%ecx

0:
        /* Get mem_lower from Multiboot2 information */
        cmpl    $MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO,(%ecx)
        jne     1f

        mov     MB2_mem_lower(%ecx),%edx
        jmp     4f

1:
        /* Get EFI SystemTable address from Multiboot2 information */
        cmpl    $MULTIBOOT2_TAG_TYPE_EFI64,(%ecx)
        jne     2f

        lea     MB2_efi64_st(%ecx),%esi
        lea     efi_st(%rip),%edi
        movsq

        /* Do not go into real mode on EFI platform */
        movb    $1,skip_realmode(%rip)

        jmp     4f

2:
        /* Get EFI ImageHandle address from Multiboot2 information */
        cmpl    $MULTIBOOT2_TAG_TYPE_EFI64_IH,(%ecx)
        jne     3f

        lea     MB2_efi64_ih(%ecx),%esi
        lea     efi_ih(%rip),%edi
        movsq
        jmp     4f

3:
        /* Is it the end of Multiboot2 information? */
        cmpl    $MULTIBOOT2_TAG_TYPE_END,(%ecx)
        je      run_bs

4:
        /* Go to next Multiboot2 information tag */
        add     MB2_tag_size(%ecx),%ecx
        add     $(MULTIBOOT2_TAG_ALIGN-1),%ecx
        and     $~(MULTIBOOT2_TAG_ALIGN-1),%ecx
        jmp     0b

run_bs:
        push    %rax
        push    %rdx

        /* Initialize BSS (no nasty surprises!) */
        lea     __bss_start(%rip),%rdi
        lea     _end(%rip),%rcx
        sub     %rdi,%rcx
        xor     %rax,%rax
        rep     stosb

        mov     efi_ih(%rip),%rdi   /* EFI ImageHandle */
        mov     efi_st(%rip),%rsi   /* EFI SystemTable */
        call    efi_multiboot2

        pop     %rcx
        pop     %rax

        shl     $10-4,%rcx          /* Convert multiboot2.mem_lower to bytes/16 */

        cli

        /* Initialise GDT */
        lgdt    gdt_boot_descr(%rip)

        /* Reload code selector */
        ljmpl   *cs32_switch_addr(%rip)

        .code32

cs32_switch:
        /* Initialise basic data segments */
        mov     $BOOT_DS,%edx
        mov     %edx,%ds
        mov     %edx,%es
        mov     %edx,%fs
        mov     %edx,%gs
        mov     %edx,%ss

        mov     $sym_phys(cpu0_stack)+1024,%esp

        /* Disable paging */
        mov     %cr0,%edx
        and     $(~X86_CR0_PG),%edx
        mov     %edx,%cr0

        push    %eax
        push    %ecx

        /* Disable Long Mode */
        mov     $MSR_EFER,%ecx
        rdmsr
        and     $(~EFER_LME),%eax
        wrmsr

        pop     %ecx
        pop     %eax

        /* Turn off PAE */
        mov     %cr4,%edx
        and     $(~X86_CR4_PAE),%edx
        mov     %edx,%cr4

        jmp     trampoline_setup

__start:
        cld
        cli

        /* Initialise GDT and basic data segments. */
        lgdt    %cs:sym_phys(gdt_boot_descr)
        mov     $BOOT_DS,%ecx
        mov     %ecx,%ds
        mov     %ecx,%es
        mov     %ecx,%ss

        /* Bootloaders may set multiboot[12].mem_lower to a nonzero value */
        xor     %edx,%edx

        /* Check for Multiboot bootloader */
        cmp     $MULTIBOOT_BOOTLOADER_MAGIC,%eax
        je      multiboot1_proto

        /* Check for Multiboot2 bootloader */
        cmp     $MULTIBOOT2_BOOTLOADER_MAGIC,%eax
        je      multiboot2_proto

        jmp     not_multiboot

multiboot1_proto:
        /* Get mem_lower from Multiboot information */
        testb   $MBI_MEMLIMITS,(%ebx)
        jz      bios_platform       /* not available? BDA value will be fine */

        mov     MB_mem_lower(%ebx),%edx
        jmp     bios_platform

multiboot2_proto:
        /* Skip Multiboot2 information fixed part */
        lea     MB2_fixed_sizeof(%ebx),%ecx

0:
        /* Get mem_lower from Multiboot2 information */
        cmpl    $MULTIBOOT2_TAG_TYPE_BASIC_MEMINFO,(%ecx)
        jne     1f

        mov     MB2_mem_lower(%ecx),%edx
        jmp     bios_platform

1:
        /* Is it the end of Multiboot2 information? */
        cmpl    $MULTIBOOT2_TAG_TYPE_END,(%ecx)
        je      bios_platform

        /* Go to next Multiboot2 information tag */
        add     MB2_tag_size(%ecx),%ecx
        add     $(MULTIBOOT2_TAG_ALIGN-1),%ecx
        and     $~(MULTIBOOT2_TAG_ALIGN-1),%ecx
        jmp     0b

bios_platform:
        /* Set up trampoline segment 64k below EBDA */
        movzwl  0x40e,%ecx          /* EBDA segment */
        cmp     $0xa000,%ecx        /* sanity check (high) */
        jae     0f
        cmp     $0x4000,%ecx        /* sanity check (low) */
        jae     1f
0:
        movzwl  0x413,%ecx          /* use base memory size on failure */
        shl     $10-4,%ecx
1:
        /*
         * Compare the value in the BDA with the information from the
         * multiboot structure (if available) and use the smallest.
         */
        cmp     $0x100,%edx         /* is the multiboot value too small? */
        jb      trampoline_setup    /* if so, do not use it */
        shl     $10-4,%edx
        cmp     %ecx,%edx           /* compare with BDA value */
        cmovb   %edx,%ecx           /* and use the smaller */

trampoline_setup:
        /* Reserve 64kb for the trampoline */
        sub     $0x1000,%ecx

        /* From arch/x86/smpboot.c: start_eip had better be page-aligned! */
        xor     %cl, %cl
        shl     $4, %ecx
        mov     %ecx,sym_phys(trampoline_phys)

        /* Save the Multiboot info struct (after relocation) for later use. */
        mov     $sym_phys(cpu0_stack)+1024,%esp
        push    %eax                /* Multiboot magic */
        push    %ebx                /* Multiboot information address */
        call    reloc               /* %ecx contains trampoline address */
        mov     %eax,sym_phys(multiboot_ptr)

        cmpb    $1,sym_phys(skip_realmode)
        je      1f

        /* Initialize BSS (no nasty surprises!) */
        mov     $sym_phys(__bss_start),%edi
        mov     $sym_phys(__bss_end),%ecx
        sub     %edi,%ecx
        xor     %eax,%eax
        rep     stosb

1:
        /* Interrogate CPU extended features via CPUID. */
        mov     $0x80000000,%eax
        cpuid
        shld    $16,%eax,%ecx
        xor     %edx,%edx
        cmp     $0x8000,%cx         # any function @ 0x8000xxxx?
        jne     1f
        cmp     $0x80000000,%eax    # any function > 0x80000000?
        jbe     1f
        mov     $0x80000001,%eax
        cpuid
1:      mov     %edx,sym_phys(cpuid_ext_features)
        mov     %edx,sym_phys(boot_cpu_data)+CPUINFO_FEATURE_OFFSET(X86_FEATURE_LM)

        /* Check for availability of long mode. */
        bt      $cpufeat_bit(X86_FEATURE_LM),%edx
        jnc     bad_cpu

        /* Stash TSC to calculate a good approximation of time-since-boot */
        rdtsc
        mov     %eax,sym_phys(boot_tsc_stamp)
        mov     %edx,sym_phys(boot_tsc_stamp+4)

        /*
         * During boot, hook 4kB mappings of first 2MB of memory into L2.
         * This avoids mixing cachability for the legacy VGA region, and is
         * corrected when Xen relocates itself.
         */
        mov     $sym_phys(l1_identmap)+__PAGE_HYPERVISOR,%edi
        mov     %edi,sym_phys(l2_xenmap)

        /* Apply relocations to bootstrap trampoline. */
        mov     sym_phys(trampoline_phys),%edx
        mov     $sym_phys(__trampoline_rel_start),%edi
1:
        mov     (%edi),%eax
        add     %edx,(%edi,%eax)
        add     $4,%edi
        cmp     $sym_phys(__trampoline_rel_stop),%edi
        jb      1b

        /* Patch in the trampoline segment. */
        shr     $4,%edx
        mov     $sym_phys(__trampoline_seg_start),%edi
1:
        mov     (%edi),%eax
        mov     %dx,(%edi,%eax)
        add     $4,%edi
        cmp     $sym_phys(__trampoline_seg_stop),%edi
        jb      1b

        call    cmdline_parse_early

        /* Switch to low-memory stack.  */
        mov     sym_phys(trampoline_phys),%edi
        lea     0x10000(%edi),%esp
        lea     trampoline_boot_cpu_entry-trampoline_start(%edi),%eax
        pushl   $BOOT_CS32
        push    %eax

        /* Copy bootstrap trampoline to low memory, below 1MB. */
        mov     $sym_phys(trampoline_start),%esi
        mov     $trampoline_end - trampoline_start,%ecx
        rep     movsb

        /* Jump into the relocated trampoline. */
        lret

#include "cmdline.S"

reloc:
#include "reloc.S"

ENTRY(trampoline_start)
#include "trampoline.S"
GLOBAL(trampoline_end)

#include "x86_64.S"

obj-bin-y += head.o

RELOC_DEPS = $(BASEDIR)/include/asm-x86/config.h $(BASEDIR)/include/xen/compiler.h \
	     $(BASEDIR)/include/xen/multiboot.h $(BASEDIR)/include/xen/multiboot2.h

head.o: reloc.S

reloc.S: reloc.c $(RELOC_DEPS)
	$(MAKE) -f build32.mk $@ RELOC_DEPS="$(RELOC_DEPS)"

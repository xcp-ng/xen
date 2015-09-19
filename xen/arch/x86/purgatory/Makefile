cc_common_flags = -Wall -Os -g0                                \
                    -nostdinc                                  \
                    -mcmodel=large                             \
                    -fno-builtin                               \
                    -ffreestanding                             \
                    -fno-zero-initialized-in-bss               \
                    -fno-stack-protector                       \
                    -fno-PIC                                   \
                    -fno-PIE                                   \
                    -fno-tree-vectorize                        \
                    -D__XEN__                                  \
                    -D__PURGATORY__                            \
                    -include $(srctree)/include/xen/config.h   \
                    -I$(srctree)/$(src)                        \
                    -I$(objtree)/include                       \
                    -I$(srctree)/include                       \
                    -I$(objtree)/arch/x86/include              \
                    -I$(srctree)/arch/x86/include              \
                    -I$(objtree)/arch/x86/include/generated

cmd_cc_purg = $(CC) $(cc_common_flags)               \
                  -c $< -o $@

cmd_cc_as_purg = $(CC) $(cc_common_flags)            \
		     -D__ASSEMBLY__                  \
		     -Wa,--noexecstack               \
                     -c $< -o $@

cmd_ld_purg = $(LD) --no-undefined               \
                -z nodefaultlib                  \
                -z noexecstack                   \
                -e purgatory_start               \
                -S $(real-prereqs) -o $@

cmd_ldr_purg = $(cmd_ld_purg) -r

purgatory-y := purgatory.o stack.o setup-x86_64.o sha2-256.o entry64.o memcmp.o
PURGATORY_OBJS = $(addprefix $(obj)/,$(purgatory-y))

$(obj)/%.o: $(src)/%.c $(src)/config.h
	$(call if_changed,cc_purg)

$(obj)/%.o: $(src)/%.S $(src)/config.h
	$(call if_changed,cc_as_purg)

$(obj)/sha2-256.o: $(srctree)/lib/sha2-256.c $(src)/config.h
	$(call if_changed,cc_purg)

$(obj)/memcmp.o: $(srctree)/lib/memcmp.c $(src)/config.h
	$(call if_changed,cc_purg)

$(obj)/purgatory.ro: $(PURGATORY_OBJS) FORCE
		$(call if_changed,ldr_purg)

$(obj)/purgatory.chk: $(obj)/purgatory.ro FORCE
		$(call if_changed,ld_purg)

$(obj)/kexec-purgatory.o: $(obj)/purgatory.ro $(obj)/purgatory.chk

$(obj)/kexec-purgatory.S: $(srctree)/tools/binfile FORCE
	$(call if_changed,binfile,$(obj)/purgatory.ro kexec_purgatory)

targets += kexec-purgatory.S

clean-files := purgatory.ro purgatory.chk

obj-y += kexec-purgatory.o

CFLAGS += -fshort-wchar

obj-y += boot.o
obj-y += compat.o
obj-y += runtime.o

extra-y += relocs-dummy.o

create = test -e $(1) || touch -t 199901010000 $(1)

efi := y$(shell rm -f disabled)
efi := $(if $(efi),$(shell $(CC) $(filter-out $(CFLAGS-y) .%.d,$(CFLAGS)) -c check.c 2>disabled && echo y))
efi := $(if $(efi),$(shell $(LD) -mi386pep --subsystem=10 -o check.efi check.o 2>disabled && echo y))
efi := $(if $(efi),$(shell rm disabled)y)
nogcov-$(efi) += stub.o

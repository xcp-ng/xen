XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror -Wshadow -Wno-unused-result
CFLAGS += -I$(XEN_ROOT)/tools/libs/ctrl -include $(XEN_ROOT)/tools/config.h -I$(XEN_ROOT)/tools
CFLAGS += $(CFLAGS_libxentoollog) $(CFLAGS_libxenctrl) $(CFLAGS_libguest) $(CFLAGS_libxenstore)
CFLAGS += -D_GNU_SOURCE -DXC_WANT_COMPAT_MAP_FOREIGN_API
CFLAGS += $(CFLAGS_libxentoolcore)

PROGRAMS := xenguest

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

ACPI_PATH  = $(XEN_ROOT)/tools/libacpi
DSDT_FILES = dsdt_pvh.c
ACPI_OBJS = dsdt_pvh.o build.o static_tables.o
$(DSDT_FILES) $(ACPI_OBJS): acpi
$(ACPI_OBJS): CFLAGS += -I. -DLIBACPI_STDUTILS=\"$(CURDIR)/acpi-utils.h\"
vpath build.c $(ACPI_PATH)/
vpath static_tables.c $(ACPI_PATH)/

.PHONY: acpi
acpi:
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) DSDT_FILES="$(DSDT_FILES)"

xenguest: xenguest.o xenguest_stubs.o xg_emu.o $(ACPI_OBJS)
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $^ \
		$(LDLIBS_libxentoollog) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) -ljson-c -pthread -lempserver

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: distclean clean
distclean clean:
	$(RM) *.o $(ALL_TARGETS)
	$(RM) $(DEPS)
	$(MAKE) -C $(ACPI_PATH) ACPI_BUILD_DIR=$(CURDIR) $@

-include $(DEPS)

XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror -Wshadow
CFLAGS += -I. -I$(XEN_ROOT)/tools/libxc -include $(XEN_ROOT)/tools/config.h
CFLAGS += $(CFLAGS_libxentoollog) $(CFLAGS_libxenctrl) $(CFLAGS_libguest) $(CFLAGS_libxenstore)
CFLAGS += -D_GNU_SOURCE -D_BSD_SOURCE -DXC_WANT_COMPAT_MAP_FOREIGN_API

PROGRAMS := xenguest

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAMS)

xenguest: xenguest.o xenguest_stubs.o xg_emu.o
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $^ \
		$(LDLIBS_libxentoollog) $(LDLIBS_libxenctrl) $(LDLIBS_libxenguest) $(LDLIBS_libxenstore) -ljson-c -pthread -lempserver

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(LIBEXEC_BIN)
	$(INSTALL_PROG) $(PROGRAMS) $(DESTDIR)$(LIBEXEC_BIN)

.PHONY: clean
clean:
	$(RM) *.o $(ALL_TARGETS)
	$(RM) $(DEPS)

-include $(DEPS)

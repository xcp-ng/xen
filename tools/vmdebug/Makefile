XEN_ROOT := $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

PROGRAM := xen-vmdebug
OBJS := main.o cmdtable.o lazy.o hvmparam.o

CFLAGS += -Werror $(CFLAGS_libxenctrl) $(CFLAGS_libxenguest)

.PHONY: all
all: build

.PHONY: build
build: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS_libxenctrl) $(APPEND_LDFLAGS)

.PHONY: install
install: build
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) $(PROGRAM) $(DESTDIR)$(sbindir)

.PHONY: clean
clean:
	$(RM) *.o *~ $(PROGRAM)
	$(RM) $(DEPS)

.PHONY: distclean
distclean: clean

-include $(DEPS)


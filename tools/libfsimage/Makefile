XEN_ROOT = $(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

SUBDIRS-y = common ufs reiserfs iso9660 fat zfs btrfs
SUBDIRS-$(CONFIG_X86) += xfs
ifneq ($(EXTFS_LIBS), )
    SUBDIRS-y += ext2fs-lib
else
    SUBDIRS-y += ext2fs
endif

.PHONY: all clean install
all clean install: %: subdirs-%

.PHONY: distclean
distclean: clean

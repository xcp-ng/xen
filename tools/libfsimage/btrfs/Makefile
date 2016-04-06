XEN_ROOT = $(CURDIR)/../../..

CFLAGS += -DBTRFS_FLAT_INCLUDES=1
LIB_SRCS-y = fsys_btrfs.c \
             crc32c.c \
             ctree.c \
	     dir-item.c \
             disk-io.c \
	     extent-cache.c \
	     extent_io.c \
	     extent-tree.c \
	     file-item.c \
	     free-space-cache.c \
	     inode.c \
	     inode-item.c \
	     raid6.c \
	     rbtree.c \
	     rbtree-utils.c \
	     repair.c \
	     root-tree.c \
	     utils.c \
	     volumes.c

FS = btrfs
FS_LIBDEPS =  $(filter -llzo2,$(ZLIB)) -lz

# Include configure output (config.h)
CFLAGS += -include $(XEN_ROOT)/tools/config.h

include $(XEN_ROOT)/tools/libfsimage/Rules.mk

/*
 * Copyright (C) 2016 Citrix Systems R&D Ltd.
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2 or later.  See the file COPYING for more details.
 */

#include "xenfsimage_plugin.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/xattr.h>
#ifdef HAVE_LZO1X
#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>
#endif
#include <zlib.h>

#include "kerncompat.h"
#include "ctree.h"
#include "disk-io.h"
#include "internal.h"
#include "volumes.h"

/* #define DDEBUG */

#ifdef DDEBUG
__attribute__ ((format (printf, 1, 2)))
static inline void debug(const char *fmt, ...)
{
    va_list args;
    int saved_errno = errno;

    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    errno = saved_errno;
}
#else
__attribute__ ((format (printf, 1, 2)))
static inline void debug(const char *fmt, ...)
{
}
#endif

struct btrfs_file {
    struct btrfs_key key;
    struct btrfs_root *root;
    size_t size;
    uint64_t filepos;
};

/*
 * To avoid significant modifications to the import btrfs files, use a global
 * offset variable which is added to every pread() call so that a partition
 * within a disk image can be used.
 */
uint64_t partition_offset;

/*
 * This code only supports opening a single disk image due to apparent
 * limitations in the btrfs code when doing a sequence of open_ctree(),
 * open_ctree(), close_ctree(), close_ctree().
 */
static struct btrfs_fs_info *fs_info;
static char *mount_dev;
static char *mount_options;

static int
btrfs_mount(fsi_t *fsi, const char *dev, const char *options)
{
    u64 bytenr;
    uint64_t offset;
    int i;

    offset = fsip_fs_offset(fsi);
    if (!options)
        options = "";

    if (fs_info) {
        if (strcmp(dev, mount_dev) || strcmp(options, mount_options) ||
            offset != partition_offset) {
            errno = ENOTSUP;
            return -1;
        }
        return 0;
    }

    partition_offset = offset;
    debug("Mount %s, offset %lu\n", dev, partition_offset);

    for (i = 0; i < BTRFS_SUPER_MIRROR_MAX; i++) {
        bytenr = btrfs_sb_offset(i);
        fs_info = open_ctree_fs_info(dev, bytenr, 0, 0, OPEN_CTREE_PARTIAL);
        if (fs_info)
            break;
        debug("Could not open root, trying backup super\n");
    }

    if (!fs_info)
        return -1;

    mount_dev = strdup(dev);
    if (options)
        mount_options = strdup(options);
    else
        mount_options = "";

    return 0;
}

static int
btrfs_umount(fsi_t *fsi)
{
    return 0;
}

static int
symlink_lookup(struct btrfs_root *root, struct btrfs_key key,
               char *symlink_target)
{
    struct btrfs_path path;
    struct extent_buffer *leaf;
    struct btrfs_file_extent_item *extent_item;
    u32 len;
    u32 name_offset;
    int ret;

    btrfs_init_path(&path);

    key.type = BTRFS_EXTENT_DATA_KEY;
    key.offset = 0;

    ret = btrfs_search_slot(NULL, root, &key, &path, 0, 0);
    if (ret < 0)
        return 0;

    leaf = path.nodes[0];
    if (!leaf) {
        debug("Error getting leaf for symlink\n");
        ret = -EIO;
        goto out;
    }

    extent_item = btrfs_item_ptr(leaf, path.slots[0],
                                 struct btrfs_file_extent_item);

    len = btrfs_file_extent_inline_item_len(leaf, btrfs_item_nr(path.slots[0]));
    if (len >= PATH_MAX) {
        debug("Symlink target length %d is longer than PATH_MAX\n", len);
        ret = -ENAMETOOLONG;
        goto out;
    }

    name_offset = (unsigned long) extent_item
        + offsetof(struct btrfs_file_extent_item, disk_bytenr);
    read_extent_buffer(leaf, symlink_target, name_offset, len);

    symlink_target[len] = 0;

out:
    btrfs_release_path(&path);
    return ret;
}

char *
skip_slashes(char *s)
{
    while (*s && *s == '/')
        s++;
    return s;
}

/* Returns 0 on success, or -errno on failure. */
static int
lookup_inode(struct btrfs_file *file, char *search_name)
{
    struct btrfs_path path;
    struct btrfs_key *key = &file->key;
    struct btrfs_dir_item *di;
    struct btrfs_inode_item *inode_item;
    int ret, link = 0;
    char *ptr;
    char *name = skip_slashes(search_name);
    u64 dir;
    struct btrfs_root *root;

again:
    btrfs_init_path(&path);

    /* Lookup default subvolume */
    dir = btrfs_super_root_dir(file->root->fs_info->super_copy);
    di = btrfs_lookup_dir_item(NULL, file->root, &path, dir, "default", 7, 0);
    if (!di) {
        btrfs_release_path(&path);
        return -ENOENT;
    }

    /* Find fs_root for default subvolume */
    btrfs_dir_item_key_to_cpu(path.nodes[0], di, key);
    btrfs_release_path(&path);
    key->type = BTRFS_ROOT_ITEM_KEY;
    key->offset = (u64)-1;
    root = btrfs_read_fs_root(file->root->fs_info, key);
    if (IS_ERR(root)) {
        debug("Error reading subvolume %lu\n", PTR_ERR(root));
        return PTR_ERR(root);
    }
    dir = btrfs_root_dirid(&root->root_item);

    for (;; ) {
        ptr = strchr(name, '/');
        if (ptr)
            *ptr = '\0';

        debug("lookup component %s\n", name);

        di = btrfs_lookup_dir_item(NULL, root, &path, dir, name, strlen(name), 0);
        if (IS_ERR(di))
            return PTR_ERR(di);
        else if (!di)
            return -ENOENT;

        btrfs_dir_item_key_to_cpu(path.nodes[0], di, key);
        btrfs_release_path(&path);

        /* Follow subvolume if needed */
        if (key->type == BTRFS_ROOT_ITEM_KEY) {
            key->offset = (u64)-1;
            root = btrfs_read_fs_root(file->root->fs_info, key);
            if (IS_ERR(root)) {
                debug("Error reading subvolume %lu\n", PTR_ERR(root));
                return PTR_ERR(root);
            }
            dir = btrfs_root_dirid(&root->root_item);
            goto next;
        }

        ret = btrfs_lookup_inode(NULL, root, &path, key, 0);
        if (ret < 0)
            return ret;

        inode_item = btrfs_item_ptr(path.nodes[0], path.slots[0],
                                    struct btrfs_inode_item);
        file->size = btrfs_inode_size(path.nodes[0], inode_item);

        /* Follow symlink if needed */
        if ((btrfs_inode_mode(path.nodes[0], inode_item) & S_IFMT) == S_IFLNK) {
            char symlink_buf[PATH_MAX];

            btrfs_release_path(&path);
            if (++link == 40)
                return -ELOOP;

            ret = symlink_lookup(root, *key, symlink_buf);
            if (ret < 0)
                return ret;

            debug("symlink lookup %s\n", symlink_buf);

            /* Restart lookup if symlink is absolute */
            if (*symlink_buf == '/') {
                strcpy(search_name, symlink_buf);
                goto again;
            }

            if (((name - search_name) + strlen(symlink_buf)) > (PATH_MAX - 1))
                return -ENAMETOOLONG;
            strcpy(name, symlink_buf);
            continue;
        }

        dir = key->objectid;
        btrfs_release_path(&path);

next:
        if (!ptr)
            break;

        name = skip_slashes(ptr + 1);
    }

    file->root = root;
    return 0;
}

/* Copied from btrfs-progs/cmds-restore.c */
#define LZO_LEN 4
#define lzo1x_worst_compress(x) ((x) + ((x) / 16) + 64 + 3)

static int decompress_zlib(char *inbuf, char *outbuf, u64 compress_len,
                           u64 decompress_len)
{
    z_stream strm;
    int ret;

    memset(&strm, 0, sizeof(strm));
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        debug("zlib init returned %d", ret);
        return -EIO;
    }

    strm.avail_in = compress_len;
    strm.next_in = (unsigned char *)inbuf;
    strm.avail_out = decompress_len;
    strm.next_out = (unsigned char *)outbuf;
    ret = inflate(&strm, Z_NO_FLUSH);
    if (ret != Z_STREAM_END) {
        (void)inflateEnd(&strm);
        debug("zlib inflate failed: %d", ret);
        return -EIO;
    }

    (void)inflateEnd(&strm);
    return 0;
}

/* Copied from btrfs-progs/cmds-restore.c */
static inline size_t read_compress_length(unsigned char *buf)
{
    __le32 dlen;
    memcpy(&dlen, buf, LZO_LEN);
    return le32_to_cpu(dlen);
}

#ifdef HAVE_LZO1X
/* Copied from btrfs-progs/cmds-restore.c */
static int decompress_lzo(struct btrfs_root *root, unsigned char *inbuf,
                          char *outbuf, u64 compress_len, u64 *decompress_len)
{
    size_t new_len;
    size_t in_len;
    size_t out_len = 0;
    size_t tot_len;
    size_t tot_in;
    int ret;

    ret = lzo_init();
    if (ret != LZO_E_OK) {
        debug("lzo init returned %d", ret);
        return -EIO;
    }

    tot_len = read_compress_length(inbuf);
    inbuf += LZO_LEN;
    tot_in = LZO_LEN;

    while (tot_in < tot_len) {
        size_t mod_page;
        size_t rem_page;
        in_len = read_compress_length(inbuf);

        if ((tot_in + LZO_LEN + in_len) > tot_len) {
            debug("bad compress length %lu", (unsigned long)in_len);
            return -EIO;
        }

        inbuf += LZO_LEN;
        tot_in += LZO_LEN;
        new_len = lzo1x_worst_compress(root->sectorsize);
        ret = lzo1x_decompress_safe((const unsigned char *)inbuf, in_len,
                (unsigned char *)outbuf,
                (void *)&new_len, NULL);
        if (ret != LZO_E_OK) {
            debug("lzo decompress failed: %d", ret);
            return -EIO;
        }
        out_len += new_len;
        outbuf += new_len;
        inbuf += in_len;
        tot_in += in_len;

        /*
         * If the 4 byte header does not fit to the rest of the page we
         * have to move to the next one, unless we read some garbage
         */
        mod_page = tot_in % root->sectorsize;
        rem_page = root->sectorsize - mod_page;
        if (rem_page < LZO_LEN) {
            inbuf += rem_page;
            tot_in += rem_page;
        }
    }

    *decompress_len = out_len;

    return 0;
}
#else
static int decompress_lzo(struct btrfs_root *root, unsigned char *inbuf,
                          char *outbuf, u64 compress_len, u64 *decompress_len)
{
    return -ENOTSUP;
}
#endif

/* Copied from btrfs-progs/cmds-restore.c */
static int decompress(struct btrfs_root *root, char *inbuf, char *outbuf,
                      u64 compress_len, u64 *decompress_len, int compress)
{
    switch (compress) {
        case BTRFS_COMPRESS_ZLIB:
            return decompress_zlib(inbuf, outbuf, compress_len,
                                   *decompress_len);
        case BTRFS_COMPRESS_LZO:
            return decompress_lzo(root, (unsigned char *)inbuf, outbuf,
                                  compress_len, decompress_len);
        default:
            break;
    }

    debug("invalid compression type: %d", compress);
    return -EIO;
}

/* Copied from btrfs-progs/cmds-restore.c */
static int next_leaf(struct btrfs_root *root, struct btrfs_path *path)
{
    int slot;
    int level = 1;
    int offset = 1;
    struct extent_buffer *c;
    struct extent_buffer *next = NULL;

again:
    for (; level < BTRFS_MAX_LEVEL; level++) {
        if (path->nodes[level])
            break;
    }

    if (level >= BTRFS_MAX_LEVEL)
        return 1;

    slot = path->slots[level] + 1;

    while(level < BTRFS_MAX_LEVEL) {
        if (!path->nodes[level])
            return 1;

        slot = path->slots[level] + offset;
        c = path->nodes[level];
        if (slot >= btrfs_header_nritems(c)) {
            level++;
            if (level == BTRFS_MAX_LEVEL)
                return 1;
            offset = 1;
            continue;
        }

        if (path->reada)
            reada_for_search(root, path, level, slot, 0);

        next = read_node_slot(root, c, slot);
        if (extent_buffer_uptodate(next))
            break;
        offset++;
    }
    path->slots[level] = slot;
    while(1) {
        level--;
        c = path->nodes[level];
        free_extent_buffer(c);
        path->nodes[level] = next;
        path->slots[level] = 0;
        if (!level)
            break;
        if (path->reada)
            reada_for_search(root, path, level, 0, 0);
        next = read_node_slot(root, next, 0);
        if (!extent_buffer_uptodate(next))
            goto again;
    }
    return 0;
}

/*
 * Copies data from the input buffer to the output buffer where they overlap.
 * in_buf: Input buffer (read from disk)
 * in_len: Number of bytes in input buffer
 * in_offset: Offset of input buffer in file
 * out_buf: Ouput buffer (returned to the caller)
 * out_len: Number of available bytes in output buffer
 * out_offset: Offset of output buffer in file
 * file_size: Length of file
 */
static u64
fill_buffer(char *in_buf, u64 in_len, u64 in_offset,
            char *out_buf, u64 out_len, u64 out_offset,
            u64 file_size)
{
    u64 amount, delta;

    if (in_offset + in_len <= out_offset)
        return 0;
    if (in_offset >= (out_offset + out_len))
        return 0;

    if (in_len + in_offset > file_size)
        in_len = file_size - in_offset;
    if (in_offset >= out_offset) {
        delta = in_offset - out_offset;
        amount = min(in_len, out_len - delta);
        memcpy(out_buf + delta, in_buf, amount);
    } else {
        delta = out_offset - in_offset;
        amount = min(in_len - delta, out_len);
        memcpy(out_buf, in_buf + delta, amount);
    }
    return amount;
}

/* Adapted from btrfs-progs/cmds-restore.c */
static ssize_t
read_inline(struct btrfs_root *root, struct btrfs_path *path,
            u64 file_size, u64 in_offset,
            char *out_buf, u64 out_len, u64 out_offset)
{
    struct extent_buffer *leaf = path->nodes[0];
    struct btrfs_file_extent_item *fi;
    unsigned long ptr;
    char in_buf[4096];
    int len;
    int inline_item_len;
    int compress;
    char *comp_buf;
    u64 ram_size;
    ssize_t ret;

    fi = btrfs_item_ptr(leaf, path->slots[0],
            struct btrfs_file_extent_item);
    ptr = btrfs_file_extent_inline_start(fi);
    len = btrfs_file_extent_inline_len(leaf, path->slots[0], fi);
    inline_item_len = btrfs_file_extent_inline_item_len(leaf,
            btrfs_item_nr(path->slots[0]));
    read_extent_buffer(leaf, in_buf, ptr, inline_item_len);

    compress = btrfs_file_extent_compression(leaf, fi);
    if (compress == BTRFS_COMPRESS_NONE)
        return fill_buffer(in_buf, len, in_offset,
                out_buf, out_len, out_offset,
                file_size);

    ram_size = btrfs_file_extent_ram_bytes(leaf, fi);
    comp_buf = calloc(1, ram_size);
    if (!comp_buf) {
        debug("not enough memory");
        return -ENOMEM;
    }

    ret = decompress(root, in_buf, comp_buf, len, &ram_size, compress);
    if (ret) {
        free(comp_buf);
        return ret;
    }

    ret = fill_buffer(comp_buf, len, in_offset,
            out_buf, out_len, out_offset,
            file_size);
    free(comp_buf);

    return ret;
}

/* Adapted from btrfs-progs/cmds-restore.c */
static ssize_t read_extent(struct btrfs_root *root,
                           struct extent_buffer *leaf,
                           struct btrfs_file_extent_item *fi,
                           u64 file_size, u64 in_offset,
                           char *out_buf, u64 out_len, u64 out_offset)
{
    struct btrfs_multi_bio *multi = NULL;
    struct btrfs_device *device;
    char *in_buf, *comp_buf = NULL;
    u64 bytenr;
    u64 ram_size;
    u64 disk_size;
    u64 num_bytes;
    u64 length;
    u64 size_left;
    u64 dev_bytenr;
    u64 offset;
    u64 count = 0;
    int compress;
    ssize_t ret;
    int dev_fd;

    compress = btrfs_file_extent_compression(leaf, fi);
    bytenr = btrfs_file_extent_disk_bytenr(leaf, fi);
    disk_size = btrfs_file_extent_disk_num_bytes(leaf, fi);
    ram_size = btrfs_file_extent_ram_bytes(leaf, fi);
    offset = btrfs_file_extent_offset(leaf, fi);
    num_bytes = btrfs_file_extent_num_bytes(leaf, fi);
    size_left = disk_size;
    if (compress == BTRFS_COMPRESS_NONE)
        bytenr += offset;

    /* we found a hole */
    if (disk_size == 0)
        return 0;

    in_buf = malloc(size_left);
    if (!in_buf) {
        debug("not enough memory\n");
        return -ENOMEM;
    }

    if (compress != BTRFS_COMPRESS_NONE) {
        comp_buf = calloc(1, ram_size);
        if (!comp_buf) {
            debug("not enough memory");
            free(in_buf);
            return -ENOMEM;
        }
    }

    while (size_left) {
        length = size_left;
        ret = btrfs_map_block(&root->fs_info->mapping_tree, READ,
                              bytenr, &length, &multi, 1, NULL);
        if (ret) {
            debug("cannot map block logical %llu length %llu: %ld",
                  bytenr, length, ret);
            goto out;
        }
        device = multi->stripes[0].dev;
        dev_fd = device->fd;
        dev_bytenr = multi->stripes[0].physical;
        kfree(multi);

        if (size_left < length)
            length = size_left;

        ret = pread(dev_fd, in_buf + count, length,
                    dev_bytenr + partition_offset);
        /* Need both checks, or we miss negative values due to u64 conversion */
        if (ret < 0 || ret < length) {
            debug("read error\n");
            goto out;
        }

        size_left -= length;
        count += length;
        bytenr += length;
    }

    if (compress == BTRFS_COMPRESS_NONE) {
        ret = fill_buffer(in_buf, num_bytes, in_offset,
                          out_buf, out_len, out_offset,
                          file_size);
        goto out;
    }

    ret = decompress(root, in_buf, comp_buf, disk_size, &ram_size, compress);
    if (ret)
        goto out;

    ret = fill_buffer(comp_buf, num_bytes, in_offset,
                      out_buf, out_len, out_offset,
                      file_size);
out:
    free(in_buf);
    free(comp_buf);
    return ret;
}

/*
 * Adapted from btrfs-progs/cmds-restore.c
 * Returns the number of bytes written on success.
 * On failure, returns -1 and sets errno.
 * */
static ssize_t
read_file(struct btrfs_file *file, char *buf, size_t len, uint64_t offset)
{
    struct extent_buffer *leaf;
    struct btrfs_path path;
    struct btrfs_file_extent_item *fi;
    struct btrfs_root *root = file->root;
    struct btrfs_key key = file->key;
    struct btrfs_key found_key;
    ssize_t written = 0;
    int ret;
    int extent_type;
    int compression;

    debug("read %lu bytes from offset %lu\n", len, offset);

    /* Zero buffer in case of holes */
    memset(buf, 0, len);

    btrfs_init_path(&path);

    key.offset = 0;
    key.type = BTRFS_EXTENT_DATA_KEY;

    ret = btrfs_search_slot(NULL, root, &key, &path, 0, 0);
    if (ret < 0) {
        debug("searching extent data returned %d", ret);
        goto out;
    }

    leaf = path.nodes[0];
    while (!leaf) {
        ret = next_leaf(root, &path);
        if (ret < 0) {
            debug("cannot get next leaf: %d", ret);
            goto out;
        } else if (ret > 0) {
            /* No more leaves to search */
            ret = 0;
            goto out;
        }
        leaf = path.nodes[0];
    }

    for (;;) {
        if (path.slots[0] >= btrfs_header_nritems(leaf)) {
            do {
                ret = next_leaf(root, &path);
                if (ret < 0) {
                    debug("Error searching %d\n", ret);
                    goto out;
                } else if (ret) {
                    /* No more leaves to search */
                    goto done;
                }
                leaf = path.nodes[0];
            } while (!leaf);
            continue;
        }

        btrfs_item_key_to_cpu(leaf, &found_key, path.slots[0]);
        if (found_key.objectid != key.objectid)
            break;
        if (found_key.type != key.type)
            break;
        fi = btrfs_item_ptr(leaf, path.slots[0], struct btrfs_file_extent_item);
        extent_type = btrfs_file_extent_type(leaf, fi);
        compression = btrfs_file_extent_compression(leaf, fi);
        if (compression >= BTRFS_COMPRESS_LAST) {
            debug("compression type %d not supported", compression);
            ret = -EIO;
            goto out;
        }

        if (extent_type == BTRFS_FILE_EXTENT_PREALLOC)
            goto next;
        if (extent_type == BTRFS_FILE_EXTENT_INLINE) {
            ret = read_inline(root, &path, file->size, found_key.offset,
                              buf, len, offset);
            if (ret < 0)
                goto out;
            written += ret;
        } else if (extent_type == BTRFS_FILE_EXTENT_REG) {
            ret = read_extent(root, leaf, fi, file->size, found_key.offset,
                              buf, len, offset);
            if (ret < 0)
                goto out;
            written += ret;
        } else {
            debug("weird extent type %d", extent_type);
        }
next:
        path.slots[0]++;
    }

done:
    return written;

out:
    errno = -ret;
    return -1;
}

fsi_file_t *
btrfs_open(fsi_t *fsi, const char *path)
{
    struct btrfs_file *f;
    char s[PATH_MAX];
    int ret;

    debug("open %s\n", path);

    if (strlen(path) > (PATH_MAX - 1)) {
        errno = EINVAL;
        return NULL;
    }
    strcpy(s, path);

    f = calloc(1, sizeof (*f));
    if (!f) {
        errno = ENOMEM;
        return NULL;
    }

    f->root = fs_info->tree_root;
    ret = lookup_inode(f, s);
    if (ret < 0) {
        errno = -ret;
        free(f);
        return NULL;
    }

    return fsip_file_alloc(fsi, f);
}

ssize_t
btrfs_pread(fsi_file_t *file, void *buf, size_t nbytes, uint64_t off)
{
    struct btrfs_file *f = fsip_file_data(file);

    debug("pread: %lu %lu\n", nbytes, off);

    return read_file(f, buf, nbytes, off);
}

ssize_t
btrfs_read(fsi_file_t *file, void *buf, size_t nbytes)
{
    struct btrfs_file *f = fsip_file_data(file);
    ssize_t ret = btrfs_pread(file, buf, nbytes, f->filepos);

    if (ret > 0)
        f->filepos += ret;

    return ret;
}

int
btrfs_close(fsi_file_t *file)
{
    struct btrfs_file *f = fsip_file_data(file);
    free(f);
    return 0;
}

fsi_plugin_ops_t *
fsi_init_plugin(int version, fsi_plugin_t *fp, const char **name)
{
    static fsi_plugin_ops_t ops = {
        FSIMAGE_PLUGIN_VERSION,
        .fpo_mount = btrfs_mount,
        .fpo_umount = btrfs_umount,
        .fpo_open = btrfs_open,
        .fpo_read = btrfs_read,
        .fpo_pread = btrfs_pread,
        .fpo_close = btrfs_close
    };

    *name = "btrfs";
    return &ops;
}

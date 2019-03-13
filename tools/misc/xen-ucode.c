#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <xenctrl.h>

static const char *intel_id = "GenuineIntel";
static const char *amd_id   = "AuthenticAMD";

void show_curr_cpu(FILE *f)
{
    int ret;
    xc_interface *xch;
    struct xen_platform_op op = {0};
    struct xenpf_pcpu_version *ver = &op.u.pcpu_version;
    bool intel = false, amd = false;

    xch = xc_interface_open(0, 0, 0);
    if ( xch == NULL )
        return;

    op.cmd = XENPF_get_cpu_version;
    op.interface_version = XENPF_INTERFACE_VERSION;
    op.u.pcpu_version.xen_cpuid = 0;

    ret = xc_platform_op(xch, &op);
    if ( ret )
        return;

    if ( memcmp(ver->vendor_id, intel_id, sizeof(ver->vendor_id)) == 0 )
        intel = true;
    else if ( memcmp(ver->vendor_id, amd_id, sizeof(ver->vendor_id)) == 0 )
        amd = true;

    if ( intel )
    {
        fprintf(f,
                "Current CPU signature is: %02x-%02x-%02x (raw %#x)\n",
                 ver->family, ver->model, ver->stepping, ver->cpu_signature);
    }
    else if ( amd )
    {
        fprintf(f,
                "Current CPU signature is: fam%xh (raw %#x)\n",
                 ver->family, ver->cpu_signature);
    }

    if ( intel || amd )
    {
        fprintf(f,
                "Current CPU microcode revision is: %#x\n",
                ver->ucode_revision);
    }

    if ( intel )
        fprintf(f,
                "Current CPU processor flag is: %#x\n",
                ver->pf);

    xc_interface_close(xch);
}

static int parse_strategy(const char *arg)
{
    if ( !strcmp(arg, "parallel") )
        return XENPF_microcode_parallel;
    if ( !strcmp(arg, "sequential") )
        return XENPF_microcode_sequential;
    return -1;
}

int main(int argc, char *argv[])
{
    int fd, ret;
    char *filename, *buf;
    size_t len;
    struct stat st;
    xc_interface *xch;
    int strategy;

    if ( argc >= 2 && !strcmp(argv[1], "show-cpu-info") )
    {
        show_curr_cpu(stdout);
        return 0;
    }

    if ( argc < 3 || (strategy = parse_strategy(argv[2])) < 0 )
    {
        fprintf(stderr,
                "xen-ucode: Xen microcode updating tool\n"
                "Usage: %s <microcode blob> <parallel|sequential>\n", argv[0]);
        show_curr_cpu(stderr);
        return 0;
    }

    filename = argv[1];
    fd = open(filename, O_RDONLY);
    if ( fd < 0 )
    {
        fprintf(stderr, "Could not open %s. (err: %s)\n",
                filename, strerror(errno));
        return errno;
    }

    if ( fstat(fd, &st) != 0 )
    {
        fprintf(stderr, "Could not get the size of %s. (err: %s)\n",
                filename, strerror(errno));
        return errno;
    }

    len = st.st_size;
    buf = mmap(0, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( buf == MAP_FAILED )
    {
        fprintf(stderr, "mmap failed. (error: %s)\n", strerror(errno));
        return errno;
    }

    xch = xc_interface_open(NULL, NULL, 0);
    if ( xch == NULL )
    {
        fprintf(stderr, "Error opening xc interface. (err: %s)\n",
                strerror(errno));
        return errno;
    }

    ret = xc_microcode_update(xch, buf, len, strategy);
    if ( ret )
        fprintf(stderr, "Failed to update microcode. (err: %s)\n",
                strerror(errno));

    xc_interface_close(xch);

    if ( munmap(buf, len) )
    {
        printf("Could not unmap: %d(%s)\n", errno, strerror(errno));
        return errno;
    }
    close(fd);

    return 0;
}

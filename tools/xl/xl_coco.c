#include <fcntl.h>
#include <limits.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"



int main_coco(int argc, char **argv) {
    int rc;
    int dst_file = 1;
    char * mmonce = NULL;
    uint32_t domid;
    bool is_mmonce_file = false;

    int opt;
    static struct option opts[] = {
        {"file", 1, 0, 'f'},
        {"print", 0, 0, 'p'},
        {"mmonce", 1, 0, 'm'},
        {"mmonce-file", 1, 0, 'n'},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "f:pm:n:", opts, "coco", 0) {
    case 'p':
        dst_file = 1;
        break;
    case 'f':
        dst_file = open(optarg, O_WRONLY | O_CREAT, 0644);
        if (!dst_file) {
            perror("open");
            return -1;
        }
        break;
    case 'm':
        mmonce = optarg;
        is_mmonce_file = false;
        break;
    case 'n':
        mmonce = optarg;
        is_mmonce_file = true;
        break;
    }

    if (mmonce == NULL) {
        fprintf(stderr, "Error: no mmonce provided\n");
        return 1;
    }

    domid = find_domain(argv[optind]);

    rc = libxl_domain_attestation(ctx, domid, dst_file, is_mmonce_file, mmonce);

    return rc;
}

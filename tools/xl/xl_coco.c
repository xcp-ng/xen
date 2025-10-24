#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>
#include <xen-tools/common-macros.h>

#include "xl.h"
#include "xl_utils.h"



static int main_coco_attestation(int argc, char **argv);
static int main_coco_get_platform_certs(int argc, char **argv);
//static int main_coco_set_owner_key(int argc, char **argv);

static const struct cmd_spec coco_cmd_table[] = {
        { "attestation",
      &main_coco_attestation, 0, 0,
      "Get an attestation for a domain",
      "<Options> <Domain>",
    },
        { "platform",
      &main_coco_get_platform_certs, 0, 0,
      "Get the platform public key and identification",
      "<Options> <Domain>",
    }
    //    { "takeownership",
    //  &main_coco_set_owner_key, 0, 0,
    //  "Get the platform owner key",
    //  "<Options> <Domain>",
    //},
};

static int main_coco_attestation(int argc, char **argv) {
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

    SWITCH_FOREACH_OPT(opt, "f:pm:n:", opts, "coco attestation", 1) {
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

    rc = libxl_coco_domain_attestation(ctx, domid, dst_file, is_mmonce_file, mmonce);
    
    return rc;
}

static int main_coco_get_platform_certs(int argc, char **argv) {
    // get info hyprcall
    // write struct (get id + pdh)
    // no opt
    int opt, rc;
    SWITCH_FOREACH_OPT(opt, "", NULL, "coco platform", 0) {
        /* No options */
    }
    
    rc = libxl_coco_platform_certs(ctx);
    
    return rc;
}


static const int coco_cmdtable_len = ARRAY_SIZE(coco_cmd_table);

/* Look up a command in the table, allowing unambiguous truncation */
static const struct cmd_spec *coco_cmdtable_lookup(const char *s)
{
    const struct cmd_spec *cmd = NULL;
    size_t len;
    int i, count = 0;

    if (!s)
        return NULL;
    len = strlen(s);
    for (i = 0; i < coco_cmdtable_len; i++) {
        if (!strncmp(s, coco_cmd_table[i].cmd_name, len)) {
            cmd = &coco_cmd_table[i];
            /* Take an exact match, even if it also prefixes another command */
            if (len == strlen(cmd->cmd_name))
                return cmd;
            count++;
        }
    }
    return (count == 1) ? cmd : NULL;
}

int main_coco(int argc, char **argv) {
    int opt, rc;
    char *cmd;
    const struct cmd_spec *cspec;

    SWITCH_FOREACH_OPT(opt, "", NULL, "coco", 1) {
        /* No options */
    }
    cmd = argv[optind];

    /* Reset options for per-command use of getopt. */
    argv += optind;
    argc -= optind;
    optind = 1;
    
    cspec = coco_cmdtable_lookup(cmd);
    if (cspec) {
        rc = cspec->cmd_impl(argc, argv);
    } else {
        fprintf(stderr, "command not implemented\n");
        rc = EXIT_FAILURE;
    }

    return rc;
}

#include "libxl_internal.h"
#include "xenctrl.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int hex_char_to_int(char c) {
    if ('0' <= c && c <= '9') return c - '0';
    if ('a' <= c && c <= 'f') return c - 'a' + 10;
    if ('A' <= c && c <= 'F') return c - 'A' + 10;
    return -1;
}

int libxl_coco_domain_attestation(libxl_ctx *ctx, uint32_t domid, int file, bool is_mmonce_file, char *mmonce) {
    coco_attestation_report_t report;
    int rc, r;

    if (is_mmonce_file) {
        int datalen = 0;
        void *data = NULL;

        r = libxl_read_file_contents(ctx, mmonce, &data, &datalen);

        if (datalen != 16) {
            fprintf(stderr, "Error: invalid mmonce length\n");
            return ERROR_INVAL;
        }
        memcpy(&report.mnonce, data, 16);
        free(data);
    } else {
        if (strnlen(mmonce, 33) != 32) {
            fprintf(stderr, "Error: invalid mmonce length\n");
        }
        for (int i = 0; i < 16; i++) {
            int hi = hex_char_to_int(mmonce[2*i]);
            int lo = hex_char_to_int(mmonce[2*i + 1]);

            if (hi < 0 || lo < 0) {
                fprintf(stderr, "Error: invalid hex character\n");
                return -1;
            }

            report.mnonce[i] = (hi << 4) | lo;
        }

    }

    report.domid = domid;
    report.len = 0;

    rc = xc_coco_get_attestation(ctx->xch, &report);

    if (!rc) {
        size_t written = write(file, &report.sev, report.len);
        // the union used does not matter, we use the pointer
        if (written != report.len) {
            perror("write");
            close(file);
            return -1;
        }
    }

    close(file);
    return rc;
}


int libxl_coco_platform_certs(libxl_ctx *ctx, char* path) {
    int rc;
    coco_platform_certs_t certs;
    
    rc = xc_coco_get_platform_certs(ctx->xch, &certs);
    
    if (!rc) {
        int file = open(path, O_WRONLY | O_CREAT, 0644);
        if (!file) {
            perror("open:");
            return -1;
        }
        
        size_t written = write(file, &certs.sev, sizeof(certs.sev));
        if (written != sizeof(certs.sev)) {
            perror("write:");
            close(file);
            return -1;
        }
        
        printf("Platform Version: %d.%d.%d\n", 
            certs.status.version_major, 
            certs.status.version_minor, 
            certs.status.version_build);
            
        printf("Platform owned %s\n", certs.status.flags & COCO_STATUS_FEATURES_PLATFORM_OWNED ? "True" : "False");
            
        for (size_t cpu_n = 0; cpu_n < certs.cpu_number; cpu_n++) {
            printf("CPU ID %lu: ", cpu_n);
            for (size_t i = 0; i < 64; i++) {
                printf("%02X", certs.hwid[i + cpu_n * 64]);
            }
            printf("\n");
        }
    }
        
    return rc;
}
    
int libxl_coco_csr(libxl_ctx *ctx, char* path) {

    int rc;
    coco_certificate_t cert;
    
    rc = xc_coco_get_csr(ctx->xch, &cert);
    
    if (!rc) {
        int file = open(path, O_WRONLY | O_CREAT, 0644);
        if (!file) {
            perror("open:");
            return -1;
        }
        
        size_t written = write(file, &cert.sev, sizeof(cert.sev));
        if (written != sizeof(cert.sev)) {
            perror("write:");
            close(file);
            return -1;
        }
    }
    return rc;
}
int libxl_coco_regen_certificate(libxl_ctx *ctx, char* crt) {
    coco_certificate_name_t cert = 0;
    size_t i = 0;
    COCO_CERTIFICATE_NAME_ARRAY_DEF()
    for (; i < sizeof(certs_name) / 8; i++) {
        if (strcmp(crt, certs_name[i]) == 0) {
            cert = i;
            break;
        }
    }
    if (i == (sizeof(certs_name) / 8)) {
        printf("Invalid certificate name, not in :\n");
        for (i = 0; i < sizeof(certs_name) / 8; i++) {
            printf("%s ", certs_name[i]);
        }
        puts("");
        return -1;
    }
    
    return xc_coco_regen_certificate(ctx->xch, cert);
}

int libxl_coco_import_certificate(libxl_ctx *ctx, char *pek, char *crt) {
    coco_platform_import_certs_t import;
    void *data = NULL;
    int rc, datalen = 0;

    rc = libxl_read_file_contents(ctx, crt, &data, &datalen);
    if (datalen != sizeof(import.sev.oca)) {
        fprintf(stderr, "Error: invalid certificate length\n");
        return ERROR_INVAL;
    }
    memcpy(&import.sev.oca, data, sizeof(import.sev.oca));
    free(data);
    
    rc = libxl_read_file_contents(ctx, pek, &data, &datalen);

    if (datalen != sizeof(import.sev.pek)) {
        fprintf(stderr, "Error: invalid pek certificate length\n");
        return ERROR_INVAL;
    }
    memcpy(&import.sev.pek, data, sizeof(import.sev.pek));
    free(data);
    
    
    return xc_coco_import_certificate(ctx->xch, &import);
}

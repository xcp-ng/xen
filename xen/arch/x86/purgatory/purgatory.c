// SPDX-License-Identifier: GPL-2.0-only
/*
 * purgatory: Runs between two kernels
 *
 * Copyright (C) 2014 Red Hat Inc.
 * Copyright (C) 2024  Cloud Software Group Inc.
 *
 * Author:
 *       Vivek Goyal <vgoyal@redhat.com>
 *
 * This code has been imported from kexec-tools.
 */

#include <xen/sha2.h>
#include <xen/string.h>

struct sha256_region {
    uint64_t start;
    uint64_t len;
};

typedef uint8_t sha256_digest_t[SHA2_256_DIGEST_SIZE];

#define SHA256_REGIONS 16

struct sha256_region sha256_regions[SHA256_REGIONS] = {};
sha256_digest_t sha256_digest = { };

int verify_sha256_digest(void)
{
    struct sha256_region *ptr, *end;
    sha256_digest_t digest;
    struct sha2_256_state ctx;
    sha2_256_init(&ctx);
    end = &sha256_regions[sizeof(sha256_regions) / sizeof(sha256_regions[0])];

    for ( ptr = sha256_regions; ptr < end; ptr++ )
        sha2_256_update(&ctx, (uint8_t *)((uintptr_t)ptr->start), ptr->len);

    sha2_256_final(&ctx, digest);

    if ( memcmp(digest, sha256_digest, sizeof(digest)) != 0 )
        return 1;

    return 0;
}

void purgatory(void)
{
    int ret;

    ret = verify_sha256_digest();
    if ( ret )
    {
        /* loop forever */
        for ( ; ; )
            ;
    }
}

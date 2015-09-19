/* rsa.c

   The RSA publickey algorithm.

   Copyright (C) 2001 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#include <xen/rsa.h>
#include <xen/lib.h>
#include <xen/err.h>
#include <xen/bug.h>
#include <xen/sha2.h>
#include <xen/string.h>

void rsa_public_key_init(struct rsa_public_key *key)
{
    key->n = NULL;
    key->e = NULL;
    key->size = 0;
}

/*
 * Computes the size, in octets, of the modulo. Returns 0 if the
 * modulo is too small to be useful, or otherwise appears invalid.
 */
static size_t rsa_check_size(MPI n)
{
    /* Round upwards */
    size_t size;

    /* Even moduli are invalid */
    if ( mpi_test_bit(n, 0) == 0 )
        return 0;

    size = (mpi_get_nbits(n) + 7) / 8;

    if ( size < RSA_MINIMUM_N_OCTETS )
        return 0;

    return size;
}

int rsa_public_key_prepare(struct rsa_public_key *key)
{
    if ( !key->n || !key->e || key->size)
        return -EINVAL;

    key->size = rsa_check_size(key->n);

    return key->size > 0 ? 0 : -EINVAL;
}

/*
 * Formats the PKCS#1 padding, of the form
 *
 *   0x00 0x01 0xff ... 0xff 0x00 id ...digest...
 *
 * where the 0xff ... 0xff part consists of at least 8 octets. The
 * total size equals the octet size of n.
 */
static uint8_t *pkcs1_signature_prefix(unsigned int key_size, uint8_t *buffer,
                                       unsigned int id_size, const uint8_t *id,
                                       unsigned int digest_size)
{
    unsigned int j;

    if ( key_size < 11 + id_size + digest_size )
        return NULL;

    j = key_size - digest_size - id_size;

    memcpy(buffer + j, id, id_size);
    buffer[0] = 0;
    buffer[1] = 1;
    buffer[j-1] = 0;

    ASSERT(j >= 11);
    memset(buffer + 2, 0xff, j - 3);

    return buffer + j + id_size;
}

/*
 * From RFC 3447, Public-Key Cryptography Standards (PKCS) #1: RSA
 * Cryptography Specifications Version 2.1.
 *
 *     id-sha256    OBJECT IDENTIFIER ::=
 *       {joint-iso-itu-t(2) country(16) us(840) organization(1)
 *         gov(101) csor(3) nistalgorithm(4) hashalgs(2) 1}
 */
static const uint8_t
sha256_prefix[] =
{
  /* 19 octets prefix, 32 octets hash, total 51 */
  0x30,      49, /* SEQUENCE */
    0x30,    13, /* SEQUENCE */
      0x06,   9, /* OBJECT IDENTIFIER */
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
      0x05,   0, /* NULL */
    0x04,    32  /* OCTET STRING */
      /* Here comes the raw hash value */
};

static int pkcs1_rsa_sha256_encode(MPI *m, size_t key_size,
                                   struct sha2_256_state *hash)
{
    uint8_t *ptr;
    uint8_t *buf;

    buf = xmalloc_bytes(key_size);
    if ( !buf )
        return -ENOMEM;

    ptr = pkcs1_signature_prefix(key_size, buf,
                                 sizeof(sha256_prefix), sha256_prefix,
                                 SHA2_256_DIGEST_SIZE);
    if ( !ptr )
    {
        xfree(buf);
        return -EINVAL;
    }

    sha2_256_final(hash, ptr);
    *m = mpi_read_raw_data(buf, key_size);
    xfree(buf);
    return 0;
}

static int rsa_verify(const struct rsa_public_key *key, MPI m, MPI s)
{
    int ret;
    MPI m1;

    /* (1) Validate 0 <= s < n */
    if ( mpi_cmp_ui(s, 0) < 0 || mpi_cmp(s, key->n) >= 0 )
        return -EINVAL;

    m1 = mpi_alloc(key->size / BYTES_PER_MPI_LIMB);
    if ( !m1 )
        return -ENOMEM;

    /* (2) m = s^e mod n */
    ret = mpi_powm(m1, s, key->e, key->n);
    if ( ret )
        goto out;

    ret = mpi_cmp (m, m1) ? -EINVAL : 0;

out:
    mpi_free(m1);
    return ret;
}

int rsa_sha256_verify(const struct rsa_public_key *key,
                      struct sha2_256_state *hash, MPI s)
{
    int ret;
    MPI m;

    ret = pkcs1_rsa_sha256_encode(&m, key->size, hash);
    if ( ret )
        return ret;

    ret = rsa_verify(key, m, s);

    mpi_free(m);

    return ret;
}

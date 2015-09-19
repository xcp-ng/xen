/* rsa.h

   The RSA publickey algorithm.

   Copyright (C) 2001, 2002 Niels Möller

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

#ifndef RSA_H
#define RSA_H

#include <xen/mpi.h>
#include <xen/types.h>

struct sha2_256_state;

/*
 * This limit is somewhat arbitrary. Technically, the smallest modulo
 * which makes sense at all is 15 = 3*5, phi(15) = 8, size 4 bits. But
 * for ridiculously small keys, not all odd e are possible (e.g., for
 * 5 bits, the only possible modulo is 3*7 = 21, phi(21) = 12, and e =
 * 3 don't work). The smallest size that makes sense with pkcs#1, and
 * which allows RSA encryption of one byte messages, is 12 octets, 89
 * bits.
 */
#define RSA_MINIMUM_N_OCTETS 12
#define RSA_MINIMUM_N_BITS (8 * RSA_MINIMUM_N_OCTETS - 7)

struct rsa_public_key
{
    /*
     * Size of the modulo, in octets. This is also the size of all
     * signatures that are created or verified with this key.
     */
    size_t size;
    MPI n; /* Modulo */
    MPI e; /* Public exponent */
};

void rsa_public_key_init(struct rsa_public_key *key);

int rsa_public_key_prepare(struct rsa_public_key *key);

int rsa_sha256_verify(const struct rsa_public_key *key,
                      struct sha2_256_state *hash,
                      MPI signature);

#endif /* RSA_H */

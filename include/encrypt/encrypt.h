/*
 *  Copyright (C) 2023 Callum Gran
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <stdlib.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

typedef struct {
    RSA *public_key;
    RSA *private_key;
} KeyPair;

typedef struct {
    unsigned char key[32];
    unsigned char init_vect[16];
} SymmetricKey;

bool key_pair_init(KeyPair *key_pair, const char *public_key_path, const char *private_key_path);

bool key_pair_free(KeyPair *key_pair);

bool symmetric_key_init(SymmetricKey *key);

bool symmetric_key_from_bytes(SymmetricKey *key, const unsigned char *bytes);

int as_encrypt_data(RSA *public_key, const unsigned char *source, int len, unsigned char *dest);

int as_decrypt_data(RSA *private_key, const unsigned char *source, int len, unsigned char *dest);

int s_encrypt_data(SymmetricKey *key, const unsigned char *source, int len, unsigned char *dest);

int s_decrypt_data(SymmetricKey *key, const unsigned char *source, int len, unsigned char *dest);

#endif // ENCRYPT_H
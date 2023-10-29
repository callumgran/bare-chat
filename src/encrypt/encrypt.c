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

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <encrypt/encrypt.h>

bool key_pair_init(KeyPair *key_pair, const char *public_key_path, const char *private_key_path) 
{
    if (key_pair == NULL || public_key_path == NULL || private_key_path == NULL) {
        return false;
    }

    FILE *public_key_file = fopen(public_key_path, "r");
    FILE *private_key_file = fopen(private_key_path, "r");

    if (public_key_file == NULL || private_key_file == NULL) {
        return false;
    }

    // Maybe add a password argument to this function later
    key_pair->public_key = PEM_read_bio_RSA_PUBKEY(public_key_file, NULL, NULL, NULL);
    key_pair->private_key = PEM_read_bio_RSAPrivateKey(private_key_file, NULL, NULL, NULL);

    fclose(public_key_file);
    fclose(private_key_file);

    return true;
}

bool key_pair_free(KeyPair *key_pair) 
{
    if (key_pair == NULL || key_pair->public_key == NULL || key_pair->private_key == NULL) {
        return false;
    }

    RSA_free(key_pair->public_key);
    RSA_free(key_pair->private_key);

    return true;
}

bool symmetric_key_init(SymmetricKey *key) 
{
    if (key == NULL) {
        return false;
    }

    if (RAND_bytes(key->key, sizeof(key->key)) != 1) {
        return false;
    }

    if (RAND_bytes(key->init_vect, sizeof(key->init_vect)) != 1) {
        return false;
    }

    return true;
}

bool symmetric_key_from_bytes(SymmetricKey *key, const unsigned char *key_iv) 
{
    if (key == NULL || key_iv == NULL) {
        return false;
    }

    memcpy(key, key_iv, sizeof(SymmetricKey));

    return true;
}

int as_encrypt_data(RSA *public_key, const unsigned char *source, int len, unsigned char *dest) 
{
    if (public_key == NULL || source == NULL || dest == NULL) {
        return -1;
    }

    int enc_len = RSA_public_encrypt(len, source, dest, public_key, RSA_PKCS1_OAEP_PADDING);

    return enc_len;
}

int as_decrypt_data(RSA *private_key, const unsigned char *source, int len, unsigned char *dest) 
{
    if (private_key == NULL || source == NULL || dest == NULL) {
        return -1;
    }

    int dec_len = RSA_private_decrypt(len, source, dest, private_key, RSA_PKCS1_PADDING);

    return dec_len;
}

int s_encrypt_data(SymmetricKey *key, const unsigned char *source, int len, unsigned char *dest) 
{
    if (key == NULL || source == NULL || dest == NULL) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return -1;
    }

    int rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key->key, key->init_vect);

    if (rc != 1) {
        return -1;
    }

    int tmp_len = 0;
    int enc_len = 0;

    rc = EVP_EncryptUpdate(ctx, dest, &tmp_len, source, len);
    if (rc != 1) {
        return -1;
    }

    enc_len += tmp_len;

    rc = EVP_EncryptFinal_ex(ctx, dest + enc_len, &tmp_len);
    if (rc != 1) {
        return -1;
    }

    enc_len += tmp_len;

    EVP_CIPHER_CTX_free(ctx);

    return enc_len;
}

int s_decrypt_data(SymmetricKey *key, const unsigned char *source, int len, unsigned char *dest) 
{
    if (key == NULL || source == NULL || dest == NULL) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return -1;
    }

    int rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key->key, key->init_vect);

    if (rc != 1) {
        return -1;
    }

    int tmp_len = 0;
    int dec_len = 0;

    rc = EVP_DecryptUpdate(ctx, dest, &tmp_len, source, len);
    if (rc != 1) {
        return -1;
    }

    dec_len += tmp_len;

    rc = EVP_DecryptFinal_ex(ctx, dest + dec_len, &tmp_len);
    if (rc != 1) {
        return -1;
    }

    dec_len += tmp_len;

    EVP_CIPHER_CTX_free(ctx);

    return dec_len;
}

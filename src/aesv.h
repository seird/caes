#ifndef __AESV_H__
#define __AESV_H__


#include <stdint.h>
#include <string.h>
#include <immintrin.h>

#include "params.h"


/* aes block encryption */

void aesv_set_encrypt_key(__m128i RoundKeysEncrypt[ROUNDS], uint8_t user_key[BLOCKSIZE]);
void aesv_set_decrypt_key(__m128i RoundKeysDecrypt[ROUNDS], uint8_t user_key[BLOCKSIZE]);
void aesvi_encrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysEncrypt[ROUNDS]); // in place encryption
void aesvi_decrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysDecrypt[ROUNDS]); // in place encryption
__m128i aesv_encrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysEncrypt[ROUNDS]); // state remains unchanged
__m128i aesv_decrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysDecrypt[ROUNDS]); // state remains unchanged


/* aes modes */

// AES-CTR
void aesv_ctr_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
void aesv_ctr_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);

// AES-ECB
void aesv_ecb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE]);
void aesv_ecb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE]);

// AES-CFB
void aesv_cfb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
void aesv_cfb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);

// AES-OFB
void aesv_ofb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
void aesv_ofb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);

// AES-CBC
void aesv_cbc_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
void aesv_cbc_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);


#endif // __AESV_H__

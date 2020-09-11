#ifndef __AESV_H__
#define __AESV_H__


#include <stdint.h>
#include <string.h>
#include <immintrin.h>

#include "params.h"


typedef struct RoundKeys {
    __m128i * RoundKeys;
    size_t rounds;
} RoundKeys_t;


typedef enum KeySize {
    AES_128,
    AES_192,
    AES_256,
} KeySize_t;


/* aes block encryption */

void aesv_set_encrypt_key(RoundKeys_t * RoundKeysEncrypt, uint8_t * user_key, KeySize_t KeySize);
void aesv_set_decrypt_key(RoundKeys_t * RoundKeysDecrypt, uint8_t * user_key, KeySize_t KeySize);
void aesvi_encrypt(uint8_t state[BLOCKSIZE], RoundKeys_t * RoundKeysEncrypt); // in place encryption
void aesvi_decrypt(uint8_t state[BLOCKSIZE], RoundKeys_t * RoundKeysDecrypt); // in place encryption
__m128i aesv_encrypt(uint8_t state[BLOCKSIZE], RoundKeys_t * RoundKeysEncrypt); // state remains unchanged
__m128i aesv_decrypt(uint8_t state[BLOCKSIZE], RoundKeys_t * RoundKeysDecrypt); // state remains unchanged


/* aes modes */

// AES-CTR
void aesv_ctr_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aesv_ctr_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aesv_ctr_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aesv_ctr_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aesv_ctr_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aesv_ctr_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aesv_ctr_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);
void aesv_ctr_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);

// AES-ECB
void aesv_ecb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, KeySize_t KeySize);
void aesv_ecb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, KeySize_t KeySize);
void aesv_ecb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16]);
void aesv_ecb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16]);
void aesv_ecb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24]);
void aesv_ecb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24]);
void aesv_ecb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32]);
void aesv_ecb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32]);

// AES-CFB
void aesv_cfb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aesv_cfb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aesv_cfb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aesv_cfb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aesv_cfb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aesv_cfb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aesv_cfb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);
void aesv_cfb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);

// AES-OFB
void aesv_ofb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aesv_ofb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aesv_ofb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aesv_ofb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aesv_ofb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aesv_ofb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aesv_ofb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);
void aesv_ofb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);

// AES-CBC
void aesv_cbc_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aesv_cbc_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aesv_cbc_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aesv_cbc_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aesv_cbc_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aesv_cbc_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aesv_cbc_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);
void aesv_cbc_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);


#endif // __AESV_H__

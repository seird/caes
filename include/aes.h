#ifndef __AES_H__
#define __AES_H__


#include <stdint.h>
#include <stdio.h>


typedef enum KeySize {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256,
} KeySize_t;


typedef enum Mode {
    AES_CTR,
    AES_CBC,
    AES_OFB,
    AES_CFB,
    AES_ECB,
} Mode_t;


/**
 * Higher level functions
 * 
 * These functions take care of padding, key derivation and generating/storing initialization vectors
 * 
 */

/* Encrypt bytes on the heap */
void aes_encrypt(uint8_t ** data, size_t * size, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
/* Decrypt bytes on the heap */
void aes_decrypt(uint8_t ** data, size_t * size, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
/* Encrypt a file */
void aes_encrypt_file(char * filename, char * savename, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
/* Decrypt a file */
void aes_decrypt_file(char * filename, char * savename, char * passphrase, Mode_t aes_mode, KeySize_t key_size);


/**
 * Lower level functions
 * 
 * The caller is responsible for supplying data of correct size (a multiple of BLOCKSIZE bytes), initialization vectors, ...
 * 
 */

#define BLOCKSIZE 16

/* aes modes */

// AES-CTR
void aes_ctr_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_ctr_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_ctr_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aes_ctr_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aes_ctr_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aes_ctr_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aes_ctr_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);
void aes_ctr_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);

// AES-ECB
void aes_ecb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_ecb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_ecb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16]);
void aes_ecb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16]);
void aes_ecb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24]);
void aes_ecb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24]);
void aes_ecb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32]);
void aes_ecb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32]);

// AES-CFB
void aes_cfb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_cfb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_cfb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aes_cfb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aes_cfb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aes_cfb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aes_cfb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);
void aes_cfb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);

// AES-OFB
void aes_ofb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_ofb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_ofb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aes_ofb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aes_ofb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aes_ofb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aes_ofb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);
void aes_ofb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);

// AES-CBC
void aes_cbc_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_cbc_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
void aes_cbc_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aes_cbc_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE]);
void aes_cbc_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aes_cbc_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE]);
void aes_cbc_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);
void aes_cbc_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE]);


/* aes block encryption */

#include <immintrin.h>

typedef struct RoundKeys {
    __m128i * RoundKeys;
    size_t rounds;
} RoundKeys_t;


void aes_set_encrypt_key(RoundKeys_t * RoundKeysEncrypt, uint8_t * user_key, KeySize_t KeySize);
void aes_set_decrypt_key(RoundKeys_t * RoundKeysDecrypt, uint8_t * user_key, KeySize_t KeySize);
void aesi_block_encrypt(uint8_t state[BLOCKSIZE], RoundKeys_t * RoundKeysEncrypt); // in place encryption
void aesi_block_decrypt(uint8_t state[BLOCKSIZE], RoundKeys_t * RoundKeysDecrypt); // in place encryption
__m128i aes_block_encrypt(uint8_t state[BLOCKSIZE], RoundKeys_t * RoundKeysEncrypt); // state remains unchanged
__m128i aes_block_decrypt(uint8_t state[BLOCKSIZE], RoundKeys_t * RoundKeysDecrypt); // state remains unchanged


#endif // __AES_H__

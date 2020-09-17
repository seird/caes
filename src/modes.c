#include "aes.h"
#include "utils.h"


/* AES-CTR */

static void
aes_ctr(uint8_t * data, size_t blocks, struct RoundKeys * RoundKeysEncrypt, uint8_t IV[BLOCKSIZE])
{    
    for (size_t b=0; b<blocks; ++b) {
        // Encrypt IV
        __m128i vIV_aes = aes_block_encrypt(IV, RoundKeysEncrypt);

        // data XOR (Encrypted IV)
        __m128i v_ciphertext = _mm_xor_si128(vIV_aes, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), v_ciphertext);

        // Increment IV
        IV_increment(IV);
    }
}


void
aes_ctr_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);
    aes_ctr(data, blocks, &RoundKeysEncrypt, IV);
    free(RoundKeysEncrypt.RoundKeys);
}


void
aes_ctr_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    // AES-CTR decrypt is the same as encryption
    aes_ctr_encrypt(data, blocks, user_key, IV, KeySize);
}


void
aes_ctr_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE])
{
    aes_ctr_encrypt(data, blocks, user_key, IV, AES_128);
}


void
aes_ctr_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE])
{
    aes_ctr_decrypt(data, blocks, user_key, IV, AES_128);
}


void
aes_ctr_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE])
{
    aes_ctr_encrypt(data, blocks, user_key, IV, AES_192);
}


void
aes_ctr_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE])
{
    aes_ctr_decrypt(data, blocks, user_key, IV, AES_192);
}


void
aes_ctr_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE])
{
    aes_ctr_encrypt(data, blocks, user_key, IV, AES_256);
}


void
aes_ctr_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE])
{
    aes_ctr_decrypt(data, blocks, user_key, IV, AES_256);
}


/* AES-ECB */

void
aes_ecb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    (void) IV;
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);
    
    for (size_t b=0; b<blocks; ++b) {
        aesi_block_encrypt(data + b*BLOCKSIZE, &RoundKeysEncrypt); // encrypt in place
    }

    free(RoundKeysEncrypt.RoundKeys);
}


void
aes_ecb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    (void) IV;
    struct RoundKeys RoundKeysDecrypt;
    aes_set_decrypt_key(&RoundKeysDecrypt, user_key, KeySize);

    for (size_t b=0; b<blocks; ++b) {
        aesi_block_decrypt(data + b*BLOCKSIZE, &RoundKeysDecrypt); // decrypt in place
    }

    free(RoundKeysDecrypt.RoundKeys);
}


void
aes_ecb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16])
{
    aes_ecb_encrypt(data, blocks, user_key, NULL, AES_128);
}


void
aes_ecb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16])
{
    aes_ecb_decrypt(data, blocks, user_key, NULL, AES_128);
}


void
aes_ecb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24])
{
    aes_ecb_encrypt(data, blocks, user_key, NULL, AES_192);
}


void
aes_ecb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24])
{
    aes_ecb_decrypt(data, blocks, user_key, NULL, AES_192);
}


void
aes_ecb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32])
{
    aes_ecb_encrypt(data, blocks, user_key, NULL, AES_256);
}


void
aes_ecb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32])
{
    aes_ecb_decrypt(data, blocks, user_key, NULL, AES_256);
}


/* AES-CFB */

void
aes_cfb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);

    uint8_t * block_in = IV;
    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aes_block_encrypt(block_in, &RoundKeysEncrypt);

        // ciphertext = plaintext XOR block_out
        __m128i ciphertext = _mm_xor_si128(block_out, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), ciphertext);

        // Next iteration input
        block_in = data + b*BLOCKSIZE;
    }

    free(RoundKeysEncrypt.RoundKeys);
}


void
aes_cfb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);

    uint8_t block_in[BLOCKSIZE];
    memcpy(block_in, IV, BLOCKSIZE);

    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aes_block_encrypt(block_in, &RoundKeysEncrypt);

        // plaintext = ciphertext XOR block_out
        __m128i plaintext = _mm_xor_si128(block_out, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Next iteration input
        memcpy(block_in, data + b*BLOCKSIZE, BLOCKSIZE);
        
        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), plaintext);
    }

    free(RoundKeysEncrypt.RoundKeys);
}


void
aes_cfb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE])
{
    aes_cfb_encrypt(data, blocks, user_key, IV, AES_128);
}


void
aes_cfb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE])
{
    aes_cfb_decrypt(data, blocks, user_key, IV, AES_128);
}


void
aes_cfb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE])
{
    aes_cfb_encrypt(data, blocks, user_key, IV, AES_192);
}


void
aes_cfb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE])
{
    aes_cfb_decrypt(data, blocks, user_key, IV, AES_192);
}


void
aes_cfb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE])
{
    aes_cfb_encrypt(data, blocks, user_key, IV, AES_256);
}


void
aes_cfb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE])
{
    aes_cfb_decrypt(data, blocks, user_key, IV, AES_256);
}


/* AES-OFB */

void
aes_ofb_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);

    uint8_t block_in[BLOCKSIZE];
    memcpy(block_in, IV, BLOCKSIZE);

    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aes_block_encrypt(block_in, &RoundKeysEncrypt);

        // ciphertext = plaintext XOR block_out
        __m128i ciphertext = _mm_xor_si128(block_out, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), ciphertext);

        // Next iteration input
        _mm_storeu_si128((__m128i *)block_in, block_out);
    }

    free(RoundKeysEncrypt.RoundKeys);
}


void
aes_ofb_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);

    uint8_t block_in[BLOCKSIZE];
    memcpy(block_in, IV, BLOCKSIZE);

    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aes_block_encrypt(block_in, &RoundKeysEncrypt);

        // plaintext = ciphertext XOR block_out
        __m128i plaintext = _mm_xor_si128(block_out, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), plaintext);

        // Next iteration input
        _mm_storeu_si128((__m128i *)block_in, block_out);
    }

    free(RoundKeysEncrypt.RoundKeys);
}


void
aes_ofb_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE])
{
    aes_ofb_encrypt(data, blocks, user_key, IV, AES_128);
}


void
aes_ofb_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE])
{
    aes_ofb_decrypt(data, blocks, user_key, IV, AES_128);
}


void
aes_ofb_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE])
{
    aes_ofb_encrypt(data, blocks, user_key, IV, AES_192);
}


void
aes_ofb_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE])
{
    aes_ofb_decrypt(data, blocks, user_key, IV, AES_192);
}


void
aes_ofb_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE])
{
    aes_ofb_encrypt(data, blocks, user_key, IV, AES_256);
}


void
aes_ofb_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE])
{
    aes_ofb_decrypt(data, blocks, user_key, IV, AES_256);
}


/* AES-CBC */

void
aes_cbc_encrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);

    __m128i xor_in = _mm_loadu_si128((__m128i *)IV);
    uint8_t block_in_bytes[BLOCKSIZE];

    // TODO: aes_block_encrypt that takes __m128i
    for (size_t b=0; b<blocks; ++b) {
        // block_in = xor_in XOR block_out
        __m128i block_in = _mm_xor_si128(xor_in, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));
        _mm_storeu_si128((__m128i *)block_in_bytes, block_in);

        __m128i block_out = aes_block_encrypt(block_in_bytes, &RoundKeysEncrypt);

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), block_out);

        // Next iteration xor_input
        xor_in = block_out;
    }

    free(RoundKeysEncrypt.RoundKeys);
}


void
aes_cbc_decrypt(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize)
{
    struct RoundKeys RoundKeysDecrypt;
    aes_set_decrypt_key(&RoundKeysDecrypt, user_key, KeySize);

    __m128i xor_in = _mm_loadu_si128((__m128i *)IV);

    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aes_block_decrypt(data + b*BLOCKSIZE, &RoundKeysDecrypt);

        // plaintext = xor_in XOR block_out
        __m128i plaintext = _mm_xor_si128(block_out, xor_in);

        // Next iteration input
        xor_in = _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), plaintext);
    }

    free(RoundKeysDecrypt.RoundKeys);
}


void
aes_cbc_128_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE])
{
    aes_cbc_encrypt(data, blocks, user_key, IV, AES_128);
}


void
aes_cbc_128_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[16], uint8_t IV[BLOCKSIZE])
{
    aes_cbc_decrypt(data, blocks, user_key, IV, AES_128);
}


void
aes_cbc_192_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE])
{
    aes_cbc_encrypt(data, blocks, user_key, IV, AES_192);
}


void
aes_cbc_192_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[24], uint8_t IV[BLOCKSIZE])
{
    aes_cbc_decrypt(data, blocks, user_key, IV, AES_192);
}


void
aes_cbc_256_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE])
{
    aes_cbc_encrypt(data, blocks, user_key, IV, AES_256);
}


void
aes_cbc_256_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[32], uint8_t IV[BLOCKSIZE])
{
    aes_cbc_decrypt(data, blocks, user_key, IV, AES_256);
}

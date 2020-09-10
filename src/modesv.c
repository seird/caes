#include "aesv.h"
#include "utils.h"


/* AES-CTR */

static void
aesv_ctr(uint8_t * data, size_t blocks, __m128i RoundKeys[ROUNDS], uint8_t IV[BLOCKSIZE])
{    
    for (size_t b=0; b<blocks; ++b) {
        // Encrypt IV
        __m128i vIV_aes = aesv_encrypt(IV, RoundKeys);

        // data XOR (Encrypted IV)
        __m128i v_ciphertext = _mm_xor_si128(vIV_aes, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), v_ciphertext);

        // Increment IV
        IV_increment(IV);
    }
}


void
aesv_ctr_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE])
{
    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, user_key);
    aesv_ctr(data, blocks, RoundKeysEncrypt, IV);
}


void
aesv_ctr_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE])
{
    // AES-CTR decrypt is the same as encryption
    aesv_ctr_encrypt(data, blocks, user_key, IV);
}


/* AES-ECB */

void
aesv_ecb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE])
{
    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, user_key);
    
    for (size_t b=0; b<blocks; ++b) {
        aesvi_encrypt(data + b*BLOCKSIZE, RoundKeysEncrypt); // encrypt in place
    }
}


void
aesv_ecb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE])
{
    __m128i RoundKeysDecrypt[ROUNDS];
    aesv_set_decrypt_key(RoundKeysDecrypt, user_key);

    for (size_t b=0; b<blocks; ++b) {
        aesvi_decrypt(data + b*BLOCKSIZE, RoundKeysDecrypt); // decrypt in place
    }
}


/* AES-CFB */

void
aesv_cfb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE])
{
    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, user_key);

    uint8_t * block_in = IV;
    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aesv_encrypt(block_in, RoundKeysEncrypt);

        // ciphertext = plaintext XOR block_out
        __m128i ciphertext = _mm_xor_si128(block_out, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), ciphertext);

        // Next iteration input
        block_in = data + b*BLOCKSIZE;
    }
}


void
aesv_cfb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE])
{
    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, user_key);

    uint8_t block_in[BLOCKSIZE];
    memcpy(block_in, IV, BLOCKSIZE);

    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aesv_encrypt(block_in, RoundKeysEncrypt);

        // plaintext = ciphertext XOR block_out
        __m128i plaintext = _mm_xor_si128(block_out, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Next iteration input
        memcpy(block_in, data + b*BLOCKSIZE, BLOCKSIZE);
        
        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), plaintext);
    }
}


/* AES-OFB */

void
aesv_ofb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE])
{
    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, user_key);

    uint8_t block_in[BLOCKSIZE];
    memcpy(block_in, IV, BLOCKSIZE);

    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aesv_encrypt(block_in, RoundKeysEncrypt);

        // ciphertext = plaintext XOR block_out
        __m128i ciphertext = _mm_xor_si128(block_out, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), ciphertext);

        // Next iteration input
        _mm_storeu_si128((__m128i *)block_in, block_out);
    }
}


void
aesv_ofb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE])
{
    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, user_key);

    uint8_t block_in[BLOCKSIZE];
    memcpy(block_in, IV, BLOCKSIZE);

    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aesv_encrypt(block_in, RoundKeysEncrypt);

        // plaintext = ciphertext XOR block_out
        __m128i plaintext = _mm_xor_si128(block_out, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), plaintext);

        // Next iteration input
        _mm_storeu_si128((__m128i *)block_in, block_out);
    }
}


/* AES-CBC */

void
aesv_cbc_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE])
{
    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, user_key);

    __m128i xor_in = _mm_loadu_si128((__m128i *)IV);
    uint8_t block_in_bytes[BLOCKSIZE];

    // TODO: aesv_encrypt that takes __m128i
    for (size_t b=0; b<blocks; ++b) {
        // block_in = xor_in XOR block_out
        __m128i block_in = _mm_xor_si128(xor_in, _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE)));
        _mm_storeu_si128((__m128i *)block_in_bytes, block_in);

        __m128i block_out = aesv_encrypt(block_in_bytes, RoundKeysEncrypt);

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), block_out);

        // Next iteration xor_input
        xor_in = block_out;
    }
}


void
aesv_cbc_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE])
{
    __m128i RoundKeysDecrypt[ROUNDS];
    aesv_set_decrypt_key(RoundKeysDecrypt, user_key);

    __m128i xor_in = _mm_loadu_si128((__m128i *)IV);

    for (size_t b=0; b<blocks; ++b) {
        __m128i block_out = aesv_decrypt(data + b*BLOCKSIZE, RoundKeysDecrypt);

        // plaintext = xor_in XOR block_out
        __m128i plaintext = _mm_xor_si128(block_out, xor_in);

        // Next iteration input
        xor_in = _mm_loadu_si128((__m128i *)(data + b*BLOCKSIZE));

        // Store the result
        _mm_storeu_si128((__m128i *)(data + b*BLOCKSIZE), plaintext);
    }
}

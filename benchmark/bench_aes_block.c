#include "benchmarks.h"

#include "../src/aes.h"
#include "../src/aesv.h"


#define BLOCKS 1e6


BENCH_FUNC(bench_aes_block_encrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t RoundKeysEncrypt[EXPANDEDSIZE];

    aes_set_encrypt_key(RoundKeysEncrypt, key);

    for (size_t b=0; b<BLOCKS; ++b) {
        aes_encrypt(data, RoundKeysEncrypt);
    }
}


BENCH_FUNC(bench_aes_block_decrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t RoundKeysDecrypt[EXPANDEDSIZE];

    aes_set_decrypt_key(RoundKeysDecrypt, key);

    for (size_t b=0; b<BLOCKS; ++b) {
        aes_decrypt(data, RoundKeysDecrypt);
    }   
}


BENCH_FUNC(bench_aesvi_intrinsic_block_encrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    __m128i RoundKeysEncrypt[ROUNDS];

    aesv_set_encrypt_key(RoundKeysEncrypt, key);

    for (size_t b=0; b<BLOCKS; ++b) {
        aesvi_encrypt(data, RoundKeysEncrypt);
    }
}


BENCH_FUNC(bench_aesvi_intrinsic_block_decrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    __m128i RoundKeysDecrypt[ROUNDS];

    aesv_set_decrypt_key(RoundKeysDecrypt, key);

    for (size_t b=0; b<BLOCKS; ++b) {
        aesvi_decrypt(data, RoundKeysDecrypt);
    }
}

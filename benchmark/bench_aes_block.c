#include "benchmarks.h"

#include "../src/aes.h"
#include "../src/aesv.h"


#define BLOCKS 1e6


BENCH_FUNC(bench_aes_block_encrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t RoundKeysEncrypt[EXPANDEDSIZE];

    aes_set_encrypt_key(RoundKeysEncrypt, key);

    for (size_t b=0; b<BLOCKS; ++b) {
        aes_encrypt(data, RoundKeysEncrypt);
    }
}


BENCH_FUNC(bench_aes_block_decrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t RoundKeysDecrypt[EXPANDEDSIZE];

    aes_set_decrypt_key(RoundKeysDecrypt, key);

    for (size_t b=0; b<BLOCKS; ++b) {
        aes_decrypt(data, RoundKeysDecrypt);
    }   
}


BENCH_FUNC(bench_aesvi_intrinsic_block_128_encrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    RoundKeys_t RoundKeysEncrypt;

    aesv_set_encrypt_key(&RoundKeysEncrypt, key, AES_128);

    for (size_t b=0; b<BLOCKS; ++b) {
        aesvi_encrypt(data, &RoundKeysEncrypt);
    }
}


BENCH_FUNC(bench_aesvi_intrinsic_block_128_decrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    RoundKeys_t RoundKeysDecrypt;

    aesv_set_decrypt_key(&RoundKeysDecrypt, key, AES_128);

    for (size_t b=0; b<BLOCKS; ++b) {
        aesvi_decrypt(data, &RoundKeysDecrypt);
    }
}


BENCH_FUNC(bench_aesvi_intrinsic_block_192_encrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";

    RoundKeys_t RoundKeysEncrypt;

    aesv_set_encrypt_key(&RoundKeysEncrypt, key, AES_192);

    for (size_t b=0; b<BLOCKS; ++b) {
        aesvi_encrypt(data, &RoundKeysEncrypt);
    }
}


BENCH_FUNC(bench_aesvi_intrinsic_block_192_decrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";

    RoundKeys_t RoundKeysDecrypt;

    aesv_set_decrypt_key(&RoundKeysDecrypt, key, AES_192);

    for (size_t b=0; b<BLOCKS; ++b) {
        aesvi_decrypt(data, &RoundKeysDecrypt);
    }
}


BENCH_FUNC(bench_aesvi_intrinsic_block_256_encrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";

    RoundKeys_t RoundKeysEncrypt;

    aesv_set_encrypt_key(&RoundKeysEncrypt, key, AES_256);

    for (size_t b=0; b<BLOCKS; ++b) {
        aesvi_encrypt(data, &RoundKeysEncrypt);
    }
}


BENCH_FUNC(bench_aesvi_intrinsic_block_256_decrypt)
{
    uint8_t data[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF";
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";

    RoundKeys_t RoundKeysDecrypt;

    aesv_set_decrypt_key(&RoundKeysDecrypt, key, AES_256);

    for (size_t b=0; b<BLOCKS; ++b) {
        aesvi_decrypt(data, &RoundKeysDecrypt);
    }
}

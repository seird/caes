#include "benchmarks.h"
#include "../src/aes.h"


BENCH_FUNC(bench_aes_ctr_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ctr_128_encrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_ctr_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ctr_128_decrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_cfb_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_cfb_128_encrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_cfb_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_cfb_128_decrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_ofb_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ofb_128_encrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_ofb_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ofb_128_decrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_ecb_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ecb_128_encrypt(data, blocks, key);
}


BENCH_FUNC(bench_aes_ecb_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ecb_128_decrypt(data, blocks, key);
}


BENCH_FUNC(bench_aes_cbc_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_cbc_128_encrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_cbc_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_cbc_128_decrypt(data, blocks, key, IV);
}

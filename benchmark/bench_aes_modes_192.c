#include "benchmarks.h"
#include "../src/aes.h"


BENCH_FUNC(bench_aes_ctr_192_encrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ctr_192_encrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_ctr_192_decrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ctr_192_decrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_cfb_192_encrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_cfb_192_encrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_cfb_192_decrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_cfb_192_decrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_ofb_192_encrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ofb_192_encrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_ofb_192_decrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ofb_192_decrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_ecb_192_encrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ecb_192_encrypt(data, blocks, key);
}


BENCH_FUNC(bench_aes_ecb_192_decrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_ecb_192_decrypt(data, blocks, key);
}


BENCH_FUNC(bench_aes_cbc_192_encrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_cbc_192_encrypt(data, blocks, key, IV);
}


BENCH_FUNC(bench_aes_cbc_192_decrypt)
{
    uint8_t key[] = "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
                    "\x62\xf8\xea\xd2\x52\x2c\x6b\x7b";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    size_t blocks = (size_t) DATASIZE / BLOCKSIZE;
    
    aes_cbc_192_decrypt(data, blocks, key, IV);
}

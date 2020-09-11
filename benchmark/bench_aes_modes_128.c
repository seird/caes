#include "benchmarks.h"

#include "../src/aes.h"
#include "../src/aesv.h"


static void
read_file_bytes(uint8_t ** data, size_t * bytes_read)
{
    // Read data from file
    FILE * fptr = fopen("file_bench", "rb");

    fseek(fptr, 0, SEEK_END);
    long num_bytes = ftell(fptr);
    rewind(fptr);         
    *data = (uint8_t *) malloc(sizeof(uint8_t)*num_bytes);
    fread(*data, num_bytes, 1, fptr);
    fclose(fptr);

    *bytes_read = num_bytes;
}


BENCH_FUNC(bench_aes_ctr_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_ctr_128_encrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_ctr_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_ctr_128_decrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_cfb_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_cfb_128_encrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_cfb_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_cfb_128_decrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_ofb_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_ofb_128_encrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_ofb_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_ofb_128_decrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_ecb_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_ecb_128_encrypt(data, blocks, key);

    free(data);
}


BENCH_FUNC(bench_aes_ecb_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_ecb_128_decrypt(data, blocks, key);

    free(data);
}


BENCH_FUNC(bench_aes_cbc_128_encrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_cbc_128_encrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_cbc_128_decrypt)
{
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aesv_cbc_128_decrypt(data, blocks, key, IV);

    free(data);
}

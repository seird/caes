#include "benchmarks.h"
#include "../src/aes.h"


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


BENCH_FUNC(bench_aes_ctr_256_encrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_ctr_256_encrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_ctr_256_decrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_ctr_256_decrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_cfb_256_encrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_cfb_256_encrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_cfb_256_decrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_cfb_256_decrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_ofb_256_encrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_ofb_256_encrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_ofb_256_decrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_ofb_256_decrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_ecb_256_encrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_ecb_256_encrypt(data, blocks, key);

    free(data);
}


BENCH_FUNC(bench_aes_ecb_256_decrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_ecb_256_decrypt(data, blocks, key);

    free(data);
}


BENCH_FUNC(bench_aes_cbc_256_encrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_cbc_256_encrypt(data, blocks, key, IV);

    free(data);
}


BENCH_FUNC(bench_aes_cbc_256_decrypt)
{
    uint8_t key[] = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
                    "\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4";
    uint8_t IV[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    
    uint8_t * data = NULL;
    size_t bytes_read;
    read_file_bytes(&data, &bytes_read);
    size_t blocks = (size_t) bytes_read / BLOCKSIZE;
    
    aes_cbc_256_decrypt(data, blocks, key, IV);

    free(data);
}

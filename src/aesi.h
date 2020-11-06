#ifndef __AESI_H__
#define __AESI_H__


#include <string.h>

#include "aes.h"
#include "argon2/argon2.h"


#define SALTSIZE 32
#define BLOCKS_PER_ITERATION 10000000 // BLOCKS_PER_ITERATION * BLOCKSIZE bytes are allocated on the heap

#if ((_FILE_OFFSET_BITS == 64) && (defined(_WIN64) || defined(_WIN32)))
#define fopen fopen64
#define fseek fseeko64
#define ftell ftello64
#endif

typedef uint8_t * Salt_t;


typedef void (* encrypt_fptr_t)(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);
typedef void (* decrypt_fptr_t)(uint8_t * data, size_t blocks, uint8_t * user_key, uint8_t IV[BLOCKSIZE], KeySize_t KeySize);



#endif // __AESI_H__

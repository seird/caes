#include <stdint.h>

#include "aes.h"
#include "argon2/argon2.h"


#define IV_increment(IV) {\
    for (int i = BLOCKSIZE-1; i >= 0; --i) { \
        if (IV[i] == 0xff) { \
            IV[i] = 0; \
            continue; \
        } \
        IV[i] += 1; \
        break; \
    } \
}


static inline void
derive_key_iv(char * passphrase, KeySize_t key_size, Salt_t salt, size_t salt_size, uint8_t * user_key, uint8_t * IV) {
    int HASHLEN = key_size + BLOCKSIZE; // key + IV
    uint8_t hash1[HASHLEN];

    uint32_t t_cost = 2;            // 1-pass computation
    uint32_t m_cost = (1<<16);      // 64 mebibytes memory usage
    uint32_t parallelism = 1;       // number of threads and lanes

    uint8_t * pwd = (uint8_t *) strdup(passphrase);
    uint32_t pwd_size = strlen((char *) pwd);
    argon2i_hash_raw(t_cost, m_cost, parallelism, pwd, pwd_size, salt, salt_size, hash1, HASHLEN);

    memcpy(user_key, hash1, key_size);
    memcpy(IV, hash1+key_size, BLOCKSIZE);
    free(pwd);
}


static inline void
random_bytes(uint8_t * data, size_t size)
{
    for (size_t i=0; i<size; ++i) {
        data[i] = rand() % 256;
    }
}


static inline void
open_file(char * filename, FILE ** fptr, size_t * file_size)
{
    // Read data from file
#if (_FILE_OFFSET_BITS == 64)
    *fptr = fopen64(filename, "rb");
    fseeko64(*fptr, 0, SEEK_END);
    *file_size = (size_t) ftello64(*fptr);
#else
    *fptr = fopen(filename, "rb");
    fseek(*fptr, 0, SEEK_END);
    *file_size = (size_t) ftell(*fptr);
#endif

    rewind(*fptr);
}

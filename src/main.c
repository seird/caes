#include <stdio.h>
#include "aes.h"
#include "aesv.h"


#if (!defined(TEST) && !defined(SHARED) && !defined(BENCHMARK))
int
main(void)
{
    // Test vectors
    uint8_t key[BLOCKSIZE] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    uint8_t plaintext[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    uint8_t ciphertext[BLOCKSIZE] = "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a";

    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, key);

    // Encrypt
    aesvi_encrypt(plaintext, RoundKeysEncrypt);

    printf("encrypted %s ciphertext\n", (memcmp(plaintext, ciphertext, BLOCKSIZE) == 0) ? "==" : "!=");
}
#endif

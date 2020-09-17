#include "tests.h"
#include "../src/aes.h"


MU_TEST(test_aes_block)
{
    // Test vectors
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t plaintext[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    uint8_t ciphertext[BLOCKSIZE] = "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a";
    
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, key, 11);

    struct RoundKeys RoundKeysDecrypt;
    aes_set_decrypt_key(&RoundKeysDecrypt, key, 11);

    uint8_t d[BLOCKSIZE];

    // Encrypt
    memcpy(d, plaintext, BLOCKSIZE);
    aesi_block_encrypt(d, &RoundKeysEncrypt);
    MU_CHECK(memcmp(d, ciphertext, BLOCKSIZE) == 0);

    // Decrypt
    memcpy(d, ciphertext, BLOCKSIZE);
    aesi_block_decrypt(d, &RoundKeysDecrypt);
    MU_CHECK(memcmp(d, plaintext, BLOCKSIZE) == 0);    
}

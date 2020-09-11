#include "tests.h"
#include "../src/aes.h"



MU_TEST(test_aes_SubBytes)
{
    uint8_t bytes[256];
    uint8_t original_bytes[256];
    for (int i=0; i<256; ++i) {
        bytes[i] = (uint8_t) i;
    }
    memcpy(original_bytes, bytes, 256);

    for (int i=0; i<256; i+=BLOCKSIZE) {
        SubBytes(&bytes[i]);
    }

    MU_CHECK(memcmp(bytes, original_bytes, 256) != 0);

    for (int i=0; i<256; i+=BLOCKSIZE) {
        InvSubBytes(&bytes[i]);
    }

    MU_CHECK(memcmp(bytes, original_bytes, 256) == 0);
}


MU_TEST(test_aes_ShiftRows)
{
    uint8_t state_original[BLOCKSIZE] = {0x01, 0x10, 0x03, 0x30, 0x05, 0x50, 0x07, 0x70,
                                         0x09, 0x90, 0x0b, 0xb0, 0x0d, 0xd0, 0x0f, 0xf0};

    uint8_t state[BLOCKSIZE] = {0x01, 0x10, 0x03, 0x30, 0x05, 0x50, 0x07, 0x70,
                                0x09, 0x90, 0x0b, 0xb0, 0x0d, 0xd0, 0x0f, 0xf0};

    ShiftRows(state);
    MU_CHECK(memcmp(state_original, state, BLOCKSIZE) != 0);

    InvShiftRows(state);
    MU_CHECK(memcmp(state_original, state, BLOCKSIZE) == 0);
}


MU_TEST(test_aes_MixColumns)
{
    uint8_t state_original[BLOCKSIZE] = {0x01, 0x10, 0x03, 0x30, 0x05, 0x50, 0x07, 0x70,
                                         0x09, 0x90, 0x0b, 0xb0, 0x0d, 0xd0, 0x0f, 0xf0};

    uint8_t state[BLOCKSIZE] = {0x01, 0x10, 0x03, 0x30, 0x05, 0x50, 0x07, 0x70,
                                0x09, 0x90, 0x0b, 0xb0, 0x0d, 0xd0, 0x0f, 0xf0};

    MixColumns(state);
    MU_CHECK(memcmp(state_original, state, BLOCKSIZE) != 0);

    InvMixColumns(state);
    MU_CHECK(memcmp(state_original, state, BLOCKSIZE) == 0);
}


MU_TEST(test_aes_block)
{
    // Test vectors
    uint8_t key[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    uint8_t plaintext[BLOCKSIZE] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    uint8_t ciphertext[BLOCKSIZE] = "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a";

    uint8_t RoundKeys[EXPANDEDSIZE];
    KeyExpansion(RoundKeys, key);

    uint8_t d[BLOCKSIZE];    

    // Encrypt
    memcpy(d, plaintext, BLOCKSIZE);
    aes_encrypt(d, RoundKeys);
    MU_CHECK(memcmp(d, ciphertext, BLOCKSIZE) == 0);

    // Decrypt
    memcpy(d, ciphertext, BLOCKSIZE);
    aes_decrypt(d, RoundKeys);
    MU_CHECK(memcmp(d, plaintext, BLOCKSIZE) == 0);    
}

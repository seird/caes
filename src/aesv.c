#include "aesv.h"


static __m128i
aes_128_key_expansion(__m128i key, __m128i keygened)
{
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}


void
aesv_set_encrypt_key(__m128i RoundKeysEncrypt[ROUNDS], uint8_t user_key[BLOCKSIZE])
{
    RoundKeysEncrypt[0] = _mm_loadu_si128((__m128i *)user_key);

    // 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    RoundKeysEncrypt[1]  = aes_128_key_expansion(RoundKeysEncrypt[0], _mm_aeskeygenassist_si128(RoundKeysEncrypt[0], 0x01));
    RoundKeysEncrypt[2]  = aes_128_key_expansion(RoundKeysEncrypt[1], _mm_aeskeygenassist_si128(RoundKeysEncrypt[1], 0x02));
    RoundKeysEncrypt[3]  = aes_128_key_expansion(RoundKeysEncrypt[2], _mm_aeskeygenassist_si128(RoundKeysEncrypt[2], 0x04));
    RoundKeysEncrypt[4]  = aes_128_key_expansion(RoundKeysEncrypt[3], _mm_aeskeygenassist_si128(RoundKeysEncrypt[3], 0x08));
    RoundKeysEncrypt[5]  = aes_128_key_expansion(RoundKeysEncrypt[4], _mm_aeskeygenassist_si128(RoundKeysEncrypt[4], 0x10));
    RoundKeysEncrypt[6]  = aes_128_key_expansion(RoundKeysEncrypt[5], _mm_aeskeygenassist_si128(RoundKeysEncrypt[5], 0x20));
    RoundKeysEncrypt[7]  = aes_128_key_expansion(RoundKeysEncrypt[6], _mm_aeskeygenassist_si128(RoundKeysEncrypt[6], 0x40));
    RoundKeysEncrypt[8]  = aes_128_key_expansion(RoundKeysEncrypt[7], _mm_aeskeygenassist_si128(RoundKeysEncrypt[7], 0x80));
    RoundKeysEncrypt[9]  = aes_128_key_expansion(RoundKeysEncrypt[8], _mm_aeskeygenassist_si128(RoundKeysEncrypt[8], 0x1b));
    RoundKeysEncrypt[10] = aes_128_key_expansion(RoundKeysEncrypt[9], _mm_aeskeygenassist_si128(RoundKeysEncrypt[9], 0x36));
}


void
aesv_set_decrypt_key(__m128i RoundKeysDecrypt[ROUNDS], uint8_t user_key[BLOCKSIZE])
{
    __m128i RoundKeysEncrypt[ROUNDS];
    aesv_set_encrypt_key(RoundKeysEncrypt, user_key);

    RoundKeysDecrypt[0] = RoundKeysEncrypt[ROUNDS-1];
    for (int i=1; i<ROUNDS-1; ++i) {
        RoundKeysDecrypt[i] = _mm_aesimc_si128(RoundKeysEncrypt[ROUNDS-i-1]);
    }
    RoundKeysDecrypt[ROUNDS-1] = RoundKeysEncrypt[0];
}


void
aesvi_encrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysEncrypt[ROUNDS])
{
    __m128i vstate = _mm_loadu_si128((__m128i *)state);

    // Initial round
    vstate = _mm_xor_si128(vstate, RoundKeysEncrypt[0]);

    // Main rounds
    for (int i=1; i<ROUNDS-1; ++i) {
        vstate = _mm_aesenc_si128(vstate, RoundKeysEncrypt[i]);
    }

    // Final round
    vstate = _mm_aesenclast_si128(vstate, RoundKeysEncrypt[ROUNDS-1]);

    // Store the result
    _mm_storeu_si128((__m128i *)state, vstate);
}


void
aesvi_decrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysDecrypt[ROUNDS])
{
    __m128i vstate = _mm_loadu_si128((__m128i *)state);

    // Initial round
    vstate = _mm_xor_si128(vstate, RoundKeysDecrypt[0]);

    // Main rounds
    for (int i=1; i<ROUNDS-1; ++i) {
        vstate = _mm_aesdec_si128(vstate, RoundKeysDecrypt[i]);
    }

    // Final round
    vstate = _mm_aesdeclast_si128(vstate, RoundKeysDecrypt[ROUNDS-1]);

    // Store the result
    _mm_storeu_si128((__m128i *)state, vstate);
}


__m128i
aesv_encrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysEncrypt[ROUNDS])
{
    __m128i vstate = _mm_loadu_si128((__m128i *)state);

    // Initial round
    vstate = _mm_xor_si128(vstate, RoundKeysEncrypt[0]);

    // Main rounds
    for (int i=1; i<ROUNDS-1; ++i) {
        vstate = _mm_aesenc_si128(vstate, RoundKeysEncrypt[i]);
    }

    // Final round
    vstate = _mm_aesenclast_si128(vstate, RoundKeysEncrypt[ROUNDS-1]);

    // Return the result
    return vstate;
}


__m128i
aesv_decrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysDecrypt[ROUNDS])
{
    __m128i vstate = _mm_loadu_si128((__m128i *)state);

    // Initial round
    vstate = _mm_xor_si128(vstate, RoundKeysDecrypt[0]);

    // Main rounds
    for (int i=1; i<ROUNDS-1; ++i) {
        vstate = _mm_aesdec_si128(vstate, RoundKeysDecrypt[i]);
    }

    // Final round
    vstate = _mm_aesdeclast_si128(vstate, RoundKeysDecrypt[ROUNDS-1]);

    // Return the result
    return vstate;
}

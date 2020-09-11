#include "aesv.h"


static __m128i
AES_128_ASSIST(__m128i temp1, __m128i temp2)
{
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2 ,0xff);
    temp3 = _mm_slli_si128(temp1, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp3 = _mm_slli_si128(temp3, 0x4);
    temp1 = _mm_xor_si128(temp1, temp3);
    temp1 = _mm_xor_si128(temp1, temp2);
    return temp1;
}


static void
KEY_192_ASSIST(__m128i * temp1, __m128i * temp2, __m128i * temp3)
{
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0x55);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
    *temp2 = _mm_shuffle_epi32(*temp1, 0xff);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, *temp2);
}


static void
KEY_256_ASSIST_1(__m128i * temp1, __m128i * temp2)
{
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}


static void
KEY_256_ASSIST_2(__m128i * temp1, __m128i * temp3)
{
    __m128i temp2,temp4;
    temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);
}


void
aesv_set_encrypt_key(struct RoundKeys * RoundKeysEncrypt, uint8_t * user_key, KeySize_t KeySize)
{
    int rounds;
    switch (KeySize) {
        case AES_128: {
            aes_128:
            rounds = 11;
            RoundKeysEncrypt->rounds = rounds;
            RoundKeysEncrypt->RoundKeys = malloc(sizeof(__m128i) * rounds);
            RoundKeysEncrypt->RoundKeys[0] = _mm_loadu_si128((__m128i *)user_key);

            // 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
            RoundKeysEncrypt->RoundKeys[1]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[0], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[0], 0x01));
            RoundKeysEncrypt->RoundKeys[2]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[1], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[1], 0x02));
            RoundKeysEncrypt->RoundKeys[3]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[2], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[2], 0x04));
            RoundKeysEncrypt->RoundKeys[4]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[3], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[3], 0x08));
            RoundKeysEncrypt->RoundKeys[5]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[4], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[4], 0x10));
            RoundKeysEncrypt->RoundKeys[6]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[5], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[5], 0x20));
            RoundKeysEncrypt->RoundKeys[7]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[6], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[6], 0x40));
            RoundKeysEncrypt->RoundKeys[8]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[7], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[7], 0x80));
            RoundKeysEncrypt->RoundKeys[9]  = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[8], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[8], 0x1b));
            RoundKeysEncrypt->RoundKeys[10] = AES_128_ASSIST(RoundKeysEncrypt->RoundKeys[9], _mm_aeskeygenassist_si128(RoundKeysEncrypt->RoundKeys[9], 0x36));
            break;
        }
        case AES_192: {
            rounds = 13;
            RoundKeysEncrypt->rounds = rounds;
            RoundKeysEncrypt->RoundKeys = malloc(sizeof(__m128i) * rounds);
            RoundKeysEncrypt->RoundKeys[0] = _mm_loadu_si128((__m128i *)user_key);

            __m128i temp1, temp2, temp3;            
            temp1 = _mm_loadu_si128((__m128i*)user_key);
            temp3 = _mm_loadu_si128((__m128i*)(user_key+16));
            RoundKeysEncrypt->RoundKeys[0]=temp1;
            RoundKeysEncrypt->RoundKeys[1]=temp3;
            temp2=_mm_aeskeygenassist_si128 (temp3,0x1);
            KEY_192_ASSIST(&temp1, &temp2, &temp3);
            RoundKeysEncrypt->RoundKeys[1] = (__m128i)_mm_shuffle_pd((__m128d)RoundKeysEncrypt->RoundKeys[1], (__m128d)temp1,0);
            RoundKeysEncrypt->RoundKeys[2] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
            temp2=_mm_aeskeygenassist_si128 (temp3,0x2);
            KEY_192_ASSIST(&temp1, &temp2, &temp3);
            RoundKeysEncrypt->RoundKeys[3]=temp1;
            RoundKeysEncrypt->RoundKeys[4]=temp3;
            temp2=_mm_aeskeygenassist_si128 (temp3,0x4);
            KEY_192_ASSIST(&temp1, &temp2, &temp3);
            RoundKeysEncrypt->RoundKeys[4] = (__m128i)_mm_shuffle_pd((__m128d)RoundKeysEncrypt->RoundKeys[4], (__m128d)temp1,0);
            RoundKeysEncrypt->RoundKeys[5] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
            temp2=_mm_aeskeygenassist_si128 (temp3,0x8);
            KEY_192_ASSIST(&temp1, &temp2, &temp3);
            RoundKeysEncrypt->RoundKeys[6]=temp1;
            RoundKeysEncrypt->RoundKeys[7]=temp3;
            temp2=_mm_aeskeygenassist_si128 (temp3,0x10);
            KEY_192_ASSIST(&temp1, &temp2, &temp3);
            RoundKeysEncrypt->RoundKeys[7] = (__m128i)_mm_shuffle_pd((__m128d)RoundKeysEncrypt->RoundKeys[7], (__m128d)temp1,0);
            RoundKeysEncrypt->RoundKeys[8] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
            temp2=_mm_aeskeygenassist_si128 (temp3,0x20);
            KEY_192_ASSIST(&temp1, &temp2, &temp3);
            RoundKeysEncrypt->RoundKeys[9]=temp1;
            RoundKeysEncrypt->RoundKeys[10]=temp3;
            temp2=_mm_aeskeygenassist_si128 (temp3,0x40);
            KEY_192_ASSIST(&temp1, &temp2, &temp3);
            RoundKeysEncrypt->RoundKeys[10] = (__m128i)_mm_shuffle_pd((__m128d)RoundKeysEncrypt->RoundKeys[10], (__m128d)temp1,0);
            RoundKeysEncrypt->RoundKeys[11] = (__m128i)_mm_shuffle_pd((__m128d)temp1,(__m128d)temp3,1);
            temp2=_mm_aeskeygenassist_si128 (temp3,0x80);
            KEY_192_ASSIST(&temp1, &temp2, &temp3);
            RoundKeysEncrypt->RoundKeys[12]=temp1;
            break;
        }
        case AES_256: {
            rounds = 15;
            RoundKeysEncrypt->rounds = rounds;
            RoundKeysEncrypt->RoundKeys = malloc(sizeof(__m128i) * rounds);
            RoundKeysEncrypt->RoundKeys[0] = _mm_loadu_si128((__m128i *)user_key);

            __m128i temp1, temp2, temp3;
            temp1 = _mm_loadu_si128((__m128i*)user_key);
            temp3 = _mm_loadu_si128((__m128i*)(user_key+16));
            RoundKeysEncrypt->RoundKeys[0] = temp1;
            RoundKeysEncrypt->RoundKeys[1] = temp3;
            temp2 = _mm_aeskeygenassist_si128 (temp3,0x01);
            KEY_256_ASSIST_1(&temp1, &temp2);
            RoundKeysEncrypt->RoundKeys[2]=temp1;
            KEY_256_ASSIST_2(&temp1, &temp3);
            RoundKeysEncrypt->RoundKeys[3]=temp3;
            temp2 = _mm_aeskeygenassist_si128 (temp3,0x02);
            KEY_256_ASSIST_1(&temp1, &temp2);
            RoundKeysEncrypt->RoundKeys[4]=temp1;
            KEY_256_ASSIST_2(&temp1, &temp3);
            RoundKeysEncrypt->RoundKeys[5]=temp3;
            temp2 = _mm_aeskeygenassist_si128 (temp3,0x04);
            KEY_256_ASSIST_1(&temp1, &temp2);
            RoundKeysEncrypt->RoundKeys[6]=temp1;
            KEY_256_ASSIST_2(&temp1, &temp3);
            RoundKeysEncrypt->RoundKeys[7]=temp3;
            temp2 = _mm_aeskeygenassist_si128 (temp3,0x08);
            KEY_256_ASSIST_1(&temp1, &temp2);
            RoundKeysEncrypt->RoundKeys[8]=temp1;
            KEY_256_ASSIST_2(&temp1, &temp3);
            RoundKeysEncrypt->RoundKeys[9]=temp3;
            temp2 = _mm_aeskeygenassist_si128 (temp3,0x10);
            KEY_256_ASSIST_1(&temp1, &temp2);
            RoundKeysEncrypt->RoundKeys[10]=temp1;
            KEY_256_ASSIST_2(&temp1, &temp3);
            RoundKeysEncrypt->RoundKeys[11]=temp3;
            temp2 = _mm_aeskeygenassist_si128 (temp3,0x20);
            KEY_256_ASSIST_1(&temp1, &temp2);
            RoundKeysEncrypt->RoundKeys[12]=temp1;
            KEY_256_ASSIST_2(&temp1, &temp3);
            RoundKeysEncrypt->RoundKeys[13]=temp3;
            temp2 = _mm_aeskeygenassist_si128 (temp3,0x40);
            KEY_256_ASSIST_1(&temp1, &temp2);
            RoundKeysEncrypt->RoundKeys[14]=temp1;
            break;
        }
        default: 
            goto aes_128;
    }
}


void
aesv_set_decrypt_key(struct RoundKeys * RoundKeysDecrypt, uint8_t * user_key, KeySize_t KeySize)
{
    struct RoundKeys RoundKeysEncrypt;
    aesv_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);
    size_t rounds = RoundKeysEncrypt.rounds;
    RoundKeysDecrypt->RoundKeys = malloc(sizeof(__m128i) * rounds);
    RoundKeysDecrypt->rounds = rounds;

    RoundKeysDecrypt->RoundKeys[0] = RoundKeysEncrypt.RoundKeys[rounds-1];
    for (size_t i=1; i<rounds-1; ++i) {
        RoundKeysDecrypt->RoundKeys[i] = _mm_aesimc_si128(RoundKeysEncrypt.RoundKeys[rounds-i-1]);
    }
    RoundKeysDecrypt->RoundKeys[rounds-1] = RoundKeysEncrypt.RoundKeys[0];
}


void
aesvi_encrypt(uint8_t state[BLOCKSIZE], struct RoundKeys * RoundKeysEncrypt)
{
    size_t rounds = RoundKeysEncrypt->rounds;
    __m128i vstate = _mm_loadu_si128((__m128i *)state);

    // Initial round
    vstate = _mm_xor_si128(vstate, RoundKeysEncrypt->RoundKeys[0]);

    // Main rounds
    for (size_t i=1; i<rounds-1; ++i) {
        vstate = _mm_aesenc_si128(vstate, RoundKeysEncrypt->RoundKeys[i]);
    }

    // Final round
    vstate = _mm_aesenclast_si128(vstate, RoundKeysEncrypt->RoundKeys[rounds-1]);

    // Store the result
    _mm_storeu_si128((__m128i *)state, vstate);
}


void
aesvi_decrypt(uint8_t state[BLOCKSIZE], struct RoundKeys * RoundKeysDecrypt)
{
    size_t rounds = RoundKeysDecrypt->rounds;
    __m128i vstate = _mm_loadu_si128((__m128i *)state);

    // Initial round
    vstate = _mm_xor_si128(vstate, RoundKeysDecrypt->RoundKeys[0]);

    // Main rounds
    for (size_t i=1; i<rounds-1; ++i) {
        vstate = _mm_aesdec_si128(vstate, RoundKeysDecrypt->RoundKeys[i]);
    }

    // Final round
    vstate = _mm_aesdeclast_si128(vstate, RoundKeysDecrypt->RoundKeys[rounds-1]);

    // Store the result
    _mm_storeu_si128((__m128i *)state, vstate);
}


__m128i
aesv_encrypt(uint8_t state[BLOCKSIZE], struct RoundKeys * RoundKeysEncrypt)
{
    size_t rounds = RoundKeysEncrypt->rounds;
    __m128i vstate = _mm_loadu_si128((__m128i *)state);

    // Initial round
    vstate = _mm_xor_si128(vstate, RoundKeysEncrypt->RoundKeys[0]);

    // Main rounds
    for (size_t i=1; i<rounds-1; ++i) {
        vstate = _mm_aesenc_si128(vstate, RoundKeysEncrypt->RoundKeys[i]);
    }

    // Final round
    vstate = _mm_aesenclast_si128(vstate, RoundKeysEncrypt->RoundKeys[rounds-1]);

    // Return the result
    return vstate;
}


__m128i
aesv_decrypt(uint8_t state[BLOCKSIZE], struct RoundKeys * RoundKeysDecrypt)
{
    size_t rounds = RoundKeysDecrypt->rounds;
    __m128i vstate = _mm_loadu_si128((__m128i *)state);

    // Initial round
    vstate = _mm_xor_si128(vstate, RoundKeysDecrypt->RoundKeys[0]);

    // Main rounds
    for (size_t i=1; i<rounds-1; ++i) {
        vstate = _mm_aesdec_si128(vstate, RoundKeysDecrypt->RoundKeys[i]);
    }

    // Final round
    vstate = _mm_aesdeclast_si128(vstate, RoundKeysDecrypt->RoundKeys[rounds-1]);

    // Return the result
    return vstate;
}

#include "aes.h"
#include "lookup_tables.h"


void
KeyExpansionCore(uint8_t inp[4], int i)
{
    // Rotate inp left and s_box lookup
    uint8_t tmp[4];
    tmp[0] = s_box[inp[1]];
    tmp[1] = s_box[inp[2]];
    tmp[2] = s_box[inp[3]];
    tmp[3] = s_box[inp[0]];

    memcpy(inp, tmp, 4);

    // Rcon lookup
    inp[0] ^= rcon[i];
}


void
KeyExpansion(uint8_t expanded_key[EXPANDEDSIZE], uint8_t * user_key)
{
    // __m128i _mm_aeskeygenassist_si128 (__m128i a, const int imm8)

    // The first BLOCKSIZE is the original key
    memcpy(expanded_key, user_key, BLOCKSIZE);

    int rcon_iteration = 1;
    int current_size = BLOCKSIZE;

    while (current_size < EXPANDEDSIZE) {
        uint8_t tmp[4];
        memcpy(tmp, &expanded_key[current_size-4], 4);

        if ((current_size % BLOCKSIZE) == 0) {
            KeyExpansionCore(tmp, rcon_iteration);
            rcon_iteration += 1;
        }

        for (int i=0; i<4; ++i) {
            expanded_key[current_size] = expanded_key[current_size-BLOCKSIZE] ^ tmp[i];
            current_size += 1;
        }
    }
}


void
AddRoundKey(uint8_t state[BLOCKSIZE], uint8_t key[BLOCKSIZE])
{
    for (int i=0; i<BLOCKSIZE; ++i) {
        state[i] ^= key[i];
    }
}


void
SubBytes(uint8_t state[BLOCKSIZE])
{
    for (int i=0; i<BLOCKSIZE; ++i) 
        state[i] = s_box[state[i]];
}


void
InvSubBytes(uint8_t state[BLOCKSIZE])
{
    for (int i=0; i<BLOCKSIZE; ++i) 
        state[i] = inv_s_box[state[i]];
}


void
ShiftRows(uint8_t state[BLOCKSIZE])
{
    /*
    Cyclic shift to the left of the state rows
    row 0: 0 shifts
    row 1: 1 shift
    row 2: 2 shifts
    row 3: 3 shifts
    */
    uint8_t tmp[BLOCKSIZE];

    tmp[0]  = state[0];
    tmp[1]  = state[5];
    tmp[2]  = state[10];
    tmp[3]  = state[15];
    tmp[4]  = state[4];
    tmp[5]  = state[9];
    tmp[6]  = state[14];
    tmp[7]  = state[3];
    tmp[8]  = state[8];
    tmp[9]  = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    memcpy(state, tmp, BLOCKSIZE);
}


void
InvShiftRows(uint8_t state[BLOCKSIZE])
{
    /*
    Cyclic shift to the right of the state rows
    row 0: 0 shifts
    row 1: 1 shift
    row 2: 2 shifts
    row 3: 3 shifts
    */
    uint8_t tmp[BLOCKSIZE];

    tmp[0]  = state[0];
    tmp[1]  = state[13];
    tmp[2]  = state[10];
    tmp[3]  = state[7];
    tmp[4]  = state[4];
    tmp[5]  = state[1];
    tmp[6]  = state[14];
    tmp[7]  = state[11];
    tmp[8]  = state[8];
    tmp[9]  = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    memcpy(state, tmp, BLOCKSIZE);
}


void
MixColumns(uint8_t state[BLOCKSIZE])
{
    /*
    2   3   1   1
    1   2   3   1
    1   1   2   2
    3   1   1   2

    Multiplication and reduction result can be found in lookup table mul2 and mul3. Multiplication by 1 is the same.
    */
    uint8_t tmp[BLOCKSIZE];

    tmp[0] = mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
    tmp[1] = state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
    tmp[2] = state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
    tmp[3] = mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

    tmp[4] = mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
    tmp[5] = state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
    tmp[6] = state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
    tmp[7] = mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

    tmp[8] = mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
    tmp[9] = state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
    tmp[10] = state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
    tmp[11] = mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

    tmp[12] = mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
    tmp[13] = state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
    tmp[14] = state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
    tmp[15] = mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

    memcpy(state, tmp, BLOCKSIZE);
}


void
InvMixColumns(uint8_t state[BLOCKSIZE])
{
    /*
    14  11  13  9
    9   14  11  13
    13  9   14  11
    11  13  9   14

    Multiplication and reduction result can be found in lookup table mul9, mul11, mul13 and mul14.
    */
    uint8_t tmp[BLOCKSIZE];

    tmp[0] = mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
    tmp[1] = mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
    tmp[2] = mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
    tmp[3] = mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

    tmp[4] = mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
    tmp[5] = mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
    tmp[6] = mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
    tmp[7] = mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

    tmp[8] = mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
    tmp[9] = mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
    tmp[10] = mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
    tmp[11] = mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

    tmp[12] = mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
    tmp[13] = mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
    tmp[14] = mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
    tmp[15] = mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

    memcpy(state, tmp, BLOCKSIZE);
}


void
aes_encrypt(uint8_t state[BLOCKSIZE], uint8_t RoundKeysEncrypt[EXPANDEDSIZE])
{
    // Initial round
    AddRoundKey(state, RoundKeysEncrypt);

    // Main rounds
    for (int i=1; i<ROUNDS-1; ++i) {
        ShiftRows(state);
        SubBytes(state);
        MixColumns(state);
        AddRoundKey(state, &RoundKeysEncrypt[i*BLOCKSIZE]);
    }

    // Final round
    ShiftRows(state);
    SubBytes(state);
    AddRoundKey(state, &RoundKeysEncrypt[(ROUNDS-1)*BLOCKSIZE]);
}


void
aes_decrypt(uint8_t state[BLOCKSIZE], uint8_t RoundKeysDecrypt[EXPANDEDSIZE])
{
    // Initial round
    AddRoundKey(state, &RoundKeysDecrypt[(ROUNDS-1)*BLOCKSIZE]);
    InvSubBytes(state);
    InvShiftRows(state);

    // Main rounds
    for (int i=ROUNDS-2; i>0; --i) {
        AddRoundKey(state, &RoundKeysDecrypt[i*BLOCKSIZE]);
        InvMixColumns(state);
        InvSubBytes(state);
        InvShiftRows(state);
    }

    // Final round
    AddRoundKey(state, RoundKeysDecrypt);
}

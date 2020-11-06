#include "aesi.h"
#include "utils.h"


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
aes_set_encrypt_key(struct RoundKeys * RoundKeysEncrypt, uint8_t * user_key, KeySize_t KeySize)
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
aes_set_decrypt_key(struct RoundKeys * RoundKeysDecrypt, uint8_t * user_key, KeySize_t KeySize)
{
    struct RoundKeys RoundKeysEncrypt;
    aes_set_encrypt_key(&RoundKeysEncrypt, user_key, KeySize);
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
aesi_block_encrypt(uint8_t state[BLOCKSIZE], struct RoundKeys * RoundKeysEncrypt)
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
aesi_block_decrypt(uint8_t state[BLOCKSIZE], struct RoundKeys * RoundKeysDecrypt)
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
aes_block_encrypt(uint8_t state[BLOCKSIZE], struct RoundKeys * RoundKeysEncrypt)
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
aes_block_decrypt(uint8_t state[BLOCKSIZE], struct RoundKeys * RoundKeysDecrypt)
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


static
encrypt_fptr_t get_encrypt_fptr(Mode_t aes_mode)
{
    encrypt_fptr_t fptr = NULL;
    switch (aes_mode)
    {
    case AES_CTR:
        fptr = aes_ctr_encrypt;
        break;
    case AES_CBC:
        fptr = aes_cbc_encrypt;
        break;
    case AES_CFB:
        fptr = aes_cfb_encrypt;
        break;
    case AES_OFB:
        fptr = aes_ofb_encrypt;
        break;
    case AES_ECB:
        fptr = aes_ecb_encrypt;
        break;
    default:
        fptr = aes_ctr_encrypt;
    }
    return fptr;
}


static
decrypt_fptr_t get_decrypt_fptr(Mode_t aes_mode)
{
    decrypt_fptr_t fptr = NULL;
    switch (aes_mode)
    {
    case AES_CTR:
        fptr = aes_ctr_decrypt;
        break;
    case AES_CBC:
        fptr = aes_cbc_decrypt;
        break;
    case AES_CFB:
        fptr = aes_cfb_decrypt;
        break;
    case AES_OFB:
        fptr = aes_ofb_decrypt;
        break;
    case AES_ECB:
        fptr = aes_ecb_decrypt;
        break;
    default:
        fptr = aes_ctr_decrypt;
    }
    return fptr;
}


void
aes_encrypt(uint8_t ** data, size_t * size, char * passphrase, Mode_t aes_mode, KeySize_t key_size)
{
    encrypt_fptr_t fptr = get_encrypt_fptr(aes_mode);

    size_t blocks = *size / BLOCKSIZE;
    size_t remainder_bytes = *size - blocks*BLOCKSIZE;
    size_t padded_bytes = remainder_bytes ? BLOCKSIZE - remainder_bytes : 0;
    if (padded_bytes) ++blocks;

    *data = realloc(*data, *size + padded_bytes + sizeof(size_t) + SALTSIZE); // original size + padding + num padding bytes + salt
    // pad with zeros
    memset(*data + *size, 0, padded_bytes);

    uint8_t user_key[key_size];
    uint8_t IV[BLOCKSIZE];
    uint8_t salt[SALTSIZE];
    if (!random_bytes(salt, SALTSIZE)) exit(EXIT_FAILURE);
    derive_key_iv(passphrase, key_size, salt, SALTSIZE, user_key, IV);

    fptr(*data, blocks, user_key, IV, key_size);

    // store the padding size
    *(size_t *)(*data + *size + padded_bytes) = padded_bytes;
    // store the salt
    memcpy(*data + *size + padded_bytes + sizeof(size_t), salt, SALTSIZE);
    // update the data size
    *size = *size + padded_bytes + sizeof(size_t) + SALTSIZE;
}


void
aes_decrypt(uint8_t ** data, size_t * size, char * passphrase, Mode_t aes_mode, KeySize_t key_size)
{
    decrypt_fptr_t fptr = get_decrypt_fptr(aes_mode);

    // read the padding size
    size_t padded_bytes = *(size_t *)(*data + *size - SALTSIZE - sizeof(size_t));
    size_t blocks = (*size - sizeof(size_t) - SALTSIZE) / BLOCKSIZE;

    uint8_t user_key[key_size];
    uint8_t IV[BLOCKSIZE];
    uint8_t salt[SALTSIZE];
    memcpy(salt, *data + *size - SALTSIZE, SALTSIZE);
    derive_key_iv(passphrase, key_size, salt, SALTSIZE, user_key, IV);

    fptr(*data, blocks, user_key, IV, key_size);

    // update the data size
    *size = *size - padded_bytes - sizeof(size_t) - SALTSIZE;

    *data = realloc(*data, *size);
}


void
aes_encrypt_file(char * filename, char * savename, char * passphrase, Mode_t aes_mode, KeySize_t key_size)
{
    encrypt_fptr_t fptr = get_encrypt_fptr(aes_mode);

    // setup in/out files
    FILE * f_in = NULL;
    size_t f_in_size;

    open_file(filename, &f_in, &f_in_size);
    if (f_in == NULL) return;
    if (f_in_size == 0) return;

    size_t blocks = f_in_size / BLOCKSIZE;

    uint8_t * data = malloc((blocks >= BLOCKS_PER_ITERATION) ? (BLOCKS_PER_ITERATION*BLOCKSIZE) : (f_in_size));

    FILE * f_out = fopen(savename, "wb");

    if (f_out == NULL) return;

    // derive key and IV
    uint8_t user_key[key_size];
    uint8_t IV[BLOCKSIZE];
    uint8_t salt[SALTSIZE];
    if (!random_bytes(salt, SALTSIZE)) exit(EXIT_FAILURE);
    derive_key_iv(passphrase, key_size, salt, SALTSIZE, user_key, IV);

    // write the padding size
    size_t remainder_bytes = f_in_size - blocks*BLOCKSIZE;
    size_t padded_bytes = remainder_bytes ? BLOCKSIZE - remainder_bytes : 0;
    fwrite(&padded_bytes, sizeof(size_t), 1, f_out);

    // write the salt to the output file
    fwrite(salt, 1, SALTSIZE, f_out);

    // do the encryption
    size_t i = 0;
    while (i < (blocks/BLOCKS_PER_ITERATION)) { // handle large files
        if (fread(data, 1, BLOCKS_PER_ITERATION*BLOCKSIZE, f_in)) {
            fptr(data, BLOCKS_PER_ITERATION, user_key, IV, key_size);
            fwrite(data, 1, BLOCKS_PER_ITERATION*BLOCKSIZE, f_out);
        }
        ++i;
    }

    // encrypt the remainder blocks
    size_t remainder_blocks = (f_in_size - (blocks/BLOCKS_PER_ITERATION)*BLOCKSIZE*BLOCKS_PER_ITERATION) / BLOCKSIZE;
    if (remainder_blocks) {
        if (fread(data, 1, remainder_blocks*BLOCKSIZE, f_in)) {
            fptr(data, remainder_blocks, user_key, IV, key_size);
            fwrite(data, 1, remainder_blocks*BLOCKSIZE, f_out);
        }
    }

    // encrypt remaining bytes
    if (padded_bytes) {
        memset(data, 0, BLOCKSIZE);
        if (fread(data, 1, BLOCKSIZE-padded_bytes, f_in)) {
            fptr(data, 1, user_key, IV, key_size);
            fwrite(data, 1, BLOCKSIZE, f_out);
        }
    }
    

    free(data);

    fclose(f_in);
    fclose(f_out);
}


void
aes_decrypt_file(char * filename, char * savename, char * passphrase, Mode_t aes_mode, KeySize_t key_size)
{
    decrypt_fptr_t fptr = get_decrypt_fptr(aes_mode);

    FILE * f_in = NULL;
    size_t f_in_size;

    open_file(filename, &f_in, &f_in_size);
    if (f_in == NULL) return;
    if (f_in_size <= (SALTSIZE+sizeof(size_t))) return;

    // read the padding size from f_in
    size_t padded_bytes = 0;
    if (!fread(&padded_bytes, sizeof(size_t), 1, f_in)) return;

    f_in_size = f_in_size - (padded_bytes > 0) * BLOCKSIZE - sizeof(size_t) - SALTSIZE;
    size_t blocks = f_in_size / BLOCKSIZE;

    uint8_t * data = malloc((blocks >= BLOCKS_PER_ITERATION) ? (BLOCKS_PER_ITERATION*BLOCKSIZE) : (f_in_size));

    FILE * f_out = fopen(savename, "wb");

    if (f_out == NULL) return;

    // read the salt from f_in
    uint8_t salt[SALTSIZE];
    if (!fread(salt, 1, SALTSIZE, f_in)) return;

    // derive key and IV
    uint8_t user_key[key_size];
    uint8_t IV[BLOCKSIZE];
    derive_key_iv(passphrase, key_size, salt, SALTSIZE, user_key, IV);

    // do the decryption
    size_t i = 0;
    while (i < (blocks/BLOCKS_PER_ITERATION)) { // handle large files
        if (fread(data, 1, BLOCKS_PER_ITERATION*BLOCKSIZE, f_in)) {
            fptr(data, BLOCKS_PER_ITERATION, user_key, IV, key_size);
            fwrite(data, 1, BLOCKS_PER_ITERATION*BLOCKSIZE, f_out);
        }
        ++i;
    }

    // decrypt the remaining blocks
    size_t remainder_bytes = f_in_size - (blocks/BLOCKS_PER_ITERATION)*BLOCKSIZE*BLOCKS_PER_ITERATION;
    if (remainder_bytes) {
        if (fread(data, 1, remainder_bytes, f_in)) {
            fptr(data, remainder_bytes/BLOCKSIZE, user_key, IV, key_size);
            fwrite(data, 1, remainder_bytes, f_out);
        }
    }

    // decrypt the remaining bytes
    if (padded_bytes) {
        memset(data, 0, BLOCKSIZE);
        if (fread(data, 1, BLOCKSIZE, f_in)) {
            fptr(data, 1, user_key, IV, key_size);
            fwrite(data, 1, BLOCKSIZE-padded_bytes, f_out);
        }
    }
    
    free(data);

    fclose(f_in);
    fclose(f_out);
}

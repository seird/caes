#ifndef __AES_H__
#define __AES_H__


#include <stdint.h>
#include <string.h>

#include "params.h"


#define EXPANDEDSIZE (ROUNDS*BLOCKSIZE)


void KeyExpansionCore(uint8_t inp[4], int i);
void KeyExpansion(uint8_t RoundKeys[EXPANDEDSIZE], uint8_t user_key[BLOCKSIZE]);
void AddRoundKey(uint8_t state[BLOCKSIZE], uint8_t user_key[BLOCKSIZE]);
void SubBytes(uint8_t state[BLOCKSIZE]);
void InvSubBytes(uint8_t state[BLOCKSIZE]);
void ShiftRows(uint8_t state[BLOCKSIZE]);
void InvShiftRows(uint8_t state[BLOCKSIZE]);
void MixColumns(uint8_t state[BLOCKSIZE]);
void InvMixColumns(uint8_t state[BLOCKSIZE]);

#define aes_set_encrypt_key(RoundKeysEncrypt, user_key) KeyExpansion(RoundKeysEncrypt, user_key)
#define aes_set_decrypt_key(RoundKeysDecrypt, user_key) KeyExpansion(RoundKeysDecrypt, user_key)
void aes_encrypt(uint8_t state[BLOCKSIZE], uint8_t RoundKeysEncrypt[EXPANDEDSIZE]);
void aes_decrypt(uint8_t state[BLOCKSIZE], uint8_t RoundKeysDecrypt[EXPANDEDSIZE]);


#endif // __AES_H__

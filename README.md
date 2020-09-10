# AES

[![pipeline status](https://gitlab.com/kdries/caes/badges/master/pipeline.svg)](https://gitlab.com/kdries/caes/commits/master)


AES implementation in C and [Intel intrinsics](https://software.intel.com/sites/landingpage/IntrinsicsGuide/#cats=Cryptography).


## Modes

- AES-CTR
- AES-CBC
- AES-CFB
- AES-OFB
- AES-ECB


## Benchmarks

Time to encrypt / decrypt a 100MB file (no parallelization/threading):

|             | Encrypt  | Decrypt  |
|-------------|----------|---------:|
| **aes_ctr** | 0.1087 s | 0.1077 s |
| **aes_cbc** | 0.0919 s | 0.0447 s |
| **aes_cfb** | 0.0917 s | 0.0455 s |
| **aes_ofb** | 0.0900 s | 0.0901 s |
| **aes_ecb** | 0.0435 s | 0.0436 s |


```
=================================================
Benchmarking ...
        Number of runs     =                   10

bench_aes_block_encrypt
          0.231700 seconds per run [2.317000 seconds total]

bench_aes_block_decrypt
          0.239300 seconds per run [2.393000 seconds total]

bench_aesvi_intrinsic_block_encrypt
          0.009600 seconds per run [0.096000 seconds total]

bench_aesvi_intrinsic_block_decrypt
          0.009600 seconds per run [0.096000 seconds total]


===========================================================
AES MODES ...
===========================================================
bench_aes_ctr_encrypt
          0.108700 seconds per run [1.087000 seconds total]

bench_aes_ctr_decrypt
          0.107700 seconds per run [1.077000 seconds total]

bench_aes_cfb_encrypt
          0.091700 seconds per run [0.917000 seconds total]

bench_aes_cfb_decrypt
          0.045500 seconds per run [0.455000 seconds total]

bench_aes_ofb_encrypt
          0.090000 seconds per run [0.900000 seconds total]

bench_aes_ofb_decrypt
          0.090100 seconds per run [0.901000 seconds total]

bench_aes_ecb_encrypt
          0.043500 seconds per run [0.435000 seconds total]

bench_aes_ecb_decrypt
          0.043600 seconds per run [0.436000 seconds total]

bench_aes_cbc_encrypt
          0.091900 seconds per run [0.919000 seconds total]

bench_aes_cbc_decrypt
          0.044700 seconds per run [0.447000 seconds total]
```


## External Functions

Intel intrinsics in `src/aesv.h`:

```c
/* aes block encryption */

void aesv_set_encrypt_key(__m128i RoundKeysEncrypt[ROUNDS], uint8_t user_key[BLOCKSIZE]);
void aesv_set_decrypt_key(__m128i RoundKeysDecrypt[ROUNDS], uint8_t user_key[BLOCKSIZE]);
void aesvi_encrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysEncrypt[ROUNDS]); // in place encryption
void aesvi_decrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysDecrypt[ROUNDS]); // in place encryption
__m128i aesv_encrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysEncrypt[ROUNDS]); // state remains unchanged
__m128i aesv_decrypt(uint8_t state[BLOCKSIZE], __m128i RoundKeysDecrypt[ROUNDS]); // state remains unchanged


/* aes modes */

// AES-CTR
void aesv_ctr_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
void aesv_ctr_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);

// AES-ECB
void aesv_ecb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE]);
void aesv_ecb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE]);

// AES-CFB
void aesv_cfb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
void aesv_cfb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);

// AES-OFB
void aesv_ofb_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
void aesv_ofb_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);

// AES-CBC
void aesv_cbc_encrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
void aesv_cbc_decrypt(uint8_t * data, size_t blocks, uint8_t user_key[BLOCKSIZE], uint8_t IV[BLOCKSIZE]);
```

Plain C in `src/aes.h`:

```c
/* aes block encryption */

#define aes_set_encrypt_key(RoundKeysEncrypt, user_key) KeyExpansion(RoundKeysEncrypt, user_key)
#define aes_set_decrypt_key(RoundKeysDecrypt, user_key) KeyExpansion(RoundKeysDecrypt, user_key)
void aes_encrypt(uint8_t state[BLOCKSIZE], uint8_t RoundKeysEncrypt[EXPANDEDSIZE]);
void aes_decrypt(uint8_t state[BLOCKSIZE], uint8_t RoundKeysDecrypt[EXPANDEDSIZE]);
```
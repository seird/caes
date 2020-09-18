# AES

[![pipeline status](https://gitlab.com/kdries/caes/badges/master/pipeline.svg)](https://gitlab.com/kdries/caes/commits/master)


AES implementation in C with [Intel intrinsics](https://software.intel.com/sites/landingpage/IntrinsicsGuide/#cats=Cryptography).


## Modes

- AES-CTR-128/192/256
- AES-CBC-128/192/256
- AES-CFB-128/192/256
- AES-OFB-128/192/256
- AES-ECB-128/192/256


## Example

Encrypt/decrypt a file:

```c
#include "aes.h"

int
main(void)
{
	// Encrypt file
	char passphrase[] = "hunter2";	

	aes_encrypt_file("in.jpg", "out.jpg.aes", passphrase, AES_CTR, AES_256);
	aes_decrypt_file("out.jpg.aes", "out.jpg", passphrase, AES_CTR, AES_256);


	// Encrypt data
    size_t size = 10*BLOCKSIZE + 5;
    uint8_t * data = (uint8_t *) malloc(size);
    memset(data, 0xab, size);

    aes_encrypt(&data, &size, passphrase, aes_mode, key_size);
    aes_decrypt(&data, &size, passphrase, aes_mode, key_size);

	
	return 0;
}
```


## Api

Intel intrinsics in `src/aes.h`:

```c
typedef enum KeySize {
    AES_128 = 128,
    AES_192 = 192,
    AES_256 = 256,
} KeySize_t;


typedef enum Mode {
    AES_CTR,
    AES_CBC,
    AES_OFB,
    AES_CFB,
    AES_ECB,
} Mode_t;


void aes_encrypt(uint8_t ** data, size_t * size, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
void aes_decrypt(uint8_t ** data, size_t * size, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
void aes_encrypt_file(char * filename, char * savename, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
void aes_decrypt_file(char * filename, char * savename, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
```


## Benchmarks

Time to encrypt / decrypt a 100MB file (no parallelization/threading, reading the file takes 0.03s):

|                 | Encrypt  | Decrypt  |
|-----------------|----------|---------:|
| **aes_ctr_128** | 0.1089 s | 0.1080 s |
| **aes_cbc_128** | 0.0924 s | 0.0501 s |
| **aes_cfb_128** | 0.0921 s | 0.0530 s |
| **aes_ofb_128** | 0.0917 s | 0.0901 s |
| **aes_ecb_128** | 0.0501 s | 0.0507 s |
| **aes_ctr_192** | 0.1179 s | 0.1178 s |
| **aes_cbc_192** | 0.1030 s | 0.0540 s |
| **aes_cfb_192** | 0.1028 s | 0.0567 s |
| **aes_ofb_192** | 0.1005 s | 0.1020 s |
| **aes_ecb_192** | 0.0540 s | 0.0550 s |
| **aes_ctr_256** | 0.1310 s | 0.1335 s |
| **aes_cbc_256** | 0.1160 s | 0.0640 s |
| **aes_cfb_256** | 0.1127 s | 0.0618 s |
| **aes_ofb_256** | 0.1108 s | 0.1125 s |
| **aes_ecb_256** | 0.0637 s | 0.0610 s |


```
=================================================
Benchmarking ...
	Number of runs     =                   10


===========================================================
AES BLOCKS ...
===========================================================
bench_aes_block_encrypt
	  0.236200 seconds per run [2.362000 seconds total]

bench_aes_block_decrypt
	  0.240600 seconds per run [2.406000 seconds total]

bench_aesi_intrinsic_block_128_encrypt
	  0.009600 seconds per run [0.096000 seconds total]

bench_aesi_intrinsic_block_128_decrypt
	  0.009600 seconds per run [0.096000 seconds total]

bench_aesi_intrinsic_block_192_encrypt
	  0.011400 seconds per run [0.114000 seconds total]

bench_aesi_intrinsic_block_192_decrypt
	  0.011200 seconds per run [0.112000 seconds total]

bench_aesi_intrinsic_block_256_encrypt
	  0.012900 seconds per run [0.129000 seconds total]

bench_aesi_intrinsic_block_256_decrypt
	  0.012900 seconds per run [0.129000 seconds total]


===========================================================
AES MODES ...
===========================================================
bench_aes_ctr_128_encrypt
	  0.108900 seconds per run [1.089000 seconds total]

bench_aes_ctr_128_decrypt
	  0.108000 seconds per run [1.080000 seconds total]

bench_aes_cfb_128_encrypt
	  0.092100 seconds per run [0.921000 seconds total]

bench_aes_cfb_128_decrypt
	  0.053000 seconds per run [0.530000 seconds total]

bench_aes_ofb_128_encrypt
	  0.091700 seconds per run [0.917000 seconds total]

bench_aes_ofb_128_decrypt
	  0.090100 seconds per run [0.901000 seconds total]

bench_aes_ecb_128_encrypt
	  0.050100 seconds per run [0.501000 seconds total]

bench_aes_ecb_128_decrypt
	  0.050700 seconds per run [0.507000 seconds total]

bench_aes_cbc_128_encrypt
	  0.092400 seconds per run [0.924000 seconds total]

bench_aes_cbc_128_decrypt
	  0.050100 seconds per run [0.500999 seconds total]

bench_aes_ctr_192_encrypt
	  0.117900 seconds per run [1.179001 seconds total]

bench_aes_ctr_192_decrypt
	  0.117800 seconds per run [1.177999 seconds total]

bench_aes_cfb_192_encrypt
	  0.102800 seconds per run [1.028001 seconds total]

bench_aes_cfb_192_decrypt
	  0.056700 seconds per run [0.566999 seconds total]

bench_aes_ofb_192_encrypt
	  0.100500 seconds per run [1.004999 seconds total]

bench_aes_ofb_192_decrypt
	  0.102000 seconds per run [1.020000 seconds total]

bench_aes_ecb_192_encrypt
	  0.054000 seconds per run [0.540001 seconds total]

bench_aes_ecb_192_decrypt
	  0.055000 seconds per run [0.549999 seconds total]

bench_aes_cbc_192_encrypt
	  0.103000 seconds per run [1.030001 seconds total]

bench_aes_cbc_192_decrypt
	  0.054000 seconds per run [0.539999 seconds total]

bench_aes_ctr_256_encrypt
	  0.131000 seconds per run [1.309999 seconds total]

bench_aes_ctr_256_decrypt
	  0.133500 seconds per run [1.335001 seconds total]

bench_aes_cfb_256_encrypt
	  0.112700 seconds per run [1.127001 seconds total]

bench_aes_cfb_256_decrypt
	  0.061800 seconds per run [0.617998 seconds total]

bench_aes_ofb_256_encrypt
	  0.110800 seconds per run [1.108002 seconds total]

bench_aes_ofb_256_decrypt
	  0.112500 seconds per run [1.125000 seconds total]

bench_aes_ecb_256_encrypt
	  0.063700 seconds per run [0.636999 seconds total]

bench_aes_ecb_256_decrypt
	  0.061000 seconds per run [0.610001 seconds total]

bench_aes_cbc_256_encrypt
	  0.116000 seconds per run [1.160000 seconds total]

bench_aes_cbc_256_decrypt
	  0.064000 seconds per run [0.639999 seconds total]
```

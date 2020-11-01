# AES

[![pipeline status](https://gitlab.com/kdries/caes/badges/master/pipeline.svg)](https://gitlab.com/kdries/caes/commits/master)


AES implementation in C with [Intel intrinsics](https://software.intel.com/sites/landingpage/IntrinsicsGuide/#cats=Cryptography).


## Modes

- AES-CTR-128/192/256
- AES-CBC-128/192/256
- AES-CFB-128/192/256
- AES-OFB-128/192/256
- AES-ECB-128/192/256


## Command line utility


### Build

```
make build
```

### Usage
```
Usage: aes.exe -[e|d] [-m mode] [-s size] -i file_in -o file_out [PASSPHRASE]

-e                encrypt
-d                decrypt
-i <file_in>      path to file to encrypt
-o <file_out>     path to encrypted output file
-m <mode>         AES mode: ctr, cbc, ofb, cfb or ecb; default ctr
-s <size>         AES key size: 128, 192 or 256; default 256
```

### Example
```
# Encrypt in.jpg
$ ./aes.exe -e -i in.jpg -o out.jpg.aes hunter2

# Decrypt in.jpg.aes
$ ./aes.exe -d -i out.jpg.aes -o out.jpg hunter2

# Or enter the passphrase interactively
$ ./aes.exe -e -i in.jpg -o out.jpg.aes
Enter password:
Repeat password:
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


### Api Example

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
    
    aes_encrypt(&data, &size, passphrase, AES_CTR, AES_256);
    aes_decrypt(&data, &size, passphrase, AES_CTR, AES_256);
    
    
    return 0;
}
```

## Benchmarks

- Buffer (in RAM) size = 160 MB
- Averaged over 5 runs
- No threading


### AES blocks

|                 |  Encrypt  |  Decrypt  |
|-----------------|:---------:|:---------:|
|**aes_block_128**| 4790 MB/s | 4790 MB/s |
|**aes_block_192**| 3941 MB/s | 4188 MB/s |
|**aes_block_256**| 3653 MB/s | 3320 MB/s |


### AES modes

|                 |  Encrypt  |  Decrypt  |
|-----------------|:---------:|:---------:|
| **aes_ctr_128** | 1246 MB/s | 1288 MB/s |
| **aes_cbc_128** | 1610 MB/s | 4734 MB/s |
| **aes_cfb_128** | 1600 MB/s | 4420 MB/s |
| **aes_ofb_128** | 1663 MB/s | 1663 MB/s |
| **aes_ecb_128** | 5063 MB/s | 5063 MB/s |
| **aes_ctr_192** | 1144 MB/s | 1143 MB/s |
| **aes_cbc_192** | 1384 MB/s | 4103 MB/s |
| **aes_cfb_192** | 1377 MB/s | 3721 MB/s |
| **aes_ofb_192** | 1421 MB/s | 1423 MB/s |
| **aes_ecb_192** | 4301 MB/s | 4233 MB/s |
| **aes_ctr_256** | 1024 MB/s | 1026 MB/s |
| **aes_cbc_256** | 1210 MB/s | 3404 MB/s |
| **aes_cfb_256** | 1214 MB/s | 3239 MB/s |
| **aes_ofb_256** | 1240 MB/s | 1240 MB/s |
| **aes_ecb_256** | 3556 MB/s | 3509 MB/s |


```
=================================================
Benchmarking ...
        Number of runs     =                    5


===========================================================
AES BLOCKS ...
===========================================================
bench_aes_intrinsic_block_128_encrypt
          0.033400 seconds per run [0.167000 seconds total] [4790 MB/s]

bench_aes_intrinsic_block_128_decrypt
          0.033400 seconds per run [0.167000 seconds total] [4790 MB/s]

bench_aes_intrinsic_block_192_encrypt
          0.040600 seconds per run [0.203000 seconds total] [3941 MB/s]

bench_aes_intrinsic_block_192_decrypt
          0.038200 seconds per run [0.191000 seconds total] [4188 MB/s]

bench_aes_intrinsic_block_256_encrypt
          0.043800 seconds per run [0.219000 seconds total] [3653 MB/s]

bench_aes_intrinsic_block_256_decrypt
          0.048200 seconds per run [0.241000 seconds total] [3320 MB/s]


===========================================================
AES MODES ...
===========================================================
bench_aes_ctr_128_encrypt
          0.128400 seconds per run [0.642000 seconds total] [1246 MB/s]

bench_aes_ctr_128_decrypt
          0.124200 seconds per run [0.621000 seconds total] [1288 MB/s]

bench_aes_cfb_128_encrypt
          0.100000 seconds per run [0.500000 seconds total] [1600 MB/s]

bench_aes_cfb_128_decrypt
          0.036200 seconds per run [0.181000 seconds total] [4420 MB/s]

bench_aes_ofb_128_encrypt
          0.096200 seconds per run [0.481000 seconds total] [1663 MB/s]

bench_aes_ofb_128_decrypt
          0.096200 seconds per run [0.481000 seconds total] [1663 MB/s]

bench_aes_ecb_128_encrypt
          0.031600 seconds per run [0.158000 seconds total] [5063 MB/s]

bench_aes_ecb_128_decrypt
          0.031600 seconds per run [0.158000 seconds total] [5063 MB/s]

bench_aes_cbc_128_encrypt
          0.099400 seconds per run [0.497000 seconds total] [1610 MB/s]

bench_aes_cbc_128_decrypt
          0.033800 seconds per run [0.169000 seconds total] [4734 MB/s]

bench_aes_ctr_192_encrypt
          0.139800 seconds per run [0.699000 seconds total] [1144 MB/s]

bench_aes_ctr_192_decrypt
          0.140000 seconds per run [0.700000 seconds total] [1143 MB/s]

bench_aes_cfb_192_encrypt
          0.116200 seconds per run [0.581000 seconds total] [1377 MB/s]

bench_aes_cfb_192_decrypt
          0.043000 seconds per run [0.215000 seconds total] [3721 MB/s]

bench_aes_ofb_192_encrypt
          0.112600 seconds per run [0.563000 seconds total] [1421 MB/s]

bench_aes_ofb_192_decrypt
          0.112400 seconds per run [0.562000 seconds total] [1423 MB/s]

bench_aes_ecb_192_encrypt
          0.037200 seconds per run [0.186000 seconds total] [4301 MB/s]

bench_aes_ecb_192_decrypt
          0.037800 seconds per run [0.189000 seconds total] [4233 MB/s]

bench_aes_cbc_192_encrypt
          0.115600 seconds per run [0.578000 seconds total] [1384 MB/s]

bench_aes_cbc_192_decrypt
          0.039000 seconds per run [0.195000 seconds total] [4103 MB/s]

bench_aes_ctr_256_encrypt
          0.156200 seconds per run [0.781000 seconds total] [1024 MB/s]

bench_aes_ctr_256_decrypt
          0.156000 seconds per run [0.780000 seconds total] [1026 MB/s]

bench_aes_cfb_256_encrypt
          0.131800 seconds per run [0.659000 seconds total] [1214 MB/s]

bench_aes_cfb_256_decrypt
          0.049400 seconds per run [0.247000 seconds total] [3239 MB/s]

bench_aes_ofb_256_encrypt
          0.129000 seconds per run [0.645000 seconds total] [1240 MB/s]

bench_aes_ofb_256_decrypt
          0.129000 seconds per run [0.645000 seconds total] [1240 MB/s]

bench_aes_ecb_256_encrypt
          0.045000 seconds per run [0.224999 seconds total] [3556 MB/s]

bench_aes_ecb_256_decrypt
          0.045600 seconds per run [0.228000 seconds total] [3509 MB/s]

bench_aes_cbc_256_encrypt
          0.132200 seconds per run [0.661000 seconds total] [1210 MB/s]

bench_aes_cbc_256_decrypt
          0.047000 seconds per run [0.235001 seconds total] [3404 MB/s]
```

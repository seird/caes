# AES

[![build](https://github.com/seird/caes/actions/workflows/build.yml/badge.svg)](https://github.com/seird/caes/actions) [![codecov](https://codecov.io/gh/seird/caes/branch/master/graph/badge.svg)](https://codecov.io/gh/seird/caes)


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
make
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

### Build

```
make lib
```

### Usage

Include the header `include/aes.h`:

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


/* Encrypt bytes on the heap */
void aes_encrypt(uint8_t ** data, size_t * size, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
/* Decrypt bytes on the heap */
void aes_decrypt(uint8_t ** data, size_t * size, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
/* Encrypt a file */
void aes_encrypt_file(char * filename, char * savename, char * passphrase, Mode_t aes_mode, KeySize_t key_size);
/* Decrypt a file */
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

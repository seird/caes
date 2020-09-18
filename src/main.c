#include <time.h>

#include "aes.h"


#if (!defined(TEST) && !defined(SHARED) && !defined(BENCHMARK))


static void
print_array(uint8_t * data, size_t size)
{
    for (size_t i=0; i<size; ++i) {
        printf("%02x ", data[i]);
        if (((i+1) % BLOCKSIZE) == 0) printf("\n");
    }
    printf("\n-----------------------------------------------\n");
}


int
main(void)
{
    srand(time(NULL));

    Mode_t aes_mode = AES_CTR;
    KeySize_t key_size = AES_256;
    char passphrase[] = "hunter2";

    // Encrypt data
    size_t size = 10*BLOCKSIZE + 5;
    uint8_t * data = (uint8_t *) malloc(size);
    uint8_t reference[size];
    memset(data, 0xab, size);
    memcpy(reference, data, size);

    print_array(data, size);
    aes_encrypt(&data, &size, passphrase, aes_mode, key_size);
    print_array(data, size);
    aes_decrypt(&data, &size, passphrase, aes_mode, key_size);
    print_array(data, size);
    
    if (memcmp(reference, data, size)) {
        printf("Fail:\n");
        printf("reference plaintext:\n");
        print_array(reference, size);
        printf("decrypted plaintext:\n");
        print_array(data, size);
    } else {
        printf("Success.\n");
    }

    // Encrypt a file
    aes_encrypt_file("./images/in.jpg", "out.jpg.aes", passphrase, aes_mode, key_size);
    aes_decrypt_file("out.jpg.aes", "out.jpg", passphrase, aes_mode, key_size);
    
    return 0;    
}
#endif

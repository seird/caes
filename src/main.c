#include <time.h>

#include "aes.h"


#if (!defined(TEST) && !defined(SHARED) && !defined(BENCHMARK))


static void
print_array(uint8_t * data, size_t size)
{
    for (size_t i=0; i<size; ++i) {
        printf("%02x ", data[i]);
    } printf("\n");
}


int
main(void)
{
    srand(time(NULL));

    Mode_t aes_mode = AES_CTR;
    KeySize_t key_size = AES_256;
    char passphrase[] = "hunter2";

    // Encrypt data
    Salt_t salt;
    size_t size = 2*BLOCKSIZE+3;
    uint8_t data[size];
    uint8_t reference[size];
    memset(data, 0xab, size);
    memcpy(reference, data, size);

    aes_encrypt(data, size, passphrase, &salt, aes_mode, key_size);
    aes_decrypt(data, size, passphrase, &salt, aes_mode, key_size);

    free(salt);

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

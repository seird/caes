#include "tests.h"
#include "../src/aes.h"


#define F_IN "test_file_input.bytes"
#define F_ENCRYPTED "test_file_encrypted.bytes"
#define F_DECRYPTED "test_file_decrypted.bytes"

#define DATA_SIZE 1024+1


MU_TEST(test_file)
{
    // Write bytes to the input file
    FILE * fp_in;
    MU_CHECK((fp_in = fopen(F_IN, "wb")) != NULL);
    if (fp_in == NULL) return;
    for (int i=0; i<DATA_SIZE; ++i) {
        uint8_t b = (uint8_t) i;
        fwrite(&b, 1, 1, fp_in);
    }
    fclose(fp_in);

    // Encrypt the input file
    aes_encrypt_file(F_IN, F_ENCRYPTED, "hunter2", AES_CTR, AES_256);

    // Check if the encrypted file has been created by aes_encrypt_file
    FILE * fp_encrypted;
    MU_CHECK((fp_encrypted = fopen(F_ENCRYPTED, "rb")) != NULL);
    if (fp_encrypted == NULL) return;
    fclose(fp_encrypted);

    // Decrypt the encrypted file
    aes_decrypt_file(F_ENCRYPTED, F_DECRYPTED, "hunter2", AES_CTR, AES_256);

    // Check if the decrypted file has been created by aes_decrypt_file
    FILE * fp_decrypted;
    MU_CHECK((fp_decrypted = fopen(F_DECRYPTED, "rb")) != NULL);
    if (fp_decrypted == NULL) return;

    // Compare the encrypted data with the original data
    fp_in = fopen(F_IN, "rb");
    uint8_t * data_in = (uint8_t *) malloc(DATA_SIZE);
    uint8_t * data_decrypted = (uint8_t *) malloc(DATA_SIZE);
    fread(data_in, 1, DATA_SIZE, fp_in);
    fread(data_decrypted, 1, DATA_SIZE, fp_decrypted);

    MU_CHECK(memcmp(data_in, data_decrypted, DATA_SIZE) == 0);
    for (int i=0; i<DATA_SIZE; ++i) {
        MU_CHECK(data_decrypted[i] == (uint8_t)i);
    }

    // Clean up
    fclose(fp_in);
    fclose(fp_decrypted);
}


MU_TEST(test_file_incorrect_pass)
{
    // Write bytes to the input file
    FILE * fp_in;
    MU_CHECK((fp_in = fopen(F_IN, "wb")) != NULL);
    if (fp_in == NULL) return;
    for (int i=0; i<DATA_SIZE; ++i) {
        uint8_t b = (uint8_t) i;
        fwrite(&b, 1, 1, fp_in);
    }
    fclose(fp_in);

    // Encrypt the input file
    aes_encrypt_file(F_IN, F_ENCRYPTED, "hunter2", AES_CTR, AES_256);

    // Check if the encrypted file has been created by aes_encrypt_file
    FILE * fp_encrypted;
    MU_CHECK((fp_encrypted = fopen(F_ENCRYPTED, "rb")) != NULL);
    if (fp_encrypted == NULL) return;
    fclose(fp_encrypted);

    // Decrypt the encrypted file
    aes_decrypt_file(F_ENCRYPTED, F_DECRYPTED, "hunter3", AES_CTR, AES_256);

    // Check if the decrypted file has been created by aes_decrypt_file
    FILE * fp_decrypted;
    MU_CHECK((fp_decrypted = fopen(F_DECRYPTED, "rb")) != NULL);
    if (fp_decrypted == NULL) return;

    // Compare the encrypted data with the original data
    fp_in = fopen(F_IN, "rb");
    uint8_t * data_in = (uint8_t *) malloc(DATA_SIZE);
    uint8_t * data_decrypted = (uint8_t *) malloc(DATA_SIZE);
    fread(data_in, 1, DATA_SIZE, fp_in);
    fread(data_decrypted, 1, DATA_SIZE, fp_decrypted);

    MU_CHECK(memcmp(data_in, data_decrypted, DATA_SIZE) != 0);

    // Clean up
    fclose(fp_in);
    fclose(fp_decrypted);
}

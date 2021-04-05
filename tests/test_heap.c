#include "tests.h"
#include "../src/aes.h"


#define F_IN "test_file_input.bytes"
#define F_ENCRYPTED "test_file_encrypted.bytes"
#define F_DECRYPTED "test_file_decrypted.bytes"

#define DATA_SIZE 1024+1


MU_TEST(test_heap)
{
    // Write bytes to input
    uint8_t * data = (uint8_t *) malloc(DATA_SIZE);
    MU_CHECK(data != NULL);
    if (data == NULL) return;
    for (int i=0; i<DATA_SIZE; ++i) {
        data[i] = (uint8_t) i;
    }

    // Create a reference copy (the bytes are encrypted/decrypted in-place)
    uint8_t * data_reference = (uint8_t *) malloc(DATA_SIZE);
    MU_CHECK(data_reference != NULL);
    if (data_reference == NULL) return;
    memcpy(data_reference, data, DATA_SIZE);

    // Encrypt the input data
    size_t size = DATA_SIZE;
    aes_encrypt(&data, &size, "hunter2", AES_CTR, AES_256);
    MU_CHECK(memcmp(data, data_reference, DATA_SIZE) != 0);

    // Decrypt the data
    aes_decrypt(&data, &size, "hunter2", AES_CTR, AES_256);
    MU_CHECK(size == DATA_SIZE);
    MU_CHECK(memcmp(data, data_reference, DATA_SIZE) == 0);

    // Clean up
    free(data);
    free(data_reference);
}


MU_TEST(test_heap_incorrect_pass)
{
    // Write bytes to input
    uint8_t * data = (uint8_t *) malloc(DATA_SIZE);
    MU_CHECK(data != NULL);
    if (data == NULL) return;
    for (int i=0; i<DATA_SIZE; ++i) {
        data[i] = (uint8_t) i;
    }

    // Create a reference copy (the bytes are encrypted/decrypted in-place)
    uint8_t * data_reference = (uint8_t *) malloc(DATA_SIZE);
    MU_CHECK(data_reference != NULL);
    if (data_reference == NULL) return;
    memcpy(data_reference, data, DATA_SIZE);

    // Encrypt the input data
    size_t size = DATA_SIZE;
    aes_encrypt(&data, &size, "hunter2", AES_CTR, AES_256);
    MU_CHECK(memcmp(data, data_reference, DATA_SIZE) != 0);

    // Decrypt the data
    aes_decrypt(&data, &size, "hunter3", AES_CTR, AES_256); // differenct decryption password
    MU_CHECK(size == DATA_SIZE);
    MU_CHECK(memcmp(data, data_reference, DATA_SIZE) != 0);

    // Clean up
    free(data);
    free(data_reference);
}

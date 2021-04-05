#ifndef __TESTS_H__
#define __TESTS_H__


#include "minunit.h"


MU_TEST(test_aes_block);

MU_TEST(test_aes_ctr_128_encrypt);
MU_TEST(test_aes_ctr_128_decrypt);
MU_TEST(test_aes_ecb_128_encrypt);
MU_TEST(test_aes_ecb_128_decrypt);
MU_TEST(test_aes_cfb_128_encrypt);
MU_TEST(test_aes_cfb_128_decrypt);
MU_TEST(test_aes_ofb_128_encrypt);
MU_TEST(test_aes_ofb_128_decrypt);
MU_TEST(test_aes_cbc_128_encrypt);
MU_TEST(test_aes_cbc_128_decrypt);

MU_TEST(test_aes_ctr_192_encrypt);
MU_TEST(test_aes_ctr_192_decrypt);
MU_TEST(test_aes_ecb_192_encrypt);
MU_TEST(test_aes_ecb_192_decrypt);
MU_TEST(test_aes_cfb_192_encrypt);
MU_TEST(test_aes_cfb_192_decrypt);
MU_TEST(test_aes_ofb_192_encrypt);
MU_TEST(test_aes_ofb_192_decrypt);
MU_TEST(test_aes_cbc_192_encrypt);
MU_TEST(test_aes_cbc_192_decrypt);

MU_TEST(test_aes_ctr_256_encrypt);
MU_TEST(test_aes_ctr_256_decrypt);
MU_TEST(test_aes_ecb_256_encrypt);
MU_TEST(test_aes_ecb_256_decrypt);
MU_TEST(test_aes_cfb_256_encrypt);
MU_TEST(test_aes_cfb_256_decrypt);
MU_TEST(test_aes_ofb_256_encrypt);
MU_TEST(test_aes_ofb_256_decrypt);
MU_TEST(test_aes_cbc_256_encrypt);
MU_TEST(test_aes_cbc_256_decrypt);

MU_TEST(test_file);
MU_TEST(test_file_incorrect_pass);
MU_TEST(test_heap);
MU_TEST(test_heap_incorrect_pass);

#endif
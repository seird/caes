#ifndef __TESTS_H__
#define __TESTS_H__


#include "minunit.h"


MU_TEST(test_aes_block);
MU_TEST(test_aes_SubBytes);
MU_TEST(test_aes_ShiftRows);
MU_TEST(test_aes_MixColumns);

MU_TEST(test_aesv_block);

MU_TEST(test_aesv_ctr_128_encrypt);
MU_TEST(test_aesv_ctr_128_decrypt);
MU_TEST(test_aesv_ecb_128_encrypt);
MU_TEST(test_aesv_ecb_128_decrypt);
MU_TEST(test_aesv_cfb_128_encrypt);
MU_TEST(test_aesv_cfb_128_decrypt);
MU_TEST(test_aesv_ofb_128_encrypt);
MU_TEST(test_aesv_ofb_128_decrypt);
MU_TEST(test_aesv_cbc_128_encrypt);
MU_TEST(test_aesv_cbc_128_decrypt);

MU_TEST(test_aesv_ctr_192_encrypt);
MU_TEST(test_aesv_ctr_192_decrypt);
MU_TEST(test_aesv_ecb_192_encrypt);
MU_TEST(test_aesv_ecb_192_decrypt);
MU_TEST(test_aesv_cfb_192_encrypt);
MU_TEST(test_aesv_cfb_192_decrypt);
MU_TEST(test_aesv_ofb_192_encrypt);
MU_TEST(test_aesv_ofb_192_decrypt);
MU_TEST(test_aesv_cbc_192_encrypt);
MU_TEST(test_aesv_cbc_192_decrypt);

MU_TEST(test_aesv_ctr_256_encrypt);
MU_TEST(test_aesv_ctr_256_decrypt);
MU_TEST(test_aesv_ecb_256_encrypt);
MU_TEST(test_aesv_ecb_256_decrypt);
MU_TEST(test_aesv_cfb_256_encrypt);
MU_TEST(test_aesv_cfb_256_decrypt);
MU_TEST(test_aesv_ofb_256_encrypt);
MU_TEST(test_aesv_ofb_256_decrypt);
MU_TEST(test_aesv_cbc_256_encrypt);
MU_TEST(test_aesv_cbc_256_decrypt);

#endif
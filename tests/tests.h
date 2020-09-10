#ifndef __TESTS_H__
#define __TESTS_H__


#include "minunit.h"


MU_TEST(test_aes_block);
MU_TEST(test_aes_SubBytes);
MU_TEST(test_aes_ShiftRows);
MU_TEST(test_aes_MixColumns);

MU_TEST(test_aesv_block);

MU_TEST(test_aesv_ctr_encrypt);
MU_TEST(test_aesv_ctr_decrypt);
MU_TEST(test_aesv_ecb_encrypt);
MU_TEST(test_aesv_ecb_decrypt);
MU_TEST(test_aesv_cfb_encrypt);
MU_TEST(test_aesv_cfb_decrypt);
MU_TEST(test_aesv_ofb_encrypt);
MU_TEST(test_aesv_ofb_decrypt);
MU_TEST(test_aesv_cbc_encrypt);
MU_TEST(test_aesv_cbc_decrypt);


#endif
#include "tests.h"


int tests_run = 0;
int tests_failed = 0;
int tests_result = 0;


static void
ALL_TESTS()
{
    MU_RUN_TEST(test_aes_block);
    MU_RUN_TEST(test_aes_SubBytes);
    MU_RUN_TEST(test_aes_ShiftRows);
    MU_RUN_TEST(test_aes_MixColumns);

    MU_RUN_TEST(test_aesv_block);

    MU_RUN_TEST(test_aesv_ctr_128_encrypt);
    MU_RUN_TEST(test_aesv_ctr_128_decrypt);
    MU_RUN_TEST(test_aesv_ecb_128_encrypt);
    MU_RUN_TEST(test_aesv_ecb_128_decrypt);
    MU_RUN_TEST(test_aesv_cfb_128_encrypt);
    MU_RUN_TEST(test_aesv_cfb_128_decrypt);
    MU_RUN_TEST(test_aesv_ofb_128_encrypt);
    MU_RUN_TEST(test_aesv_ofb_128_decrypt);
    MU_RUN_TEST(test_aesv_cbc_128_encrypt);
    MU_RUN_TEST(test_aesv_cbc_128_decrypt);

    MU_RUN_TEST(test_aesv_ctr_192_encrypt);
    MU_RUN_TEST(test_aesv_ctr_192_decrypt);
    MU_RUN_TEST(test_aesv_ecb_192_encrypt);
    MU_RUN_TEST(test_aesv_ecb_192_decrypt);
    MU_RUN_TEST(test_aesv_cfb_192_encrypt);
    MU_RUN_TEST(test_aesv_cfb_192_decrypt);
    MU_RUN_TEST(test_aesv_ofb_192_encrypt);
    MU_RUN_TEST(test_aesv_ofb_192_decrypt);
    MU_RUN_TEST(test_aesv_cbc_192_encrypt);
    MU_RUN_TEST(test_aesv_cbc_192_decrypt);
    
    MU_RUN_TEST(test_aesv_ctr_256_encrypt);
    MU_RUN_TEST(test_aesv_ctr_256_decrypt);
    MU_RUN_TEST(test_aesv_ecb_256_encrypt);
    MU_RUN_TEST(test_aesv_ecb_256_decrypt);
    MU_RUN_TEST(test_aesv_cfb_256_encrypt);
    MU_RUN_TEST(test_aesv_cfb_256_decrypt);
    MU_RUN_TEST(test_aesv_ofb_256_encrypt);
    MU_RUN_TEST(test_aesv_ofb_256_decrypt);
    MU_RUN_TEST(test_aesv_cbc_256_encrypt);
    MU_RUN_TEST(test_aesv_cbc_256_decrypt);
}

int
main(void)
{
    ALL_TESTS();

    MU_STATS();

    return tests_failed != 0;
}

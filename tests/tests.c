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

    MU_RUN_TEST(test_aesv_ctr_encrypt);
    MU_RUN_TEST(test_aesv_ctr_decrypt);
    MU_RUN_TEST(test_aesv_ecb_encrypt);
    MU_RUN_TEST(test_aesv_ecb_decrypt);
    MU_RUN_TEST(test_aesv_cfb_encrypt);
    MU_RUN_TEST(test_aesv_cfb_decrypt);
    MU_RUN_TEST(test_aesv_ofb_encrypt);
    MU_RUN_TEST(test_aesv_ofb_decrypt);
    MU_RUN_TEST(test_aesv_cbc_encrypt);
    MU_RUN_TEST(test_aesv_cbc_decrypt);
}

int
main(void)
{
    ALL_TESTS();

    MU_STATS();

    return tests_failed != 0;
}

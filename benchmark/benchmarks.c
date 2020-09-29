#include "benchmarks.h"


uint8_t * data = NULL;


int
main(void)
{
    // allocate the data
    data = (uint8_t *) malloc(DATASIZE);

    int num_runs = 5;

    printf("\n=================================================\nBenchmarking ...\n");
    printf("\tNumber of runs     = %20d\n", num_runs);
    putchar('\n');

    printf("\n===========================================================\n");
    printf("AES BLOCKS ...");
    printf("\n===========================================================\n");
    
    BENCH_RUN_DATA(bench_aes_intrinsic_block_128_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_intrinsic_block_128_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_intrinsic_block_192_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_intrinsic_block_192_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_intrinsic_block_256_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_intrinsic_block_256_decrypt, num_runs);

    printf("\n===========================================================\n");
    printf("AES MODES ...");
    printf("\n===========================================================\n");

    BENCH_RUN_DATA(bench_aes_ctr_128_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ctr_128_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cfb_128_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cfb_128_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ofb_128_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ofb_128_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ecb_128_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ecb_128_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cbc_128_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cbc_128_decrypt, num_runs);

    BENCH_RUN_DATA(bench_aes_ctr_192_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ctr_192_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cfb_192_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cfb_192_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ofb_192_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ofb_192_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ecb_192_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ecb_192_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cbc_192_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cbc_192_decrypt, num_runs);

    BENCH_RUN_DATA(bench_aes_ctr_256_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ctr_256_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cfb_256_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cfb_256_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ofb_256_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ofb_256_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ecb_256_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_ecb_256_decrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cbc_256_encrypt, num_runs);
    BENCH_RUN_DATA(bench_aes_cbc_256_decrypt, num_runs);

    free(data);

    return 0;
}

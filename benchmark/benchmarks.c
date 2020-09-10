#include "benchmarks.h"


int
main(void)
{
    int num_runs = 10;

    printf("\n=================================================\nBenchmarking ...\n");
    printf("\tNumber of runs     = %20d\n", num_runs);
    putchar('\n');

    BENCH_RUN(bench_aes_block_encrypt, num_runs);
    BENCH_RUN(bench_aes_block_decrypt, num_runs);

    BENCH_RUN(bench_aesvi_intrinsic_block_encrypt, num_runs);
    BENCH_RUN(bench_aesvi_intrinsic_block_decrypt, num_runs);

    printf("\n===========================================================\n");
    printf("AES MODES ...");
    printf("\n===========================================================\n");

    BENCH_RUN(bench_aes_ctr_encrypt, num_runs);
    BENCH_RUN(bench_aes_ctr_decrypt, num_runs);
    BENCH_RUN(bench_aes_cfb_encrypt, num_runs);
    BENCH_RUN(bench_aes_cfb_decrypt, num_runs);
    BENCH_RUN(bench_aes_ofb_encrypt, num_runs);
    BENCH_RUN(bench_aes_ofb_decrypt, num_runs);
    BENCH_RUN(bench_aes_ecb_encrypt, num_runs);
    BENCH_RUN(bench_aes_ecb_decrypt, num_runs);
    BENCH_RUN(bench_aes_cbc_encrypt, num_runs);
    BENCH_RUN(bench_aes_cbc_decrypt, num_runs);

    return 0;
}

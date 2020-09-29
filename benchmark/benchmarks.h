#ifndef __BENCHMARKS_H__
#define __BENCHMARKS_H__


#include <stdint.h>
#include <stdlib.h>

#include "benchmark.h"

#define DATASIZE (16*1000*1000)
extern uint8_t * data;


#define BENCH_RUN_DATA(function, iterations) do {\
    float time_start = (float) clock()/CLOCKS_PER_SEC;\
    for (int timeit_i=0; timeit_i < iterations; ++timeit_i) {\
        function();\
    }\
    float time_elapsed = (float) clock()/CLOCKS_PER_SEC - time_start;\
    printf("%s\n\t%10f seconds per run [%f seconds total] [%4.0f MB/s]\n\n", #function, time_elapsed/iterations, time_elapsed, (DATASIZE/1000000)/(time_elapsed/iterations));\
} while (0)



BENCH_FUNC(bench_aes_intrinsic_block_128_encrypt);
BENCH_FUNC(bench_aes_intrinsic_block_128_decrypt);
BENCH_FUNC(bench_aes_intrinsic_block_192_encrypt);
BENCH_FUNC(bench_aes_intrinsic_block_192_decrypt);
BENCH_FUNC(bench_aes_intrinsic_block_256_encrypt);
BENCH_FUNC(bench_aes_intrinsic_block_256_decrypt);

BENCH_FUNC(bench_aes_ctr_128_encrypt);
BENCH_FUNC(bench_aes_ctr_128_decrypt);
BENCH_FUNC(bench_aes_cfb_128_encrypt);
BENCH_FUNC(bench_aes_cfb_128_decrypt);
BENCH_FUNC(bench_aes_ofb_128_encrypt);
BENCH_FUNC(bench_aes_ofb_128_decrypt);
BENCH_FUNC(bench_aes_ecb_128_encrypt);
BENCH_FUNC(bench_aes_ecb_128_decrypt);
BENCH_FUNC(bench_aes_cbc_128_encrypt);
BENCH_FUNC(bench_aes_cbc_128_decrypt);

BENCH_FUNC(bench_aes_ctr_192_encrypt);
BENCH_FUNC(bench_aes_ctr_192_decrypt);
BENCH_FUNC(bench_aes_cfb_192_encrypt);
BENCH_FUNC(bench_aes_cfb_192_decrypt);
BENCH_FUNC(bench_aes_ofb_192_encrypt);
BENCH_FUNC(bench_aes_ofb_192_decrypt);
BENCH_FUNC(bench_aes_ecb_192_encrypt);
BENCH_FUNC(bench_aes_ecb_192_decrypt);
BENCH_FUNC(bench_aes_cbc_192_encrypt);
BENCH_FUNC(bench_aes_cbc_192_decrypt);

BENCH_FUNC(bench_aes_ctr_256_encrypt);
BENCH_FUNC(bench_aes_ctr_256_decrypt);
BENCH_FUNC(bench_aes_cfb_256_encrypt);
BENCH_FUNC(bench_aes_cfb_256_decrypt);
BENCH_FUNC(bench_aes_ofb_256_encrypt);
BENCH_FUNC(bench_aes_ofb_256_decrypt);
BENCH_FUNC(bench_aes_ecb_256_encrypt);
BENCH_FUNC(bench_aes_ecb_256_decrypt);
BENCH_FUNC(bench_aes_cbc_256_encrypt);
BENCH_FUNC(bench_aes_cbc_256_decrypt);

#endif

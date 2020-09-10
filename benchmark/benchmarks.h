#ifndef __BENCHMARKS_H__
#define __BENCHMARKS_H__


#include "benchmark.h"


BENCH_FUNC(bench_aes_block_encrypt);
BENCH_FUNC(bench_aes_block_decrypt);

BENCH_FUNC(bench_aesvi_intrinsic_block_encrypt);
BENCH_FUNC(bench_aesvi_intrinsic_block_decrypt);

BENCH_FUNC(bench_aes_ctr_encrypt);
BENCH_FUNC(bench_aes_ctr_decrypt);
BENCH_FUNC(bench_aes_cfb_encrypt);
BENCH_FUNC(bench_aes_cfb_decrypt);
BENCH_FUNC(bench_aes_ofb_encrypt);
BENCH_FUNC(bench_aes_ofb_decrypt);
BENCH_FUNC(bench_aes_ecb_encrypt);
BENCH_FUNC(bench_aes_ecb_decrypt);
BENCH_FUNC(bench_aes_cbc_encrypt);
BENCH_FUNC(bench_aes_cbc_decrypt);


#endif

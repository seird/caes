#ifndef __BENCHMARKS_H__
#define __BENCHMARKS_H__


#include "benchmark.h"


BENCH_FUNC(bench_aes_block_encrypt);
BENCH_FUNC(bench_aes_block_decrypt);

BENCH_FUNC(bench_aesvi_intrinsic_block_128_encrypt);
BENCH_FUNC(bench_aesvi_intrinsic_block_128_decrypt);
BENCH_FUNC(bench_aesvi_intrinsic_block_192_encrypt);
BENCH_FUNC(bench_aesvi_intrinsic_block_192_decrypt);
BENCH_FUNC(bench_aesvi_intrinsic_block_256_encrypt);
BENCH_FUNC(bench_aesvi_intrinsic_block_256_decrypt);

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

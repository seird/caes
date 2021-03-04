CC = gcc
CFLAGS_DEBUG = -g -Wall -Wextra -mavx2 -maes -pthread -D_FILE_OFFSET_BITS=64 #-shared
CFLAGS_RELEASE = -O3 -Wall -Wextra -mavx2 -maes -pthread -D_FILE_OFFSET_BITS=64 #-shared

SRC = \
	src/aes.c \
	src/main.c \
	src/modes.c \
	src/argon2/argon2.c \
	src/argon2/core.c \
	src/argon2/blake2/blake2b.c \
	src/argon2/thread.c \
	src/argon2/encoding.c \
	src/argon2/opt.c \

SRC_TEST = \
	$(SRC) \
	tests/tests.c \
	tests/test_aes.c \
	tests/test_aes_cbc.c \
	tests/test_aes_cfb.c \
	tests/test_aes_ctr.c \
	tests/test_aes_ecb.c \
	tests/test_aes_ofb.c \

SRC_BENCH = \
	$(SRC) \
	benchmark/benchmarks.c \
	benchmark/bench_aes_block.c \
	benchmark/bench_aes_modes_128.c \
	benchmark/bench_aes_modes_192.c \
	benchmark/bench_aes_modes_256.c \


build: 
	$(CC) $(CFLAGS_RELEASE) $(SRC) -o aes.exe

lib:
	$(CC) $(CFLAGS_RELEASE) -shared -fPIC $(SRC) -o aes.dll

run: build
	./aes.exe

debug:
	$(CC) $(CFLAGS_DEBUG) $(SRC) -o a_debug.exe 

profile: debug
	valgrind --tool=callgrind ./a_debug.exe

memcheck: debug
	valgrind --leak-check=full --show-leak-kinds=all ./a_debug.exe -e -i makefile -o makefile.aes hunter2

cache: build
	valgrind --tool=cachegrind ./aes.exe
	#cg_annotate cachegrind.out.{PID}

test:
	$(CC) $(CFLAGS_RELEASE) -DTEST $(SRC_TEST) -o test.exe
	./test.exe

bench:
	$(CC) $(CFLAGS_RELEASE) -DBENCHMARK $(SRC_BENCH) -o benchmark.exe
	./benchmark.exe

clean:
	rm --force *.exe
	rm --force *.out.*
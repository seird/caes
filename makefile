CC = gcc
CFLAGS_DEBUG = -g -Wall -Wextra -Wshadow -mavx2 -maes -pthread -D_FILE_OFFSET_BITS=64 #-shared
CFLAGS_RELEASE = -O3 -Wall -Wextra -Wshadow -mavx2 -maes -pthread -D_FILE_OFFSET_BITS=64 #-shared
CFLAGS_TEST = -O0 -Wall -Wextra -Wshadow -mavx2 -maes -pthread -D_FILE_OFFSET_BITS=64 -fprofile-arcs -ftest-coverage

SRC = \
	$(wildcard src/*.c) \
	src/argon2/argon2.c \
	src/argon2/core.c \
	src/argon2/blake2/blake2b.c \
	src/argon2/thread.c \
	src/argon2/encoding.c \
	src/argon2/opt.c \

SRC_TEST = \
	$(SRC) \
	$(wildcard tests/*.c) \

SRC_BENCH = \
	$(SRC) \
	$(wildcard benchmark/*.c) \


ifeq ($(OS),Windows_NT)
	PLATFORM_OS = WINDOWS
else
	UNAMEOS = $(shell uname)
	ifeq ($(UNAMEOS),Linux)
		PLATFORM_OS = LINUX
	endif
	ifeq ($(UNAMEOS),FreeBSD)
		PLATFORM_OS = BSD
	endif
	ifeq ($(UNAMEOS),OpenBSD)
		PLATFORM_OS = BSD
	endif
	ifeq ($(UNAMEOS),NetBSD)
		PLATFORM_OS = BSD
	endif
	ifeq ($(UNAMEOS),DragonFly)
		PLATFORM_OS = BSD
	endif
	ifeq ($(UNAMEOS),Darwin)
		PLATFORM_OS = OSX
	endif
endif


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
	$(CC) $(CFLAGS_TEST) -DTEST $(SRC_TEST) -o test.exe
	./test.exe
	gcovr -e "src/argon2/*" -e "tests/*" --xml-pretty --exclude-unreachable-branches --print-summary -o coverage.xml

coverage_html:
	$(CC) $(CFLAGS_TEST) -DTEST $(SRC_TEST) -o test.exe
	./test.exe
	gcovr -e "src/argon2/*" -e "tests/*" --html --html-details --exclude-unreachable-branches --print-summary -o coverage.html

bench:
	$(CC) $(CFLAGS_RELEASE) -DBENCHMARK $(SRC_BENCH) -o benchmark.exe
	./benchmark.exe

clean:
ifeq ($(PLATFORM_OS),WINDOWS)
	del *.o /s
	del *.exe /s
	del *.dll /s
	del *.out.* /s
	del *.so /s
	del *.a /s
	del *.gcda /s
	del *.gcno /s
	del *.css /s
	del *.html /s
else
	rm -fv *.o *.exe *.dll *.so *.out.* *.a *.gcda *.gcno *.css *.html
endif

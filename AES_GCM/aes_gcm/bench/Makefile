
CC = gcc
CFLAGS = -maes -msse4 -mpclmul -O2 -g
CLINK = -lcpucycles

C_REF_DIR = c_ref
C_REF_SRCS = $(C_REF_DIR)/*.c
C_AESNI_DIR = c_aesni
C_AESNI_SRCS = $(filter-out $(C_AESNI_DIR)/gcm_main.c, $(wildcard $(C_AESNI_DIR)/*.c))
JASMIN_SRC = ../aes_128_gcm.s
JASMIN_SYSCALL = /home/hefner/jasmin/compiler/syscall/jasmin_syscall.o

BENCH_SRCS = *.c
BENCH_SRCS += $(JASMIN_SYSCALL)

bench1:
	$(CC) $(CFLAGS) $(BENCH_SRCS) $(C_REF_SRCS) $(C_AESNI_SRCS) $(JASMIN_SRC) $(CLINK) -o bench -DBENCH1

bench2:
	$(CC) $(CFLAGS) $(BENCH_SRCS) $(C_REF_SRCS) $(C_AESNI_SRCS) $(JASMIN_SRC) $(CLINK) -o bench -DBENCH2

clean:
	rm -f bench

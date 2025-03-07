TOP = /home/hefner/jasmin.local/NIST_P384
SRC = $(TOP)/src

JASMINC = /home/hefner/jasmin/compiler/jasminc
JINCLUDE = -I NIST_P384:$(SRC)
JASMIN := $(JASMINC) $(JINCLUDE)
JASMIN_SYSCALL = /home/hefner/jasmin/compiler/syscall/jasmin_syscall.o

test: p384.s
	gcc -Wall -z noexecstack -g $(SRC)/p384.s $(JASMIN_SYSCALL) test.c -o test

test_fixed_key: p384.s
	gcc -Wall -z noexecstack -g $(SRC)/p384.s $(JASMIN_SYSCALL) test_fixed_key.c -o test_fixed_key

p384.s:
	$(JASMIN) $(SRC)/p384.jazz -o $(SRC)/p384.s

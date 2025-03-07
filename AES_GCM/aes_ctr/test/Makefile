
JASMINC = /home/hefner/jasmin/compiler/jasminc

.PHONY: test aes_128_ctr.s aes_192_ctr.s aes_256_ctr.s

all: aes_128_ctr.s aes_192_ctr.s aes_256_ctr.s test

test:
	gcc -Wall -z noexecstack -g ../aes_128_ctr.s ../aes_192_ctr.s ../aes_256_ctr.s test.c -o test -DTEST$(t)

aes_128_ctr.s:
	$(JASMINC) ../aes_128_ctr.jazz -o ../aes_128_ctr.s
	sed -i 's/-128/128/' ../aes_128_ctr.s

aes_192_ctr.s:
	$(JASMINC) ../aes_192_ctr.jazz -o ../aes_192_ctr.s
	sed -i 's/vshufps/vshufpd/' ../aes_192_ctr.s
	sed -i 's/-128/128/' ../aes_192_ctr.s

aes_256_ctr.s:
	$(JASMINC) ../aes_256_ctr.jazz -o ../aes_256_ctr.s

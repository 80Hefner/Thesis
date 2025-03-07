
JASMINC = /home/hefner/jasmin/compiler/jasminc

.PHONY: test_encrypt test_decrypt aes_128_gcm.s aes_192_gcm.s aes_256_gcm.s

all: aes_128_gcm.s aes_192_gcm.s aes_256_gcm.s test_encrypt test_decrypt

tests: test_encrypt test_decrypt

test_encrypt:
	gcc -Wall -z noexecstack -g ../aes_128_gcm.s ../aes_192_gcm.s ../aes_256_gcm.s test_encrypt.c -o test_encrypt

test_decrypt:
	gcc -Wall -z noexecstack -g ../aes_128_gcm.s ../aes_192_gcm.s ../aes_256_gcm.s test_decrypt.c -o test_decrypt

aes_128_gcm.s:
	$(JASMINC) ../aes_128_gcm.jazz -o ../aes_128_gcm.s
	sed -i 's/-128/128/' ../aes_128_gcm.s

aes_192_gcm.s:
	$(JASMINC) ../aes_192_gcm.jazz -o ../aes_192_gcm.s
	# sed -i 's/vshufps/vshufpd/' ../aes_192_gcm.s
	sed -i 's/-128/128/' ../aes_192_gcm.s

aes_256_gcm.s:
	$(JASMINC) ../aes_256_gcm.jazz -o ../aes_256_gcm.s

#!/bin/bash

make aes_128_ctr.s aes_192_ctr.s aes_256_ctr.s

for i in {1..9}
do
    make test t=$i -s
    printf "Test%02d:" $i
    ./test -lprint
    printf "\n"
done

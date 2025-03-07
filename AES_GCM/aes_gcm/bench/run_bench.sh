#!/bin/bash

make bench1
# sudo chrt -f 99 ./bench
sudo nice -n -20 ./bench

make bench2
# sudo chrt -f 99 ./bench
sudo nice -n -20 ./bench

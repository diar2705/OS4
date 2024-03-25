
#! /bin/bash

NC='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PURPLE='\033[0;35m'


g++ -std=c++11 -Wno-unused-result ./hussam_tests/main3.cpp -o test_prog
./test_prog
i=0
NUM_TESTS=10

while [[ i -lt NUM_TESTS ]]
do
	./test_prog ${i}
	((i++))
done
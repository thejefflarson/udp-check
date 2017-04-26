CC ?= clang
CFLAGS ?= -fsanitize=address -Wall -Werror -g -pedantic -std=c99

udp-check: udp-check.c vendor/tweetnacl.o
vendor/tweetnacl.o: vendor/tweetnacl.c

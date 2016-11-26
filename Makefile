CC ?= clang
CFLAGS ?= -fsanitize=address -Wall -Werror -g -pedantic

udp-check: udp-check.c vendor/tweetnacl.o
vendor/tweetnacl.o: vendor/tweetnacl.c

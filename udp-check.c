#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vendor/tweetnacl.h"

// This utility does one thing and one thing well.

// It reads a curve25519 key generated from a file in the current directory
// called server.key, if none is found it generates a file with the following
// format:
//
/* +------------+------+-----+ */
/* |0           |32    |64   | */
/* +------------+------+-----+ */
/* |public key  |secret key  | */
/* +------------+------------+ */
//
// It then listens for udp packets on port 443 with the following format:
//
/* +-------------+-------+-----+-----+ */
/* |0            |32     |64   |   80| */
/* +-------------+-------+-----+-----+ */
/* |public key   |message|auth       | */
/* +-------------+-------+-----------+ */
//
// It echoes the message value verbatim if curve25519 decryption succeeds with
// the same format. Otherwise it silently drops the packet. All packets are 80
// bytes long.

typedef struct {
  uint8_t key[crypto_box_PUBLICKEYBYTES];
  uint8_t nonce[crypto_box_NONCEBYTES];
  uint8_t message[64 + crypto_box_BOXZEROBYTES];
} message_t;

typedef struct {
  uint8_t zeros[crypto_box_ZEROBYTES];
  uint8_t text[64];
} text_t;

#define keysize crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES
#define fail(msg) {   \
  perror(msg);        \
  exit(EXIT_FAILURE); \
}
int main(int argc, char **argv) {
  uint8_t key[keysize] = {0};
  int fd = open("server.key", O_RDONLY);
  // read server.key or create it
  if(fd == -1) {
    if(errno == ENOENT) {
      fd = open("server.key", O_WRONLY | O_CREAT);
      if(fd == -1) fail("could not create server.key");
      crypto_box_keypair(key, key + crypto_box_PUBLICKEYBYTES);
      write(fd, key, keysize);
      fsync(fd);
    } else {
      fail("error reading server.key");
    }
  } else {
    ssize_t rd = read(fd, key, keysize);
    if(rd != keysize) fail("could not read server.key");
  }
  close(fd);

  struct addrinfo hints = {0}, *res;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = IPPROTO_UDP;
  char *port = "443";

  int status = getaddrinfo(NULL, port, &hints, &res);
  if(status != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    exit(EXIT_FAILURE);
  }

  int sock;
  for(struct addrinfo *p = res; p != NULL; p = p->ai_next) {
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if(sock == -1) continue;
    int yes = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1)
      fail("setsockopt");
    if(bind(sock, p->ai_addr, p->ai_addrlen) == -1) {
      close(sock);
      continue;
    }
  }

  freeaddrinfo(res);
  struct pollfd ready = {
    .fd = sock,
    .events = POLLIN,
    .revents = 0
  };

  while(1) {
    int num = poll(&ready, 1, 1000);
    if(num == -1) fail("poll returned an error.");
    if(num == 1) {
      struct sockaddr_storage addr;
      socklen_t size = sizeof(addr);
      message_t mess = {0};
      ssize_t read = recvfrom(sock, &mess, sizeof(mess), 0,
                              (struct sockaddr *)&addr, &size);
      if(read != sizeof(mess)) {
        continue;
      }

      // TK decrypt and reply
    }
  }

  close(sock);
  return 0;
}

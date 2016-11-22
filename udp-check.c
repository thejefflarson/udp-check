#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

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

int main(int argc, char **argv) {
  char key[64] = {0};
  // TK read server.key or create it



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

  int fd;
  for(struct addrinfo *p = res; p != NULL; p = p->ai_next) {
    fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if(fd == -1) continue;
    int yes = 1;
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1) {
      perror("setsockopt");
      exit(EXIT_FAILURE);
    }
    if(bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(fd);
      continue;
    }
  }



  freeaddrinfo(res);

  while(1) {
    // TK do the shit
  }

  close(fd);
  return 0;
}

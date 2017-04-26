#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <memory.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vendor/tweetnacl.h"

static int fd = -1;
void randombytes(uint8_t *x, uint64_t xlen) {
  int i;
  if(fd == -1) {
    for(;;) {
      fd = open("/dev/urandom", O_RDONLY);
      if (fd != -1) break;

      sleep(1);
    }
  }

  while(xlen > 0) {
    if(xlen < 1048576) i = xlen; else i = 1048576;

    i = read(fd,x,i);
    if(i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
}

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
  uint8_t text[64 + crypto_box_BOXZEROBYTES];
} message_t;

typedef struct {
  uint8_t zeros[crypto_box_ZEROBYTES];
  uint8_t text[64];
} plain_t;

typedef struct {
  uint8_t zeros[crypto_box_BOXZEROBYTES];
  uint8_t text[64 + crypto_box_BOXZEROBYTES];
} secret_t;

typedef struct {
  uint8_t pk[crypto_box_PUBLICKEYBYTES];
  uint8_t sk[crypto_box_SECRETKEYBYTES];
} keypair_t;

#define fail(msg) {      \
  syslog(LOG_CRIT, msg); \
  perror(msg);           \
  exit(EXIT_FAILURE);    \
}

// from beej
static void log_warn(const struct sockaddr_storage *sa,
                     const char *logline) {
  char s[INET6_ADDRSTRLEN] = {0};
  switch(((const struct sockaddr *)sa)->sa_family) {
  case AF_INET:
    inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
              s, INET6_ADDRSTRLEN);
    break;
  case AF_INET6:
    inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
              s, INET6_ADDRSTRLEN);
    break;
  default:
    strncpy(s, "Unknown AF", INET6_ADDRSTRLEN);

  }
  syslog(LOG_WARNING, "[%s] %s", s, logline);
}

int main(int argc, char **argv) {
  keypair_t key = {{0}, {0}};
  int kfd = open("server.key", O_RDONLY);
  // read server.key or create it
  if(kfd == -1) {
    if(errno == ENOENT) {
      kfd = open("server.key", O_WRONLY | O_CREAT | O_SYNC, S_IRUSR | S_IWUSR);
      if(kfd == -1) fail("could not create server.key");
      crypto_box_keypair(key.pk, key.sk);
      ssize_t rd = write(kfd, &key, sizeof(key));
      if(rd != sizeof(key)) fail("could not write to server.key");
      puts("writing file.");
    } else {
      fail("error reading server.key");
    }
  } else {
    ssize_t rd = read(kfd, &key, sizeof(key));
    if(rd != sizeof(key)) fail("could not read server.key");
  }
  close(kfd);

  struct addrinfo hints = {0}, *res;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
  hints.ai_protocol = IPPROTO_UDP;
  const char *port = "10000";

  int status = getaddrinfo(NULL, port, &hints, &res);
  if(status != 0) {
    syslog(LOG_CRIT, "getaddrinfo: %s\n", gai_strerror(status));
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
    exit(EXIT_FAILURE);
  }

  int sock = -1;
  for(struct addrinfo *p = res; p != NULL; p = p->ai_next) {
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if(sock == -1) continue;
    int yes = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1)
      fail("setsockopt");
    if(bind(sock, p->ai_addr, p->ai_addrlen) == -1) {
      close(sock);
      sock = -1;
      continue;
    }
    break;
  }
  if(sock == -1) fail("could not get a socket");
  freeaddrinfo(res);
  syslog(LOG_INFO, "Started listening on %s", port);

  while(1) {
    struct sockaddr_storage addr;
    socklen_t size = sizeof(addr);
    message_t mess = {0};
    ssize_t read = recvfrom(sock, &mess, sizeof(mess), 0,
                            (struct sockaddr *)&addr, &size);
    syslog(LOG_INFO, "Recieved a packet");
    if(read != sizeof(mess)) {
      log_warn(&addr, "Packet too short.");
      continue;
    }

    secret_t secret = {0};
    memcpy(secret.text, mess.text, sizeof(mess.text));
    plain_t plain = {0};
    int ret = crypto_box_open((uint8_t *)&plain, (uint8_t*) &secret,
                              sizeof(secret), mess.nonce, mess.key, key.sk);
    if(ret == -1) {
      log_warn(&addr, "Failed decryption.");
      continue;
    }
    memset(&secret, 0, sizeof(secret));
    memset(&mess, 0, sizeof(mess));
    memcpy(mess.key, key.pk, sizeof(mess.key));
    randombytes(mess.nonce, sizeof(mess.nonce));
    ret = crypto_box((uint8_t*) &secret, (uint8_t*) &plain,
                     sizeof(secret), mess.nonce, mess.key, key.sk);
    if(ret == -1) {
      log_warn(&addr, "Failed encryption (Should never happen!).");
      continue;
    }
    memcpy(mess.text, secret.text + crypto_box_BOXZEROBYTES,
           sizeof(mess.text));
    sendto(sock, &mess, sizeof(mess), 0, (struct sockaddr*)&addr, size);
  }
  memset(&key, 0, sizeof(key));
  close(sock);
  return 0;
}

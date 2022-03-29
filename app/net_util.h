#ifndef NET_UTIL_H
#define NET_UTIL_H

#include <stdint.h>
#include <sys/socket.h>

// print addr and port
const char *print_sockaddr(const struct sockaddr *s, socklen_t len);

#endif

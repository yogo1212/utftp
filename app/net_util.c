#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

#include "net_util.h"

const char *print_sockaddr(const struct sockaddr *s, socklen_t len)
{
	void *a;

	uint16_t port;

	if (s->sa_family == AF_INET) {
		if (len < sizeof(struct sockaddr_in))
			return NULL;

		struct sockaddr_in *sin = (struct sockaddr_in *) s;
		a = &sin->sin_addr;
		port = ntohs(sin->sin_port);
	} else if (s->sa_family == AF_INET6) {
		if (len < sizeof(struct sockaddr_in6))
			return NULL;

		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) s;
		a = &sin6->sin6_addr;
		port = ntohs(sin6->sin6_port);
	} else {
		fprintf(stderr, "unknown address family %d\n", s->sa_family);
		return NULL;
	}

	static char buf[INET6_ADDRSTRLEN + 8 + 1];

	if (!inet_ntop(s->sa_family, a, buf, sizeof(buf))) {
		fprintf(stderr, "error printing address: %s\n", strerror(errno));
		return NULL;
	}

	buf[sizeof(buf) - 1] = '\0';
	char *pos = &buf[strlen(buf)];

	ssize_t rem = sizeof(buf) - (pos - buf);
	if (snprintf(pos, rem, " : %" PRIu16, port) >= rem)
		return NULL;

	return buf;
}

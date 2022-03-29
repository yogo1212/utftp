#include "internal.h"

void utftp_internal_send_error(int fd, struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string)
{
	char buf[512];
	*((uint16_t *) buf) = htons(error_code);
	uint8_t pos = sizeof(uint16_t);

	size_t err_len = strlen(error_string);

	// truncating error message
	if (err_len >= sizeof(buf) - pos)
		err_len = sizeof(buf) - pos - 1;

	memcpy(&buf[pos], error_string, err_len);
	pos = pos + err_len;
	memset(&buf[pos], 0, sizeof(buf) - pos);

	// ignoring errors here
	sendto(fd, buf, pos + 1, 0, (struct sockaddr *) &peer, peer_len);
}

void utftp_normalise_mapped_ipv4(struct sockaddr *s, socklen_t *len)
{
	if (s->sa_family != AF_INET6)
		return;

	if (*len < sizeof(struct sockaddr_in6) || *len < sizeof(struct sockaddr_in))
		return;

	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) s;

	const uint16_t mapped_prefix[6] = { 0, 0, 0, 0, 0, 0xFFFF };
	if (memcmp(mapped_prefix, sin6->sin6_addr.s6_addr16, sizeof(mapped_prefix)) != 0)
		return;

	struct sockaddr_in6 cpy;
	memcpy(&cpy, sin6, sizeof(cpy));

	struct sockaddr_in *sin = (struct sockaddr_in *) s;
	sin->sin_family = AF_INET;
	sin->sin_port = cpy.sin6_port;

	memcpy(&sin->sin_addr, &cpy.sin6_addr.s6_addr[12], 4);
	*len = sizeof(*sin);
}

void utftp_handle_error(int fd, struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string, utftp_error_cb error_cb, void *ctx)
{
	// TODO how about error_cb overriding error_code?
	if (error_cb) {
		struct sockaddr_storage ss;
		memcpy(&ss, peer, peer_len);
		socklen_t ss_len = peer_len;
		utftp_normalise_mapped_ipv4((struct sockaddr *) &ss, &ss_len);
		error_cb((struct sockaddr *) &ss, ss_len, error_code, error_string, ctx);
	}

	if (peer && fd != -1)
		utftp_internal_send_error(fd, peer, peer_len, error_code, error_string);
}

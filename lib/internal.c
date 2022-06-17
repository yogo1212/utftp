#include "internal.h"

void utftp_internal_send_error(int fd, const struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string)
{
	char buf[512];

	char *pos = buf;
	*((uint16_t *) pos) = htons(TFTP_OP_ERROR);
	pos = pos + sizeof(uint16_t);

	*((uint16_t *) pos) = htons(error_code);
	pos = pos + sizeof(uint16_t);

	size_t err_len = strlen(error_string);

	// truncate error message
	if (err_len >= remaining(buf, sizeof(buf), pos))
		err_len = remaining(buf, sizeof(buf), pos) - 1;

	memcpy(pos, error_string, err_len);
	pos = pos + err_len;
	*pos = '\0';
	pos = pos + 1;

	// ignoring errors here
	sendto(fd, buf, (ptrdiff_t) pos - (ptrdiff_t) buf, 0, peer, peer_len);
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

static inline void call_error_cb(const struct sockaddr *peer, socklen_t peer_len, bool remote, utftp_errcode_t error_code, const char *error_string, utftp_error_cb error_cb, void *ctx)
{
	if (!error_cb)
		return;

	struct sockaddr_storage ss;

	if (peer) {
		memcpy(&ss, peer, peer_len);
		socklen_t ss_len = peer_len;
		utftp_normalise_mapped_ipv4((struct sockaddr *) &ss, &ss_len);
		peer = (struct sockaddr *) &ss;
		peer_len = ss_len;
	}

	error_cb(peer, peer_len, remote, error_code, error_string, ctx);
}

void utftp_handle_local_error(int fd, const struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string, utftp_error_cb error_cb, void *ctx)
{
	// TODO how about error_cb overriding error_code?
	call_error_cb(peer, peer_len, false, error_code, error_string, error_cb, ctx);

	if (peer && fd != -1)
		utftp_internal_send_error(fd, peer, peer_len, error_code, error_string);
}

void utftp_handle_remote_error(const struct sockaddr *peer, socklen_t peer_len, const uint8_t *buf, size_t buf_len, utftp_error_cb error_cb, void *ctx)
{
	utftp_errcode_t error_code = ntohs(*((uint16_t *) buf));

	const char *error_string = (char *) buf + sizeof(uint16_t);
	size_t len = buf_len - sizeof(uint16_t);

	if (strnlen(error_string, len) == len) {
		// TODO log message about having truncated error message
		char zt_error_buf[len + 1];
		memcpy(zt_error_buf, error_string, len);
		zt_error_buf[len] = '\0';
		error_string = zt_error_buf;
	}

	call_error_cb(peer, peer_len, true, error_code, error_string, error_cb, ctx);
}

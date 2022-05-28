#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uthash.h>

#include "internal.h"
#include "proto.h"
#include "utftp.h"

/*
 * override hash and comparison function to allow using sockaddr_storage as hash key
 * use only the address and the port, ignore all other fields
 */
#undef HASH_FUNCTION
#define HASH_FUNCTION(s,len,hashv) hash_sockaddr(s,len,&hashv)

#undef HASH_KEYCMP
#define HASH_KEYCMP(a,b,len) cmp_sockaddr(a,b,len)

static int cmp_sockaddr(const struct sockaddr_storage *a, const struct sockaddr_storage *b, size_t len)
{
	(void) len;

	if (a->ss_family != b->ss_family)
		return 1;

	switch (a->ss_family) {
	case AF_INET: ;
		const struct sockaddr_in *sin_a = (struct sockaddr_in *) a;
		const struct sockaddr_in *sin_b = (struct sockaddr_in *) b;
		if (sin_a->sin_port != sin_b->sin_port)
			return 1;

		return memcmp(&sin_a->sin_addr, &sin_b->sin_addr, sizeof(sin_a->sin_addr));

		break;
	case AF_INET6: ;
		const struct sockaddr_in6 *sin6_a = (struct sockaddr_in6 *) a;
		const struct sockaddr_in6 *sin6_b = (struct sockaddr_in6 *) b;
		if (sin6_a->sin6_port != sin6_b->sin6_port)
			return 1;

		return memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr, sizeof(sin6_a->sin6_addr));

		break;
	default:
		fprintf(stderr, "utftp: cmp_sockaddr: unknown address family: %u\n", (unsigned) a->ss_family);
		// don't know. never consider them equal
		return 1;
	}

	return 0;
}

static void hash_sockaddr(const struct sockaddr_storage *s, size_t len, unsigned *hashv)
{
	(void) len;

	unsigned addr_hashv;

	switch (s->ss_family) {
	case AF_INET: ;
		const struct sockaddr_in *sin = (struct sockaddr_in *) s;
		HASH_JEN(&sin->sin_addr, sizeof(sin->sin_addr), addr_hashv);
		*hashv = addr_hashv ^ sin->sin_port;
		break;
	case AF_INET6: ;
		const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) s;
		HASH_JEN(&sin6->sin6_addr, sizeof(sin6->sin6_addr), addr_hashv);
		// TODO only use scope_id for loopback addresses?
		*hashv = addr_hashv ^ sin6->sin6_port ^ sin6->sin6_scope_id;
		break;
	default:
		fprintf(stderr, "utftp: hash_sockaddr: unknown address family: %u\n", (unsigned) s->ss_family);
		*hashv = 1; // cmp never considers these equal. just return anything here.
	}
}

struct utftp_server {
	int fd;
	struct event *evt;
	utftp_transmission_cb receive_cb;
	utftp_transmission_cb send_cb;
	utftp_error_cb error_cb;

	// use the normalized (ipv6-ipv4 unmapped) address + port combination as the key
	utftp_transmission_t *transmissions;

	void *ctx;
};


static void delete_server_transmission(utftp_transmission_t *t, void *ctx)
{
	utftp_server_t *s = ctx;

	HASH_DEL(s->transmissions, t);
}

static void server_error_cb(const struct sockaddr *peer, socklen_t peer_len, bool remote, utftp_errcode_t error_code, const char *error_string, void *ctx)
{
	utftp_server_t *s = ctx;

	if (s->error_cb)
		s->error_cb(peer, peer_len, remote, error_code, error_string, s->ctx);
}

static void server_peer_read(utftp_server_t *s, utftp_transmission_t *t, bool timeout, bool receiving)
{
	if (timeout) {
		if (t->last_progress < time(NULL) - 300) {
			if (!t->complete)
				utftp_handle_local_error(t->fd, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "transaction timed out", s->error_cb, s->ctx);

			HASH_DEL(s->transmissions, t);
			utftp_transmission_free(t);
			return;
		}

		// TODO return values
		if (receiving)
			utftp_proto_send_ack(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block);
		else
			utftp_proto_send_block(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block, t->buf, t->block_size);

		return;
	}

	transmission_internal_cbs_t server_cbs = {
		delete_server_transmission,
		server_error_cb,
	};

	if (receiving)
		utftp_transmission_receive_cb(t, &server_cbs);
	else
		utftp_transmission_send_cb(t, &server_cbs);
}

static void server_peer_send_cb(evutil_socket_t fd, short what, void *ctx)
{
	(void) fd;

	if (what == 0)
		return;

	utftp_transmission_t *t = ctx;
	utftp_server_t *s = t->internal_ctx;

	server_peer_read(s, t, !(what & EV_READ), false);
}

static void server_peer_receive_cb(evutil_socket_t fd, short what, void *ctx)
{
	(void) fd;

	if (what == 0)
		return;

	utftp_transmission_t *t = ctx;
	utftp_server_t *s = t->internal_ctx;

	server_peer_read(s, t, !(what & EV_READ), true);
}

static void server_read_cb(evutil_socket_t fd, short what, void *ctx)
{
	(void) what;

	utftp_server_t *s = ctx;

	char buf[MAX_BLOCK_SIZE];

	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);
	ssize_t rlen = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *) &peer, &peer_len);
	if (rlen == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			utftp_handle_local_error(-1, NULL, 0, UTFTP_ERR_UNDEFINED, strerror(errno), s->error_cb, s->ctx);

		return;
	}

	utftp_normalise_mapped_ipv4((struct sockaddr *) &peer, &peer_len);

	utftp_transmission_t *t;
	HASH_FIND(hh, s->transmissions, &peer, peer_len, t);
	if (t) {
		// there already exists an transmission with this address + port combination
		return;
	}

	if (rlen < 2) {
		utftp_handle_local_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "short read", s->error_cb, s->ctx);
		return;
	}

	uint16_t op = ntohs(*((uint16_t *) buf));
	if (op != TFTP_OP_READ && op != TFTP_OP_WRITE) {
		utftp_handle_local_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_ILLEGAL_OP, sprintfa("invalid operation %04" PRIx16, op), s->error_cb, s->ctx);
		return;
	}

	const char *filename = buf + 2;

	const char *pos = utftp_proto_next_zt(filename, remaining(buf, rlen, filename));
	if (!pos) {
		utftp_handle_local_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "unterminated filename", s->error_cb, s->ctx);
		return;
	}

	const char *mode = pos + 1;
	pos = utftp_proto_next_zt(mode, remaining(buf, rlen, mode));
	if (!pos) {
		utftp_handle_local_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "unterminated mode", s->error_cb, s->ctx);
		return;
	}

	uint8_t mode_u;
	if (!utftp_proto_detect_mode(mode, &mode_u)) {
		utftp_handle_local_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, sprintfa("unknown mode \"%s\"", mode), s->error_cb, s->ctx);
		return;
	}

	pos = pos + 1;

	t = utftp_transmission_new(
		(struct sockaddr *) &peer,
		peer_len,
		server_error_cb,
		s
	);
	if (!t) {
		return;
	}

	HASH_ADD(hh, s->transmissions, peer, sizeof(t->peer), t);

	uint8_t option_mask = 0;
	size_t tsize;

	const char *option = pos;
	while ((pos = utftp_proto_next_zt(option, remaining(buf, rlen, option))) && option != pos) {
		const char *value = pos + 1;
		pos = utftp_proto_next_zt(value, remaining(buf, rlen, value));
		if (!pos)
			break;

		if (value == pos)
			break;

		// TODO 'windowsize' option
		uint8_t option_u;
		if (!utftp_proto_detect_option(option, &option_u))
			continue;

		option = pos + 1;

		char *endptr;
		unsigned long value_u = strtoul(value, &endptr, 10);
		if (!endptr || *endptr != '\0')
			continue;

		switch (option_u) {
		case OPTION_BIT_BLKSIZE:
			if (value_u > MAX_BLOCK_SIZE)
				continue;

			t->block_size = value_u;
			break;
		case OPTION_BIT_TIMEOUT:
			if (value_u > UINT8_MAX)
				continue;

			t->timeout = value_u;
			break;
		case OPTION_BIT_TSIZE:
			if (value_u > SIZE_MAX)
				continue;

			tsize = value_u;
			break;
		default:
			continue;
		}

		option_mask = option_mask | option_u;
	}

	t->data_cb = NULL;

	switch (op) {
	case TFTP_OP_READ:
		t->data_cb = s->send_cb(t, mode_u, filename, option_mask & OPTION_BIT_TSIZE ? &tsize : NULL, s->ctx);
		// TODO tsize mustn't change otherwise
		if (tsize == 0)
			option_mask = option_mask & ~OPTION_BIT_TSIZE;

		break;
	case TFTP_OP_WRITE:
		t->data_cb = s->receive_cb(t, mode_u, filename, option_mask & OPTION_BIT_TSIZE ? &tsize : NULL, s->ctx);

		break;
	}

	if (!t->data_cb) {
		if (!t->sent_error)
			utftp_internal_send_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "internal error");

		goto cleanup_t_hash;
	}

	if (!utftp_transmission_start(t, event_get_base(s->evt), op == TFTP_OP_WRITE ? server_peer_receive_cb : server_peer_send_cb)) {
		utftp_handle_local_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "couldn't start transmission", s->error_cb, s->ctx);
		goto cleanup_t_hash;
	}

	if (option_mask != 0) {
		// TODO maybe not ack tsize for write requests?
		if (!utftp_proto_send_oack(
			t->fd,
			(struct sockaddr *) &peer, peer_len,
			option_mask & OPTION_BIT_BLKSIZE ? &t->block_size : NULL,
			option_mask & OPTION_BIT_TIMEOUT ? &t->timeout : NULL,
			option_mask & OPTION_BIT_TSIZE ? &tsize : NULL)
		) {
			utftp_handle_local_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, sprintfa("failed to send oack: %s", strerror(errno)), s->error_cb, s->ctx);
			goto cleanup_t_hash;
		}
	} else {
		if (op == TFTP_OP_READ) {
			if (!utftp_transmission_fetch_next_block(t))
				goto cleanup_t_hash;

			if (!utftp_proto_send_block(t->fd, (struct sockaddr *) &peer, peer_len, t->previous_block, t->buf, t->block_size)) {
				utftp_handle_local_error(-1, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, sprintfa("failed to send first block: %s", strerror(errno)), s->error_cb, s->ctx);
				goto cleanup_t_hash;
			}
		}
		else {
			if (!utftp_proto_send_ack(t->fd, (struct sockaddr *) &peer, peer_len, 0)) {
				utftp_handle_local_error(-1, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, sprintfa("failed to send first ack: %s", strerror(errno)), s->error_cb, s->ctx);
				goto cleanup_t_hash;
			}
		}
	}

	return;

cleanup_t_hash:
	HASH_DEL(s->transmissions, t);
	utftp_transmission_free(t);
}

utftp_server_t *utftp_server_new(struct event_base *base, int fd, utftp_transmission_cb receive_cb, utftp_transmission_cb send_cb, utftp_error_cb error_cb, void *ctx)
{
	utftp_server_t *s = malloc(sizeof(*s));
	if (!s)
		return NULL;

	if (evutil_make_socket_nonblocking(fd) == -1)
		goto cleanup_s;

	s->receive_cb = receive_cb;
	s->send_cb = send_cb;
	s->error_cb = error_cb;
	s->ctx = ctx;

	s->transmissions = NULL;

	s->evt = event_new(base, fd, EV_READ | EV_PERSIST, server_read_cb, s);
	if (!s->evt)
		goto cleanup_s;

	event_add(s->evt, NULL);

	return s;

cleanup_s:
	free(s);

	return NULL;
}

void utftp_server_free(utftp_server_t *s)
{
	utftp_transmission_t *t, *tmp;
	HASH_ITER(hh, s->transmissions, t, tmp) {
		HASH_DEL(s->transmissions, t);
		utftp_transmission_free(t);
	}

	close(event_get_fd(s->evt));
	event_free(s->evt);

	free(s);
}

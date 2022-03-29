#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uthash.h>

#include "internal.h"
#include "proto.h"
#include "utftp.h"

struct utftp_server {
	int fd;
	struct event *evt;
	utftp_transmission_cb receive_cb;
	utftp_transmission_cb send_cb;
	utftp_error_cb error_cb;

	utftp_transmission_t *transmissions;

	void *ctx;
};


static void delete_server_transmission(utftp_transmission_t *t, void *ctx)
{
	utftp_server_t *s = ctx;

fprintf(stderr, "delete_server_transmission t %p ctx %p\n", (void *) t, (void *) ctx);
	HASH_DEL(s->transmissions, t);
}

static void server_error_cb(const struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string, void *ctx)
{
	utftp_server_t *s = ctx;

	if (s->error_cb)
		s->error_cb(peer, peer_len, error_code, error_string, s->ctx);
}

static void server_peer_write_cb(evutil_socket_t fd, short what, void *ctx)
{
	(void) fd;

	utftp_transmission_t *t = ctx;
	utftp_server_t *s = t->internal_ctx;

	if (!(what & EV_READ)) {
		if (what & EV_TIMEOUT) {
			if (t->expire_at < time(NULL)) {
				if (!t->last_block)
					utftp_handle_error(t->fd, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "transaction timed out", s->error_cb, s->ctx);

				HASH_DEL(s->transmissions, t);
				utftp_transmission_free(t);
				return;
			}

			// TODO return value
			utftp_proto_send_ack(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block);
		}

		return;
	}

	transmission_internal_cbs_t server_cbs = {
		delete_server_transmission,
		server_error_cb,
	};

	utftp_transmission_write_cb(t, &server_cbs);
}

static void server_peer_read_cb(evutil_socket_t fd, short what, void *ctx)
{
	(void) fd;

	utftp_transmission_t *t = ctx;
	utftp_server_t *s = t->internal_ctx;

	if (!(what & EV_READ)) {
		if (what & EV_TIMEOUT) {
			if (t->expire_at < time(NULL)) {
				if (!t->last_block)
					utftp_handle_error(t->fd, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "transaction timed out", s->error_cb, s->ctx);

				HASH_DEL(s->transmissions, t);
				utftp_transmission_free(t);
				return;
			}

			// TODO return value
			utftp_proto_send_block(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block, t->buf, t->block_size);
		}

		return;
	}

	transmission_internal_cbs_t server_cbs = {
		delete_server_transmission,
		server_error_cb,
	};

	utftp_transmission_read_cb(t, &server_cbs);
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
			utftp_handle_error(-1, NULL, 0, UTFTP_ERR_UNDEFINED, strerror(errno), s->error_cb, s->ctx);

		return;
	}

	if (rlen < 2) {
		utftp_handle_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "short read", s->error_cb, s->ctx);
		return;
	}

	uint16_t op = ntohs(*((uint16_t *) buf));
	if (op != TFTP_OP_READ && op != TFTP_OP_WRITE) {
		utftp_handle_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_ILLEGAL_OP, sprintfa("invalid operation %04" PRIx16, op), s->error_cb, s->ctx);
		return;
	}

	const char *filename = buf + 2;

	const char *pos = utftp_proto_next_zt(filename, remaining(buf, rlen, filename));
	if (!pos) {
		utftp_handle_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "unterminated filename", s->error_cb, s->ctx);
		return;
	}

	const char *mode = pos + 1;
	pos = utftp_proto_next_zt(mode, remaining(buf, rlen, mode));
	if (!pos) {
		utftp_handle_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "unterminated mode", s->error_cb, s->ctx);
		return;
	}

	uint8_t mode_u;
	if (!utftp_proto_detect_mode(mode, &mode_u)) {
		utftp_handle_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, sprintfa("unknown mode \"%s\"", mode), s->error_cb, s->ctx);
		return;
	}

	pos = pos + 1;

	utftp_transmission_t *t = utftp_transmission_new(
		event_get_base(s->evt),
		op == TFTP_OP_WRITE ? server_peer_write_cb : server_peer_read_cb,
		(struct sockaddr *) &peer,
		peer_len,
		s
	);
	if (!t) {
		utftp_handle_error(fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "couldn't allocate transmission data", s->error_cb, s->ctx);
		return;
	}

	HASH_ADD_INT(s->transmissions, fd, t);

	uint8_t option_mask;
	size_t tsize;

	const char *option = pos;
	while ((pos = utftp_proto_next_zt(option, remaining(buf, rlen, option))) && option != pos) {
		const char *value = pos + 1;
		pos = utftp_proto_next_zt(value, remaining(buf, rlen, value));
		if (!pos)
			break;

		if (value == pos)
			break;

		option = pos + 1;

		char *endptr;
		unsigned long value_u = strtoul(value, &endptr, 10);
		if (!endptr || *endptr != '\0')
			continue;

		// TODO 'windowsize' option
		uint8_t option_u;
		if (!utftp_proto_detect_option(option, &option_u))
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

		option_mask = option_mask | OPTION_BIT_TSIZE;
	}

	t->data_cb = NULL;

	switch (op) {
	case TFTP_OP_READ:
		t->data_cb = s->send_cb(t, mode_u, filename, option_mask & OPTION_BIT_TSIZE ? &tsize : NULL, s->ctx);

		break;
	case TFTP_OP_WRITE:
		t->data_cb = s->receive_cb(t, mode_u, filename, option_mask & OPTION_BIT_TSIZE ? &tsize : NULL, s->ctx);
		// TODO tsize mustn't change otherwise
		if (tsize == 0)
			option_mask = option_mask & ~OPTION_BIT_TSIZE;

		break;
	}

	if (!t->data_cb) {
		if (!t->sent_error)
			utftp_internal_send_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "internal error");

		goto cleanup_t;
	}

	struct timeval tv = { t->timeout, 0 };
	event_add(t->evt, &tv);

	if (option_mask != 0) {
		if (!utftp_proto_send_oack(
			t->fd,
			(struct sockaddr *) &peer, peer_len,
			option_mask & OPTION_BIT_BLKSIZE ? &t->block_size : NULL,
			option_mask & OPTION_BIT_TIMEOUT ? &t->timeout : NULL,
			option_mask & OPTION_BIT_TSIZE ? &tsize : NULL)
		) {
			utftp_handle_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, sprintfa("failed to send oack: %s", strerror(errno)), s->error_cb, s->ctx);
			goto cleanup_t;
		}
	} else {
		if (op == TFTP_OP_READ) {
			if (!utftp_transmission_fetch_next_block(t))
				goto cleanup_t;

			if (!utftp_proto_send_block(t->fd, (struct sockaddr *) &peer, peer_len, t->previous_block, t->buf, t->block_size)) {
				utftp_handle_error(-1, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, sprintfa("failed to send first block: %s", strerror(errno)), s->error_cb, s->ctx);
				goto cleanup_t;
			}
		}
		else {
			if (!utftp_proto_send_ack(t->fd, (struct sockaddr *) &peer, peer_len, 0)) {
				utftp_handle_error(-1, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, sprintfa("failed to send first ack: %s", strerror(errno)), s->error_cb, s->ctx);
				goto cleanup_t;
			}
		}
	}

	return;

cleanup_t:
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

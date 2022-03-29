#include <arpa/inet.h>
#include <uthash.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "internal.h"
#include "utftp.h"

#define MAX_BLOCK_SIZE 2048


bool utftp_transmission_get_peer(utftp_transmission_t *t, struct sockaddr *addr, socklen_t *addr_len)
{
	if (*addr_len < t->peer_len)
		return false;

	memcpy(addr, &t->peer, t->peer_len);
	*addr_len = t->peer_len;
	utftp_normalise_mapped_ipv4(addr, addr_len);
	return true;
}

bool utftp_transmission_fetch_next_block(utftp_transmission_t *t)
{
	size_t s = t->data_cb(t, t->buf, t->block_size);
	if (t->sent_error)
		return false;

	if (s < t->block_size) {
		t->block_size = s;
		t->last_block = true;
	}

	t->previous_block = t->previous_block + 1;
	return true;
}

void *utftp_transmission_get_ctx(utftp_transmission_t *t)
{
	return t->ctx;
}

void utftp_transmission_set_ctx(utftp_transmission_t *t, utftp_ctx_cleanup_cb cleanup_cb, void *ctx)
{
	t->cleanup_cb = cleanup_cb;
	t->ctx = ctx;
}

void utftp_transmission_end_with_error(utftp_transmission_t *t, utftp_errcode_t error_code , const char *error_string)
{
	utftp_internal_send_error(t->fd, (struct sockaddr *) &t->peer, t->peer_len, error_code, error_string);

	t->sent_error = true;
}

void utftp_transmission_set_expiration(utftp_transmission_t *t)
{
	t->expire_at = time(NULL) + 300;
}

void utftp_transmission_complete_transaction(utftp_transmission_t *t)
{
	if (t->cleanup_cb) {
		t->cleanup_cb(t, t->last_block, t->ctx);
		t->cleanup_cb = NULL;
		t->ctx = NULL;
	}

	utftp_transmission_set_expiration(t);

	struct timeval tv = { 300 + 1, 0 };
	event_add(t->evt, &tv);
}

void utftp_transmission_write_cb(utftp_transmission_t *t, const transmission_internal_cbs_t *cbs)
{
	uint8_t buf[MAX_BLOCK_SIZE + 4];

	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);
	ssize_t rlen = recvfrom(t->fd, buf, sizeof(buf), 0, (struct sockaddr *) &peer, &peer_len);
	if (rlen == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			utftp_handle_error(-1, NULL, 0, UTFTP_ERR_UNDEFINED, strerror(errno), cbs->error_cb, t->internal_ctx);

		return;
	}

	if (peer_len != t->peer_len || memcmp(&peer, &t->peer, peer_len)) {
		utftp_internal_send_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNKNOWN_ID, "unknown peer");
		return;
	}

	uint8_t *pos = buf;
	uint16_t op = ntohs(*(uint16_t *) pos);
	pos = pos + sizeof(op);

	if (op != TFTP_OP_DATA) {
		utftp_internal_send_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_ILLEGAL_OP, "illegal operation");
		return;
	}

	uint16_t block_num = ntohs(*(uint16_t *) pos);
	if (block_num < t->previous_block)
		return;

	pos = pos + sizeof(block_num);

	if (block_num > t->previous_block + 1) {
		utftp_internal_send_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "invalid block number");
		return;
	}

	if (block_num == t->previous_block)
		goto send_ack;

	size_t data_len = remaining(buf, rlen, pos);
	t->last_block = data_len != t->block_size;

	t->data_cb(t, pos, data_len);

	t->previous_block = t->previous_block + 1;

	if (t->last_block) {
		utftp_transmission_complete_transaction(t);
		return;
	}

	if (t->sent_error) {
		cbs->cleanup_cb(t, t->internal_ctx);
		utftp_transmission_free(t);
		return;
	}

	utftp_transmission_set_expiration(t);

	struct timeval tv = { t->timeout, 0 };
	event_add(t->evt, &tv);

send_ack:
	// TODO return value
	utftp_proto_send_ack(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block);
}

void utftp_transmission_read_cb(utftp_transmission_t *t, const transmission_internal_cbs_t *cbs)
{
	uint8_t buf[4];

	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);
	ssize_t rlen = recvfrom(t->fd, buf, sizeof(buf), 0, (struct sockaddr *) &peer, &peer_len);
	if (rlen == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			utftp_handle_error(-1, NULL, 0, UTFTP_ERR_UNDEFINED, strerror(errno), cbs->error_cb, t->internal_ctx);

		return;
	}

	if (peer_len != t->peer_len || memcmp(&peer, &t->peer, peer_len)) {
		utftp_internal_send_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNKNOWN_ID, "unknown peer");
		return;
	}

	uint16_t op = ntohs(*(uint16_t *) buf);
	uint8_t *pos = buf + sizeof(op);

	if (op != TFTP_OP_ACK) {
		utftp_internal_send_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_ILLEGAL_OP, "illegal operation");
		return;
	}

	uint16_t block_num = ntohs(*(uint16_t *) pos);
	if (block_num < t->previous_block)
		return;

	if (block_num > t->previous_block) {
		utftp_internal_send_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "invalid block number");
		return;
	}

	if (t->last_block) {
		utftp_transmission_complete_transaction(t);
		return;
	}

	if (!utftp_transmission_fetch_next_block(t)) {
		cbs->cleanup_cb(t, t->internal_ctx);
		utftp_transmission_free(t);
		return;
	}

	utftp_transmission_set_expiration(t);

	struct timeval tv = { t->timeout, 0 };
	event_add(t->evt, &tv);

	// TODO return value
	utftp_proto_send_block(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block, t->buf, t->block_size);
}

utftp_transmission_t *utftp_transmission_new(struct event_base *base, event_callback_fn cb, struct sockaddr *peer, socklen_t peer_len, void *internal_ctx)
{
	utftp_transmission_t *t = malloc(sizeof(*t));
	if (!t)
		return NULL;

	t->fd = socket(peer->sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (t->fd == -1)
		goto cleanup_t;

	if (peer_len > sizeof(t->peer))
		goto cleanup_s;

	t->previous_block = 0;
	t->last_block = false;

	t->peer_len = peer_len;
	memcpy(&t->peer, peer, peer_len);

	struct sockaddr_in6 addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_addr = in6addr_any;
	addr.sin6_port = 0;

	if (bind(t->fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		goto cleanup_s;
	}

	t->block_size = UTFTP_DEFAULT_BLOCK_SIZE;
	t->timeout = 1;

	utftp_transmission_set_expiration(t);

	t->evt = event_new(base, t->fd, EV_READ | EV_TIMEOUT | EV_PERSIST, cb, t);
	if (!t->evt)
		goto cleanup_s;

	t->internal_ctx = internal_ctx;

	return t;

cleanup_s:
	close(t->fd);

cleanup_t:
	free(t);

	return NULL;
}

void utftp_transmission_free(utftp_transmission_t *t)
{
	if (t->cleanup_cb)
		t->cleanup_cb(t, false, t->ctx);

	event_free(t->evt);
	close(t->fd);
	free(t);
}

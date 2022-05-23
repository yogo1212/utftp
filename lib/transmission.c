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
		t->data_cb = NULL;
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

bool utftp_transmission_send_raw_buf(utftp_transmission_t *t)
{
	return sendto(t->fd, t->buf, t->block_size, 0, (struct sockaddr *) &t->peer, t->peer_len) == t->block_size;
}

void utftp_transmission_complete_transaction(utftp_transmission_t *t)
{
	if (t->complete)
		return;

	t->complete = true;

	if (t->cleanup_cb) {
		t->cleanup_cb(t, t->complete, t->ctx);
		t->cleanup_cb = NULL;
		t->ctx = NULL;
	}

	struct timeval tv = { 300 + 1, 0 };
	event_add(t->evt, &tv);
}

void utftp_transmission_handle_data(utftp_transmission_t *t, uint16_t block_num, void *data, size_t data_len, const transmission_internal_cbs_t *cbs)
{
	if (block_num < t->previous_block)
		return;

	if (block_num > t->previous_block + 1) {
		utftp_internal_send_error(t->fd, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "invalid block number");
		return;
	}

	if (block_num == t->previous_block)
		goto send_ack;

	t->data_cb(t, data, data_len);

	t->previous_block = t->previous_block + 1;

	t->last_progress = time(NULL);

	if (data_len != t->block_size) {
		utftp_transmission_complete_transaction(t);
		goto send_ack;
	}

	if (t->sent_error) {
		cbs->cleanup_cb(t, t->internal_ctx);
		utftp_transmission_free(t);
		return;
	}

	struct timeval tv = { t->timeout, 0 };
	event_add(t->evt, &tv);

send_ack:
	// TODO return value
	utftp_proto_send_ack(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block);
}

void utftp_transmission_receive_cb(utftp_transmission_t *t, const transmission_internal_cbs_t *cbs)
{
	uint8_t buf[MAX_BLOCK_SIZE + 4];

	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);
	ssize_t rlen = recvfrom(t->fd, buf, sizeof(buf), 0, (struct sockaddr *) &peer, &peer_len);
	if (rlen == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			utftp_handle_local_error(-1, NULL, 0, UTFTP_ERR_UNDEFINED, strerror(errno), cbs->error_cb, t->internal_ctx);

		return;
	}

	if (peer.ss_family != t->peer.ss_family || memcmp(&peer, &t->peer, peer_len) != 0) {
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
	pos = pos + sizeof(block_num);

	utftp_transmission_handle_data(t, block_num, pos, remaining(buf, rlen, pos), cbs);
}

bool utftp_transmission_handle_ack(utftp_transmission_t *t, uint16_t block_num, const transmission_internal_cbs_t *cbs)
{
	if (block_num < t->previous_block)
		return true;

	if (block_num > t->previous_block) {
		utftp_internal_send_error(t->fd, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "invalid block number");
		return false;
	}

	t->last_progress = time(NULL);

	if (!t->data_cb) {
		utftp_transmission_complete_transaction(t);
		return true;
	}

	if (!utftp_transmission_fetch_next_block(t)) {
		cbs->cleanup_cb(t, t->internal_ctx);
		utftp_transmission_free(t);
		return false;
	}

	struct timeval tv = { t->timeout, 0 };
	event_add(t->evt, &tv);

	return utftp_proto_send_block(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block, t->buf, t->block_size);
}

void utftp_transmission_send_cb(utftp_transmission_t *t, const transmission_internal_cbs_t *cbs)
{
	uint8_t buf[4];

	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);
	ssize_t rlen = recvfrom(t->fd, buf, sizeof(buf), 0, (struct sockaddr *) &peer, &peer_len);
	if (rlen == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			utftp_handle_local_error(-1, NULL, 0, UTFTP_ERR_UNDEFINED, strerror(errno), cbs->error_cb, t->internal_ctx);

		return;
	}

	if (peer.ss_family != t->peer.ss_family || memcmp(&peer, &t->peer, peer_len) != 0) {
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

	// TODO return value
	utftp_transmission_handle_ack(t, block_num, cbs);
}

bool utftp_transmission_start(utftp_transmission_t *t, struct event_base *base, event_callback_fn cb)
{
	t->last_progress = time(NULL);

	t->evt = event_new(base, t->fd, EV_READ | EV_TIMEOUT | EV_PERSIST, cb, t);
	if (!t->evt) {
		// TODO error
		return false;
	}

	// TODO error
	struct timeval tv = { t->timeout, 0 };
	return event_add(t->evt, &tv) == 0;
}

utftp_transmission_t *utftp_transmission_new(const struct sockaddr *peer, socklen_t peer_len, utftp_error_cb error_cb, void *internal_ctx)
{
	utftp_transmission_t *t = malloc(sizeof(*t));
	if (!t) {
		error_cb(peer, peer_len, true, UTFTP_ERR_UNDEFINED, "couldn't allocate transmission data", internal_ctx);
		return NULL;
	}

	t->fd = socket(peer->sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (t->fd == -1) {
		error_cb(peer, peer_len, true, UTFTP_ERR_UNDEFINED, sprintfa("couldn't create socket (%s)", strerror(errno)), internal_ctx);
		goto cleanup_t;
	}

	if (peer_len > sizeof(t->peer)) {
		error_cb(peer, peer_len, true, UTFTP_ERR_UNDEFINED, "peer address too large", internal_ctx);
		goto cleanup_s;
	}

	t->previous_block = 0;
	t->complete = false;
	t->sent_error = false;

	t->evt = NULL;

	t->peer_len = peer_len;
	memcpy(&t->peer, peer, peer_len);

	struct sockaddr_storage addr;
	memset(&addr, 0, sizeof(addr));
	addr.ss_family = peer->sa_family;

	switch (peer->sa_family) {
	case AF_INET: ;
		struct sockaddr_in *sin = (struct sockaddr_in *) &addr;
		sin->sin_addr.s_addr = INADDR_ANY;
		sin->sin_port = 0;
		break;
	case AF_INET6: ;
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &addr;
		sin6->sin6_addr = in6addr_any;
		sin6->sin6_port = 0;
		break;
	default:
		error_cb(peer, peer_len, true, UTFTP_ERR_UNDEFINED, "peer address too large", internal_ctx);
	}

	if (bind(t->fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		error_cb(peer, peer_len, true, UTFTP_ERR_UNDEFINED, sprintfa("couldn't bind socket (%s)", strerror(errno)), internal_ctx);
		goto cleanup_s;
	}

	t->block_size = UTFTP_DEFAULT_BLOCK_SIZE;
	t->timeout = UTFTP_DEFAULT_TIMEOUT;

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

	if (t->evt)
		event_free(t->evt);
	close(t->fd);
	free(t);
}

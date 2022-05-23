#include "internal.h"
#include "proto.h"
#include "utftp.h"

typedef void (*read_cb)(utftp_client_t *c, utftp_transmission_t *t, transmission_internal_cbs_t *cbs);
struct utftp_client {
	utftp_transmission_t *t;
	utftp_error_cb error_cb;

	bool sending;

	// called when the tsize option is acked - can be NULL
	utftp_tsize_cb tsize_cb;

	// called when a datagram arrives
	read_cb read_cb;
	uint8_t option_mask;
};

utftp_client_t *utftp_client_new(const struct sockaddr *peer, socklen_t peer_len, utftp_error_cb error_cb, utftp_ctx_cleanup_cb cleanup_cb, void *ctx)
{
	utftp_client_t *c = malloc(sizeof(utftp_client_t));
	if (!c) {
		utftp_handle_local_error(-1, peer, peer_len, UTFTP_ERR_UNDEFINED, "couldn't allocate client", error_cb, ctx);
		return NULL;
	}

	memset(c, 0, sizeof(utftp_client_t));

	c->error_cb = error_cb;

	c->t = utftp_transmission_new(peer, peer_len, error_cb, ctx);
	if (!c->t)
		goto cleanup_c;

	utftp_transmission_set_ctx(c->t, cleanup_cb, ctx);

	c->t->internal_ctx = c;

	return c;

cleanup_c:
	free(c);
	return NULL;
}

static void _clear_transmission(utftp_transmission_t *t, void *ctx)
{
	(void) t;

	utftp_client_t *c = ctx;
	c->t = NULL;
}

static void client_handle_oack(utftp_transmission_t *t, const char *buf, size_t len)
{
	utftp_client_t *c = t->internal_ctx;

	const char *option = buf;
	const char *pos;
	while ((pos = utftp_proto_next_zt(option, remaining(buf, len, option))) && option != pos) {
		const char *value = pos + 1;
		pos = utftp_proto_next_zt(value, remaining(buf, len, value));
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

		if (!(option_u & c->option_mask))
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

			if (c->tsize_cb)
				c->tsize_cb(value_u, t->ctx);
			break;
		default:
			continue;
		}

		// only accept the first value for an option
		c->option_mask = c->option_mask & ~option_u;
	}

	// TODO return values
	if (c->sending) {
		if (!utftp_transmission_fetch_next_block(t)) {
			utftp_transmission_free(t);
			c->t = NULL;
			return;
		}

		utftp_proto_send_block(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block, t->buf, t->block_size);
	}
	else {
		utftp_proto_send_ack(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block);
	}
}

// returns true if the transaction should continue
static bool client_timeout_event(utftp_client_t *c, utftp_transmission_t *t)
{
	if (t->complete) {
		if (!c->sending) {
			// server might not have received last ack - give it a few more tries
			if (t->last_progress > time(NULL) - (t->timeout * 2))
				goto send;
		}

		return false;
	}

	if (t->last_progress < time(NULL) - 300) {
		utftp_handle_local_error(t->fd, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "transaction timed out", c->error_cb, t->ctx);
		return false;
	}

send:
	// TODO return values
	if (t->previous_block == 0)
		utftp_transmission_send_raw_buf(t);
	else if (!c->sending)
		utftp_proto_send_ack(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block);
	else if (c->sending)
		utftp_proto_send_block(t->fd, (struct sockaddr *) &t->peer, t->peer_len, t->previous_block, t->buf, t->block_size);

	return true;
}

static void client_read_cb(evutil_socket_t fd, short what, void *ctx)
{
	(void) fd;

	utftp_transmission_t *t = ctx;
	utftp_client_t *c = t->internal_ctx;

	if (!(what & EV_READ)) {
		if (!(what & EV_TIMEOUT))
			return;

		if (!client_timeout_event(c, t)) {
			utftp_transmission_free(t);
			c->t = NULL;
		}

		return;
	}

	transmission_internal_cbs_t client_cbs = {
		_clear_transmission,
		c->error_cb,
	};

	// TODO check if null
	c->read_cb(c, t, &client_cbs);
	return;
}

static void _utftp_transmission_receive_cb(utftp_client_t *c, utftp_transmission_t *t, transmission_internal_cbs_t *cbs)
{
	(void) c;

	utftp_transmission_receive_cb(t, cbs);
}

static void _utftp_transmission_send_cb(utftp_client_t *c, utftp_transmission_t *t, transmission_internal_cbs_t *cbs)
{
	(void) c;

	utftp_transmission_send_cb(t, cbs);
}

static void first_read_cb(utftp_client_t *c, utftp_transmission_t *t, transmission_internal_cbs_t *cbs)
{
	uint8_t buf[MAX_BLOCK_SIZE + 4];

	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);
	ssize_t rlen = recvfrom(t->fd, buf, sizeof(buf), 0, (struct sockaddr *) &peer, &peer_len);
	if (rlen == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			utftp_handle_local_error(-1, NULL, 0, UTFTP_ERR_UNDEFINED, strerror(errno), c->error_cb, t->ctx);

		return;
	}

	if (peer_len > sizeof(t->peer)) {
		utftp_handle_local_error(-1, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "peer address too large", c->error_cb, t->ctx);
		return;
	}

	uint16_t op = ntohs(*(uint16_t *) buf);
	uint8_t *pos = buf + sizeof(uint16_t);

	// TODO parse block_num in the corresponding transaction handler func - remove parameter
	uint16_t block_num;

	switch (op) {
	case TFTP_OP_OACK:
		if (c->option_mask == 0) {
			utftp_handle_local_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "received OACK having sent no options", c->error_cb, t->ctx);
			return;
		}

		memcpy(&t->peer, &peer, peer_len);
		t->peer_len = peer_len;

		t->timeout = UTFTP_DEFAULT_TIMEOUT;
		t->block_size = UTFTP_DEFAULT_BLOCK_SIZE;

		client_handle_oack(t, (const char *) pos, remaining(buf, rlen, pos));
		break;
	case TFTP_OP_DATA:
		if (c->sending)
			return;

		memcpy(&t->peer, &peer, peer_len);
		t->peer_len = peer_len;

		t->timeout = UTFTP_DEFAULT_TIMEOUT;
		t->block_size = UTFTP_DEFAULT_BLOCK_SIZE;

		block_num = ntohs(*(uint16_t *) pos);
		pos = pos + sizeof(uint16_t);
		if (block_num != 1) {
			// TODO dedup!!!
			utftp_handle_local_error(t->fd, (struct sockaddr *) &peer, peer_len, UTFTP_ERR_UNDEFINED, "invalid block number", c->error_cb, c->t->ctx);
			return;
		}

		utftp_transmission_handle_data(t, block_num, pos, remaining(buf, rlen, pos), cbs);
		break;
	case TFTP_OP_ACK:
		if (!c->sending)
			return;

		memcpy(&t->peer, &peer, peer_len);
		t->peer_len = peer_len;

		t->timeout = UTFTP_DEFAULT_TIMEOUT;
		t->block_size = UTFTP_DEFAULT_BLOCK_SIZE;

		block_num = ntohs(*(uint16_t *) pos);
		// TODO return value
		utftp_transmission_handle_ack(t, block_num, cbs);
		break;
	case TFTP_OP_ERROR:
		utftp_handle_remote_error((struct sockaddr *) &peer, peer_len, pos, remaining(buf, rlen, pos), c->error_cb, t->ctx);
		utftp_transmission_free(t);
		c->t = NULL;
		break;
	default:
		return;
	}

	if (c->sending)
		c->read_cb = _utftp_transmission_send_cb;
	else
		c->read_cb = _utftp_transmission_receive_cb;
}

bool utftp_client_receive(utftp_client_t *c, struct event_base *base, utftp_mode_t mode, const char *file, utftp_next_block_cb data_cb, uint16_t *block_size, uint8_t *timeout, utftp_tsize_cb tsize_cb)
{
	utftp_transmission_t *t = c->t;

	if (t->evt) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "transmission was already started", c->error_cb, t->ctx);
		return false;
	}

	t->data_cb = data_cb;
	c->sending = false;

	if (!utftp_transmission_start(t, base, client_read_cb)) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to start transmission", c->error_cb, t->ctx);
		return false;
	}

	char *pos = (char *) t->buf;
	*((uint16_t *) t->buf) = htons(TFTP_OP_READ);
	pos = pos + sizeof(uint16_t);

	pos = utftp_proto_write_zt_string(pos, remaining(t->buf, sizeof(t->buf), pos), file);
	if (!pos) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write filename", c->error_cb, t->ctx);
		return false;
	}

	pos = utftp_proto_write_mode(pos, remaining(t->buf, sizeof(t->buf), pos), mode);
	if (!pos) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write mode", c->error_cb, t->ctx);
		return false;
	}

	c->option_mask = 0;

	if (tsize_cb) {
		pos = utftp_proto_write_option(pos, remaining(t->buf, sizeof(t->buf), pos), OPTION_BIT_TSIZE, 0);
		if (!pos) {
			utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write tsize option", c->error_cb, t->ctx);
			return false;
		}

		c->tsize_cb = tsize_cb;
		c->option_mask = OPTION_BIT_TSIZE;
	}

	if (timeout) {
		pos = utftp_proto_write_option(pos, remaining(t->buf, sizeof(t->buf), pos), OPTION_BIT_TIMEOUT, *timeout);
		if (!pos) {
			utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write timeout option", c->error_cb, t->ctx);
			return false;
		}

		c->option_mask = OPTION_BIT_TIMEOUT;
	}

	if (block_size) {
		pos = utftp_proto_write_option(pos, remaining(t->buf, sizeof(t->buf), pos), OPTION_BIT_BLKSIZE, *block_size);
		if (!pos) {
			utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write block size option", c->error_cb, t->ctx);
			return false;
		}

		c->option_mask = OPTION_BIT_BLKSIZE;
	}

	t->block_size = (ptrdiff_t) pos - (ptrdiff_t) t->buf;
	c->read_cb = first_read_cb;

	if (!utftp_transmission_send_raw_buf(t)) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to send read request", c->error_cb, t->ctx);
		return false;
	}

	return true;
}

bool utftp_client_send(utftp_client_t *c, struct event_base *base, utftp_mode_t mode, const char *file, utftp_next_block_cb data_cb, uint16_t *block_size, uint8_t *timeout, size_t *tsize)
{
	utftp_transmission_t *t = c->t;

	if (t->evt) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "transmission was already started", c->error_cb, t->ctx);
		return false;
	}

	t->data_cb = data_cb;
	c->sending = true;

	if (!utftp_transmission_start(t, base, client_read_cb)) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to start transmission", c->error_cb, t->ctx);
		return false;
	}

	char *pos = (char *) t->buf;
	*((uint16_t *) t->buf) = htons(TFTP_OP_WRITE);
	pos = pos + sizeof(uint16_t);

	pos = utftp_proto_write_zt_string(pos, remaining(t->buf, sizeof(t->buf), pos), file);
	if (!pos) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write filename", c->error_cb, t->ctx);
		return false;
	}

	pos = utftp_proto_write_mode(pos, remaining(t->buf, sizeof(t->buf), pos), mode);
	if (!pos) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write mode", c->error_cb, t->ctx);
		return false;
	}

	c->option_mask = 0;

	if (tsize) {
		pos = utftp_proto_write_option(pos, remaining(t->buf, sizeof(t->buf), pos), OPTION_BIT_TSIZE, *tsize);
		if (!pos) {
			utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write tsize option", c->error_cb, t->ctx);
			return false;
		}

		c->option_mask = OPTION_BIT_TSIZE;
	}

	if (timeout) {
		pos = utftp_proto_write_option(pos, remaining(t->buf, sizeof(t->buf), pos), OPTION_BIT_TIMEOUT, *timeout);
		if (!pos) {
			utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write timeout option", c->error_cb, t->ctx);
			return false;
		}

		c->option_mask = OPTION_BIT_TIMEOUT;
	}

	if (block_size) {
		pos = utftp_proto_write_option(pos, remaining(t->buf, sizeof(t->buf), pos), OPTION_BIT_BLKSIZE, *block_size);
		if (!pos) {
			utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to write block size option", c->error_cb, t->ctx);
			return false;
		}

		c->option_mask = OPTION_BIT_BLKSIZE;
	}

	t->block_size = (ptrdiff_t) pos - (ptrdiff_t) t->buf;
	c->read_cb = first_read_cb;

	if (!utftp_transmission_send_raw_buf(t)) {
		utftp_handle_local_error(-1, (struct sockaddr *) &t->peer, t->peer_len, UTFTP_ERR_UNDEFINED, "failed to send read request", c->error_cb, t->ctx);
		return false;
	}

	return true;
}

void utftp_client_free(utftp_client_t *c)
{
	if (c->t)
		utftp_transmission_free(c->t);
	free(c);
}

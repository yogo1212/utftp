#ifndef UTFTP_INTERNAL_H
#define UTFTP_INTERNAL_H

#include <event2/event.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <uthash.h>

#include "proto.h"
#include "utftp.h"


#define UTFTP_DEFAULT_TIMEOUT (1)

typedef struct {
	void (*cleanup_cb)(utftp_transmission_t *t, void *ctx);
	utftp_error_cb error_cb;
} transmission_internal_cbs_t;

struct utftp_transmission {
  int fd;
  struct event *evt;

  struct sockaddr_storage peer;
  socklen_t peer_len;

	bool sent_error;

	time_t expire_at;
  uint8_t timeout;

	uint8_t buf[MAX_BLOCK_SIZE];
  uint16_t block_size;
  uint16_t previous_block;
	bool last_block;

  utftp_next_block_cb data_cb;

	utftp_ctx_cleanup_cb cleanup_cb;
  void *ctx;

  void *internal_ctx;

  UT_hash_handle hh;
};

#define sprintfa(fmt, ...) \
	__extension__ \
  ({ \
    int len = snprintf(NULL, 0, fmt, __VA_ARGS__); \
    char *target = NULL; \
    if (len >= 0) { \
      target = alloca(len + 1); \
      sprintf(target, fmt, __VA_ARGS__); \
    } \
    target; \
  })

utftp_transmission_t *utftp_transmission_new(const struct sockaddr *peer, socklen_t peer_len, utftp_error_cb error_cb, void *internal_ctx);
bool utftp_transmission_start(utftp_transmission_t *t, struct event_base *base, event_callback_fn cb);
void utftp_transmission_free(utftp_transmission_t *t);

bool utftp_transmission_fetch_next_block(utftp_transmission_t *t);
void utftp_transmission_set_expiration(utftp_transmission_t *t);
void utftp_transmission_complete_transaction(utftp_transmission_t *t);
bool utftp_transmission_send_raw_buf(utftp_transmission_t *t);

bool utftp_transmission_send_raw_buf(utftp_transmission_t *t);

bool utftp_transmission_handle_ack(utftp_transmission_t *t, uint16_t block_num, const transmission_internal_cbs_t *cbs);
void utftp_transmission_send_cb(utftp_transmission_t *t, const transmission_internal_cbs_t *cbs);
void utftp_transmission_handle_data(utftp_transmission_t *t, uint16_t block_num, void *data, size_t data_len, const transmission_internal_cbs_t *cbs);
void utftp_transmission_receive_cb(utftp_transmission_t *t, const transmission_internal_cbs_t *cbs);

void utftp_internal_send_error(int fd, const struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string);

// calls error_cb and send_error
void utftp_handle_local_error(int fd, const struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string, utftp_error_cb error_cb, void *ctx);

void utftp_handle_remote_error(const struct sockaddr *peer, socklen_t peer_len, const uint8_t *buf, size_t buf_len, utftp_error_cb error_cb, void *ctx);

void utftp_normalise_mapped_ipv4(struct sockaddr *s, socklen_t *len);

#endif

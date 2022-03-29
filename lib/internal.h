#ifndef UTFTP_INTERNAL_H
#define UTFTP_INTERNAL_H

#include <event2/event.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <uthash.h>

#include "proto.h"
#include "utftp.h"


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

utftp_transmission_t *utftp_transmission_new(struct event_base *base, event_callback_fn cb, struct sockaddr *peer, socklen_t peer_len, void *internal_ctx);
void utftp_transmission_free(utftp_transmission_t *t);

bool utftp_transmission_fetch_next_block(utftp_transmission_t *t);
void utftp_transmission_set_expiration(utftp_transmission_t *t);
void utftp_transmission_complete_transaction(utftp_transmission_t *t);

void utftp_transmission_read_cb(utftp_transmission_t *t, const transmission_internal_cbs_t *cbs);
void utftp_transmission_write_cb(utftp_transmission_t *t, const transmission_internal_cbs_t *cbs);

void utftp_internal_send_error(int fd, struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string);

// calls error_cb and send_error
void utftp_handle_error(int fd, struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string, utftp_error_cb error_cb, void *ctx);


void utftp_normalise_mapped_ipv4(struct sockaddr *s, socklen_t *len);

#endif

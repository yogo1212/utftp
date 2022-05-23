#ifndef UTFTP_H
#define UTFTP_H

#include <event2/event.h>
#include <stdbool.h>

#define UTFTP_DEFAULT_PORT 69
#define UTFTP_DEFAULT_BLOCK_SIZE 512

/*
 * all sockaddresses passed to and from utftp should be in network byte order.
 */

typedef enum {
	UTFTP_ERR_UNDEFINED = 0,  // Not defined, see error message (if any).
	UTFTP_ERR_NOT_FOUND,      // File not found.
	UTFTP_ERR_NO_ACCESS,      // Access violation.
	UTFTP_ERR_NO_SPACE,       // Disk full or allocation exceeded.
	UTFTP_ERR_ILLEGAL_OP,     // Illegal TFTP operation.
	UTFTP_ERR_UNKNOWN_ID,     // Unknown transfer ID.
	UTFTP_ERR_EXISTS,         // File already exists.
	UTFTP_ERR_NO_USER,        // No such user.
	UTFTP_ERR_ILLEGAL_OPTION, // Option negotiation led to termination.
} utftp_errcode_t;


struct utftp_transmission;
typedef struct utftp_transmission utftp_transmission_t;

typedef void (*utftp_ctx_cleanup_cb)(utftp_transmission_t *t, bool complete, void *ctx);

/* cleanup_cb will be called when the transmission is freed but NOT when utftp_transmission_set_ctx is called again */
void utftp_transmission_set_ctx(utftp_transmission_t *t, utftp_ctx_cleanup_cb cleanup_cb, void *ctx);
void *utftp_transmission_get_ctx(utftp_transmission_t *t);

void utftp_transmission_end_with_error(utftp_transmission_t *t, utftp_errcode_t error_code , const char *error_string);

/* returns false if addr is too small */
bool utftp_transmission_get_peer(utftp_transmission_t *t, struct sockaddr *addr, socklen_t *addr_len);

/*
 * supply or receive the next block.
 * return the amount of bytes handled.
 * when writing, returning anything but block_size will end the transmission gracefully.
 * calling utftp_transmission_end_with_error from the callback will end the transmission.
 */
typedef uint16_t (*utftp_next_block_cb)(utftp_transmission_t *t, void *buf, uint16_t block_size);

typedef enum {
	UTFTP_MODE_NETASCII = 0,
	UTFTP_MODE_OCTET,
	UTFTP_MODE_MAIL,
} utftp_mode_t;

/*
 * peer can be NULL
 * if remote is true, the error was sent by the peer
 */
typedef void (*utftp_error_cb)(const struct sockaddr *peer, socklen_t peer_len, bool remote, utftp_errcode_t error_code, const char *error_string, void *ctx);

struct utftp_client;
typedef struct utftp_client utftp_client_t;

utftp_client_t *utftp_client_new(const struct sockaddr *peer, socklen_t peer_len, utftp_error_cb error_cb, utftp_ctx_cleanup_cb cleanup_cb, void *ctx);
void utftp_client_free(utftp_client_t *c);

typedef void (*utftp_tsize_cb)(size_t tsize, void *ctx);

/*
 * tsize_cb can be NULL and will only be called if there's an OACK response containing tsize.
 * use only one ;-)
 */
bool utftp_client_receive(utftp_client_t *c, struct event_base *base, utftp_mode_t mode, const char *file, utftp_next_block_cb data_cb, uint16_t *block_size, uint8_t *timeout, utftp_tsize_cb tsize_cb);
bool utftp_client_send(utftp_client_t *c, struct event_base *base, utftp_mode_t mode, const char *file, utftp_next_block_cb data_cb, uint16_t *block_size, uint8_t *timeout, size_t *tsize);

/*
 * if the request included the tsize option, *tsize points to the supplied value.
 * for read requests, set *tsize to inform the client about the size of the transmission.
 * tsize is NULL if the client didn't include the option
 * at the risk of not supporting empty files, if tsize is 0, the option is not acknowledged
 * calling utftp_transmission_end_with_error from the callback will end the transmission.
 * return NULL and set *error_code to abort the transmission
 */
typedef utftp_next_block_cb (*utftp_transmission_cb)(utftp_transmission_t *t, utftp_mode_t mode, const char *file, size_t *tsize, void *ctx);

struct utftp_server;
typedef struct utftp_server utftp_server_t;

/*
 * fd must be bound already and will be closed by utftp_server_free
 * receive_cb will be called when a write request arrives
 * send_cb will be called when a read request arrives
 * receive_cb and send_cb can be NULL
 */
utftp_server_t *utftp_server_new(struct event_base *base, int fd, utftp_transmission_cb receive_cb, utftp_transmission_cb send_cb, utftp_error_cb error_cb, void *ctx);
void utftp_server_free(utftp_server_t *server);

#endif

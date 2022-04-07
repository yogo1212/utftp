#ifndef UTFTP_PROTO_H
#define UTFTP_PROTO_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/socket.h>

#define MAX_BLOCK_SIZE 2048

#define OPTION_BIT_BLKSIZE ((uint8_t)1<<0)
#define OPTION_BIT_TIMEOUT ((uint8_t)1<<1)
#define OPTION_BIT_TSIZE   ((uint8_t)1<<2)

#define remaining(start, len, current) \
	((len) - ((ptrdiff_t) (current) - (ptrdiff_t) (start)))


typedef enum {
  TFTP_OP_READ = 1,
  TFTP_OP_WRITE,
  TFTP_OP_DATA,
  TFTP_OP_ACK,
  TFTP_OP_ERROR,
  TFTP_OP_OACK,
} tftp_opcode_t;

bool utftp_proto_send_ack(int fd, struct sockaddr *peer, socklen_t peer_len, uint16_t block);
bool utftp_proto_send_oack(int fd, struct sockaddr *peer, socklen_t peer_len, uint16_t *block_size, uint8_t *timeout, size_t *tsize);
bool utftp_proto_send_block(int fd, struct sockaddr *peer, socklen_t peer_len, uint16_t block, void *data, size_t len);

const char *utftp_proto_next_zt(const char *ptr, size_t len);
char *utftp_proto_write_zt_string(char *buf, size_t len, const char *s);

bool utftp_proto_detect_mode(const char *s, uint8_t *mode);
char *utftp_proto_write_mode(char *buf, size_t len, uint8_t mode);

bool utftp_proto_detect_option(const char *s, uint8_t *option);
char *utftp_proto_write_option(char *buf, size_t len, uint8_t option, size_t num);

#endif

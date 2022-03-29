#include <arpa/inet.h>
#include <string.h>

#include "proto.h"
#include "utftp.h"


static const char *option_strings[] = {
	[OPTION_BIT_BLKSIZE] = "blksize",
	[OPTION_BIT_TIMEOUT] = "timeout",
	[OPTION_BIT_TSIZE] = "tsize",
};

static const char *mode_strings[] = {
	[UTFTP_MODE_NETASCII] = "netascii",
	[UTFTP_MODE_OCTET] = "octet",
	[UTFTP_MODE_MAIL] = "mail",
};


bool utftp_proto_send_ack(int fd, struct sockaddr *peer, socklen_t peer_len, uint16_t block)
{
	uint8_t buf[4];

	*((uint16_t *) buf) = htons(TFTP_OP_ACK);
	uint8_t *pos = buf + 2;

	*((uint16_t *) pos) = htons(block);
	pos = pos + 2;

	return sendto(fd, buf, pos - buf, 0, peer, peer_len) == (pos - buf);
}

bool utftp_proto_send_oack(int fd, struct sockaddr *peer, socklen_t peer_len, uint16_t *block_size, uint8_t *timeout, size_t *tsize)
{
	char buf[MAX_BLOCK_SIZE];

	*((uint16_t *) buf) = htons(TFTP_OP_OACK);
	char *pos = buf + 2;

	if (block_size) {
		pos = utftp_proto_write_option(pos, remaining(buf, sizeof(buf), pos), OPTION_BIT_BLKSIZE, *block_size);
		if (!pos) {
			// "no space to write option 'block_size'";
			return false;
		}
	}

	if (timeout) {
		pos = utftp_proto_write_option(pos, remaining(buf, sizeof(buf), pos), OPTION_BIT_TIMEOUT, *timeout);
		if (!pos) {
			// "no space to write option 'timeout'";
			return false;
		}
	}

	if (tsize) {
		pos = utftp_proto_write_option(pos, remaining(buf, sizeof(buf), pos), OPTION_BIT_TSIZE, *tsize);
		if (!pos) {
			// "no space to write option 'tsize'";
			return false;
		}
	}

	return sendto(fd, buf, pos - buf, 0, peer, peer_len) == pos - buf;
}

bool utftp_proto_send_block(int fd, struct sockaddr *peer, socklen_t peer_len, uint16_t block, void *data, size_t len)
{
	if (len > MAX_BLOCK_SIZE)
		return false;

	uint8_t buf[4 + MAX_BLOCK_SIZE];

	*((uint16_t *) buf) = htons(TFTP_OP_DATA);
	uint8_t *pos = buf + 2;

	*((uint16_t *) pos) = htons(block);
	pos = pos + 2;

	memcpy(pos, data, len);
	pos = pos + len;

	return sendto(fd, buf, pos - buf, 0, peer, peer_len) == (pos - buf);
}

const char *utftp_proto_next_zt(const char *ptr, size_t len)
{
	const char *end = ptr + len;
	while (ptr < end) {
		if (*ptr == '\0')
			return ptr;

		ptr++;
	}

	return NULL;
}

bool utftp_proto_detect_mode(const char *s, uint8_t *mode)
{
	for (utftp_mode_t i = 0; sizeof(mode_strings) / sizeof(mode_strings[0]); i++) {
		if (strcasecmp(mode_strings[i], s) != 0)
			continue;

		*mode = i;
		return true;
	}

	return false;
}

bool utftp_proto_detect_option(const char *s, uint8_t *mode)
{
	if (strcasecmp(s, option_strings[OPTION_BIT_BLKSIZE]) == 0) {
		*mode = OPTION_BIT_BLKSIZE;
		return true;
	} else if (strcasecmp(s, option_strings[OPTION_BIT_TIMEOUT]) == 0) {
		*mode = OPTION_BIT_TIMEOUT;
		return true;
	} else if (strcasecmp(s, option_strings[OPTION_BIT_TSIZE]) == 0) {
		*mode = OPTION_BIT_TSIZE;
		return true;
	}

	return false;
}

char *utftp_proto_write_zt_string(char *buf, size_t len, const char *s)
{
	size_t zt_len = strlen(s) + 1;
	if (zt_len > len)
		return NULL;

	memcpy(buf, s, zt_len);
	return buf + zt_len;
}

char *utftp_proto_write_option(char *buf, size_t len, uint8_t option, size_t num)
{
	char *value = utftp_proto_write_zt_string(buf, len, option_strings[option]);
	if (!value)
		return NULL;

	len = remaining(buf, len, value);

	int value_len = snprintf(value, len, "%zu", num);
	if (value_len < 0)
		return NULL;

	if ((size_t) value_len >= len)
		return NULL;

	return value + value_len + 1;
}

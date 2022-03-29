#include <errno.h>
#include <event2/event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utftp.h>

#include "net_util.h"

static bool get_file_size_limit(size_t *limit)
{
	const char *s = getenv("FILE_SIZE_LIMIT");
	if (!s)
		return false;

	return sscanf(s, "%zu", limit) != 1;
}

// will leave port unchanged but return true if env is not set
static bool get_port(uint16_t *port)
{
	const char *s = getenv("PORT");
	if (!s)
		return true;

	unsigned int buf;
	if (sscanf(s, "%u", &buf) != 0) {
		fprintf(stderr, "couldn't parse port \"%s\"\n", s);
		return false;
	}

	if (buf > UINT16_MAX) {
		fprintf(stderr, "invalid port: %u\n", buf);
		return false;
	}

	*port = buf;
	return true;
}

static const char *display_peer(const struct sockaddr *peer, socklen_t peer_len)
{
	const char *addr = NULL;
	if (peer)
		addr = print_sockaddr(peer, peer_len);
	if (!addr)
		return "[unknown peer]";

	return addr;
}

typedef struct {
	int fd;
} file_context_t;

static void file_context_free(utftp_transmission_t *t, bool complete, void *ctx)
{
	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);

	const char *addr;
	if (!utftp_transmission_get_peer(t, (struct sockaddr *) &peer, &peer_len))
		addr = display_peer(NULL, 0);
	else
		addr = display_peer((struct sockaddr *) &peer, peer_len);

	if (complete)
		fprintf(stderr, "transaction with %s complete\n", addr);

	file_context_t *fc = ctx;

	close(fc->fd);
	free(fc);
}

// some windows file APIs support slashes, so they're always checked
static bool is_valid_path(const char *path)
{
	if (path[0] == '/')
		return false;

	if (getenv("WINDOWS_PATH_CHECKS")) {
		if (path[1] == ':' && path[2] == '\\')
			return false;

		if (strncmp(path, "..\\", 3) == 0)
			return false;

		if (strstr(path, "\\..\\"))
			return false;

		// TODO is it possible to mix slashes and backslashes?
		// if so, the combinations need to be checked as well
	}

	if (strncmp(path, "../", 3) == 0)
		return false;

	if (strstr(path, "/../"))
		return false;

	if (getenv("NO_DIR_TRAVERSAL")) {
		if (strchr(path, '/'))
			return false;
	}

	return true;
}

static int file_flags(bool writing)
{
	int f = 0;
	// at the time of writing, there is no O_NONBLOCK for files.
	// O_DIRECT could be interesting

	if (getenv("NO_FOLLOW"))
		f = f | O_NOFOLLOW;

	if (writing) {
		if (!getenv("NO_CREATE"))
			f = f | O_CREAT;

		if (getenv("NO_OVERWRITE"))
			f = f | O_EXCL;
	}

	return f;
}

static uint16_t receive_block_cb(utftp_transmission_t *t, void *buf, uint16_t block_size)
{
	file_context_t *fc = utftp_transmission_get_ctx(t);

	size_t limit;
	if (get_file_size_limit(&limit) && ((size_t) lseek(fc->fd, 0, SEEK_CUR)) + block_size > limit) {
		// TODO filename?
		fprintf(stderr, "write file size limit exceeded\n");
		utftp_transmission_end_with_error(t, UTFTP_ERR_NO_SPACE, "file size limit exceeded");
		return 0;
	}

	ssize_t wlen = write(fc->fd, buf, block_size);
	if (wlen == -1) {
		// TODO filename?
		fprintf(stderr, "write error: %s\n", strerror(errno));
		utftp_transmission_end_with_error(t, UTFTP_ERR_UNDEFINED, "write error");
		return 0;
	}

	return wlen;
}

static utftp_next_block_cb receive_cb(utftp_transmission_t *t, utftp_mode_t mode, const char *file, size_t *tsize, void *ctx)
{
	(void) ctx;

	if (mode != UTFTP_MODE_OCTET) {
		utftp_transmission_end_with_error(t, UTFTP_ERR_UNDEFINED, "unsupported mode");
		return NULL;
	}

	if (!is_valid_path(file)) {
		utftp_transmission_end_with_error(t, UTFTP_ERR_NO_ACCESS, "illegal path");
		return NULL;
	}

	if (tsize) {
		size_t limit;
		if (get_file_size_limit(&limit) && *tsize > limit) {
			utftp_transmission_end_with_error(t, UTFTP_ERR_NO_SPACE, "file size limit exceeded");
			return NULL;
		}
	}

	file_context_t *fc = malloc(sizeof(file_context_t));
	if (!fc) {
		fprintf(stderr, "malloc failed: %s\n", strerror(errno));
		return NULL;
	}

	fc->fd = open(file, file_flags(true) | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fc->fd == -1) {
		fprintf(stderr, "file \"%s\" can't be opened for writing: %s\n", file, strerror(errno));
		utftp_transmission_end_with_error(t, UTFTP_ERR_UNDEFINED, "can't open file");
		return NULL;
	}

	if (tsize) {
		if (ftruncate(fc->fd, *tsize) == -1)
			fprintf(stderr, "can't truncate \"%s\": %s\n", file, strerror(errno));
	}

	utftp_transmission_set_ctx(t, file_context_free, fc);

	return receive_block_cb;
}

static uint16_t send_block_cb(utftp_transmission_t *t, void *buf, uint16_t block_size)
{
	file_context_t *fc = utftp_transmission_get_ctx(t);

	ssize_t rlen = read(fc->fd, buf, block_size);
	if (rlen == -1) {
		// TODO filename?
		fprintf(stderr, "read error: %s\n", strerror(errno));
		utftp_transmission_end_with_error(t, UTFTP_ERR_UNDEFINED, "read error");
		return 0;
	}

	return rlen;
}

static utftp_next_block_cb send_cb(utftp_transmission_t *t, utftp_mode_t mode, const char *file, size_t *tsize, void *ctx)
{
	(void) ctx;

	if (mode != UTFTP_MODE_OCTET) {
		utftp_transmission_end_with_error(t, UTFTP_ERR_UNDEFINED, "unsupported mode");
		return NULL;
	}

	if (!is_valid_path(file)) {
		utftp_transmission_end_with_error(t, UTFTP_ERR_NO_ACCESS, "illegal path");
		return NULL;
	}

	file_context_t *fc = malloc(sizeof(file_context_t));
	if (!fc) {
		fprintf(stderr, "malloc failed: %s\n", strerror(errno));
		return NULL;
	}

	fc->fd = open(file, file_flags(false) | O_RDONLY);
	if (fc->fd == -1) {
		fprintf(stderr, "file \"%s\" can't be opened for reading: %s\n", file, strerror(errno));
		utftp_transmission_end_with_error(t, UTFTP_ERR_UNDEFINED, "can't open file");
		return NULL;
	}

	if (tsize) {
		struct stat s;
		if (fstat(fc->fd, &s) != -1) {
			*tsize = s.st_size;
		}
		else {
			fprintf(stderr, "fstat failed for %s\n", file);
		}
	}

	utftp_transmission_set_ctx(t, file_context_free, fc);

	return send_block_cb;
}

static void error_cb(const struct sockaddr *peer, socklen_t peer_len, utftp_errcode_t error_code, const char *error_string, void *ctx)
{
	(void) ctx;

	const char *addr = display_peer(peer, peer_len);

	fprintf(stderr, "error in transmission with %s - %s (%d) \n", addr, error_string, error_code);
}

static void _utftp_server_free(void *ctx)
{
	utftp_server_t *s = ctx;
	utftp_server_free(s);
}

int main(int argc, char *argv[])
{
	argv++;
	argc--;

	if (argc == 0) {
		fprintf(stderr, "need a mode: listen, get, put\n");
		return EXIT_FAILURE;
	}

	struct event_base *base = event_base_new();

	int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (fd == -1) {
		fprintf(stderr, "couldn't create socket: %s\n", strerror(errno));
		goto cleanup_base;
	}

	const char *operation = argv[0];

	argv++;
	argc--;

	void *actor = NULL;
	void (*cleanup)(void *actor);

	if (strcmp(operation, "listen") == 0) {
		uint16_t port = UTFTP_DEFAULT_PORT;
		if (!get_port(&port))
			return EXIT_FAILURE;

		// TODO interface

		struct sockaddr_in6 addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_addr = in6addr_any;
		addr.sin6_port = htons(port);

		if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
			fprintf(stderr, "couldn't bind socket: %s\n", strerror(errno));
			close(fd);
			goto cleanup_base;
		}

		utftp_server_t *s = utftp_server_new(base, fd, receive_cb, send_cb, error_cb, NULL);
		if (!s) {
			fprintf(stderr, "failed to create server\n");
			close(fd);
			goto cleanup_base;
		}

		actor = s;
		cleanup = _utftp_server_free;
	}
/*	else if (strcmp(operation, "get") == 0 || or strcmp(operation, "put") == 0) {
		actor = c;
		cleanup = _utftp_client_free;
	} */
	else {
		fprintf(stderr, "unknown operation \"%s\"\n", operation);
		return EXIT_FAILURE;
	}

	event_base_dispatch(base);

	cleanup(actor);

cleanup_base:
	event_base_free(base);

	return EXIT_SUCCESS;
}

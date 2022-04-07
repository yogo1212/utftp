#include <arpa/inet.h>
#include <errno.h>
#include <event2/event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utftp.h>

#include "net_util.h"

static void handle_sigint(evutil_socket_t fd, short what, void *ctx)
{
	(void) fd;
	(void) what;

	struct event_base *base = ctx;
	event_base_loopbreak(base);

	// TODO stop listening?
}

static bool get_file_size_limit(size_t *limit)
{
	const char *s = getenv("FILE_SIZE_LIMIT");
	if (!s)
		return false;

	return sscanf(s, "%zu", limit) != 1;
}

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

static uint16_t *get_block_size(void)
{
	const char *s = getenv("BLOCK_SIZE");
	if (!s)
		return NULL;

	unsigned int buf;
	if (sscanf(s, "%u", &buf) != 0) {
		fprintf(stderr, "couldn't parse block size \"%s\"\n", s);
		return NULL;
	}

	if (buf > UINT16_MAX) {
		fprintf(stderr, "invalid block_size: %u\n", buf);
		return NULL;
	}

	static uint16_t block_size;
	block_size = buf;
	return &block_size;
}

static uint8_t *get_timeout(void)
{
	const char *s = getenv("TIMEOUT");
	if (!s)
		return NULL;

	unsigned int buf;
	if (sscanf(s, "%u", &buf) != 0) {
		fprintf(stderr, "couldn't parse timeout \"%s\"\n", s);
		return NULL;
	}

	if (buf > UINT8_MAX) {
		fprintf(stderr, "invalid timeout value: %u\n", buf);
		return NULL;
	}

	static uint8_t timeout;
	timeout = buf;
	return &timeout;
}

static bool set_listen_addr(struct in6_addr *a)
{
	const char *listen_addr = getenv("LISTEN_ADDRESS");
	if (!listen_addr) {
		memcpy(a, &in6addr_any, sizeof(*a));
		return true;
	}

	if (strchr(listen_addr, ':')) {
		if (inet_pton(AF_INET6, listen_addr, a) != 1) {
			fprintf(stderr, "failed to parse IPv6 address: %s (%s)\n", listen_addr, strerror(errno));
			return false;
		}
	}
	else {
		struct in_addr a4;
		if (inet_pton(AF_INET, listen_addr, &a4) != 1) {
			fprintf(stderr, "failed to parse IPv4 address: %s (%s)\n", listen_addr, strerror(errno));
			return false;
		}

		const uint16_t mapped_prefix[6] = { 0, 0, 0, 0, 0, 0xFFFF };
		memcpy(a->s6_addr16, mapped_prefix, sizeof(mapped_prefix));
		memcpy(&a->s6_addr[12], &a4, 4);
	}

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

static void _file_context_tsize_cb(size_t tsize, void *ctx)
{
	file_context_t *fc = ctx;

	if (ftruncate(fc->fd, tsize) == -1)
		fprintf(stderr, "ftrunctate failed: %s\n", strerror(errno));
}

static void file_context_free(utftp_transmission_t *t, bool complete, void *ctx)
{
	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);

	const char *addr;
	if (!utftp_transmission_get_peer(t, (struct sockaddr *) &peer, &peer_len))
		addr = display_peer(NULL, 0);
	else
		addr = display_peer((struct sockaddr *) &peer, peer_len);

	printf("%s - transaction %scomplete\n", addr, complete ? "" : "in");

	file_context_t *fc = ctx;

	close(fc->fd);
	free(fc);
}

// some windows file APIs support slashes, so they're always checked
static bool is_valid_path(const char *path)
{
	if (getenv("WINDOWS_PATH_CHECKS")) {
		if (getenv("NO_DIR_TRAVERSAL")) {
			if (strchr(path, '\\'))
				return false;
		}

		if (!getenv("ALLOW_ABSOLUTE_PATHS")) {
			if (path[1] == ':' && path[2] == '\\')
				return false;
		}

		if (strncmp(path, "..\\", 3) == 0)
			return false;

		if (strstr(path, "\\..\\"))
			return false;

		// TODO is it possible to mix slashes and backslashes?
		// if so, combinations need to be checked as well
	}

	if (!getenv("ALLOW_ABSOLUTE_PATHS")) {
		if (path[0] == '/')
			return false;
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
		f = f | O_WRONLY;

		if (!getenv("NO_CREATE"))
			f = f | O_CREAT;

		if (getenv("NO_OVERWRITE"))
			f = f | O_EXCL;
	}
	else {
		f = f | O_RDONLY;
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

	fc->fd = open(file, file_flags(true), S_IRUSR | S_IWUSR);
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

	fc->fd = open(file, file_flags(false));
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

static void error_cb(const struct sockaddr *peer, socklen_t peer_len, bool remote, utftp_errcode_t error_code, const char *error_string, void *ctx)
{
	(void) ctx;

	const char *addr = display_peer(peer, peer_len);

	fprintf(stderr, "%s - %s error in transmission: %s (%d) \n", addr, remote ? "remote" : "local", error_string, error_code);
}

static void _utftp_client_free(void *ctx)
{
	utftp_client_t *c = ctx;
	utftp_client_free(c);
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
		fprintf(stderr, "usage: listen, get, put\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "the following environment variables are supported.\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "general options:\n");
		fprintf(stderr, "\tPORT: bind (with listen) or connect (client) to a specific port\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "server only options:\n");
		fprintf(stderr, "\tLISTEN_ADDRESS: bind to a specific address\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "general file path restrictions:\n");
		fprintf(stderr, "\tby default, file names starting with a slash or going up directories are rejected.\n");
		fprintf(stderr, "\tWINDOWS_PATH_CHECKS: reject paths starting with \"x:\\\" or \"..\\\" or containing \"\\..\\\"\n");
		fprintf(stderr, "\tNO_DIR_TRAVERSAL: reject paths containing slashes (or backslashes when using WINDOWS_PATH_CHECKS)\n");
		fprintf(stderr, "\tALLOW_ABSOLUTE_PATHS: allow absolute paths (drive letters with WINDOWS_PATH_CHECKS)\n");
		fprintf(stderr, "\tNO_FOLLOW: reject paths containing symlinks\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "incoming file restrictions:\n");
		fprintf(stderr, "\tNO_CREATE: don't create files\n");
		fprintf(stderr, "\tNO_OVERWRITE: don't overwrite files\n");
		fprintf(stderr, "\tFILE_SIZE_LIMIT: limit the size for incoming transmissions\n");
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

	uint16_t port = UTFTP_DEFAULT_PORT;
	if (!get_port(&port))
		goto cleanup_base;

	if (strcmp(operation, "listen") == 0) {
		// TODO interface

		struct sockaddr_in6 addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(port);

		if (!set_listen_addr(&addr.sin6_addr)) {
			fprintf(stderr, "failed to set listen address\n");
			close(fd);
			goto cleanup_base;
		}

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
	else if (strcmp(operation, "get") == 0 || strcmp(operation, "put") == 0) {
		if (argc < 2) {
			fprintf(stderr, "usage: (get|put) host filaname\n");
			goto cleanup_base;
		}

		struct hostent *ent = gethostbyname(argv[0]);
		if (!ent) {
			fprintf(stderr, "gethostbyname failed: %s\n", strerror(errno));
			goto cleanup_base;
		}

		if (!ent->h_addr_list[0]) {
			fprintf(stderr, "gethostbyname returned an empty list\n");
			goto cleanup_base;
		}

		struct sockaddr_storage addr;
		memset(&addr, 0, sizeof(addr));

		addr.ss_family = ent->h_addrtype;

		switch (addr.ss_family) {
		case AF_INET: ;
			struct sockaddr_in *sin = (struct sockaddr_in* ) &addr;
			memcpy(&sin->sin_addr, ent->h_addr_list[0], sizeof(sin->sin_addr));
			sin->sin_port = htons(port);
			break;
		case AF_INET6: ;
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &addr;
			memcpy(&sin6->sin6_addr, ent->h_addr_list[0], sizeof(sin6->sin6_addr));
			sin6->sin6_port = htons(port);
			break;
		default:
			fprintf(stderr, "unknown address family: %d", addr.ss_family);
			goto cleanup_base;
		}

		file_context_t *fc = malloc(sizeof(file_context_t));

		const char *file = argv[1];

		// TODO windows?
		const char *local_file = rindex(file, '/');
		if (!local_file)
			local_file = file;

		bool writing = strcmp(operation, "get") == 0;
		// TODO when receiving, maybe only open file when the first block arrives
		fc->fd = open(local_file, file_flags(writing), S_IRUSR | S_IWUSR);
		if (fc->fd == -1) {
			fprintf(stderr, "file \"%s\" can't be opened for %s: %s\n", local_file, writing ? "writing" : "reading", strerror(errno));
			free(fc);
			goto cleanup_base;
		}

		utftp_client_t *c = utftp_client_new((struct sockaddr *) &addr, sizeof(addr), error_cb, file_context_free, fc);
		if (!c) {
			close(fc->fd);
			free(fc);
			goto cleanup_base;
		}

		actor = c;
		cleanup = _utftp_client_free;

		if (writing) {
			if (!utftp_client_read(c, base, UTFTP_MODE_OCTET, file, receive_block_cb, get_block_size(), get_timeout(), _file_context_tsize_cb))
				goto cleanup_actor;
		}
		else {
			size_t _tsize;
			size_t *tsize = &_tsize;

			struct stat s;
			if (fstat(fc->fd, &s) != -1) {
				*tsize = s.st_size;
			}
			else {
				fprintf(stderr, "fstat failed for %s\n", file);
				tsize = NULL;
			}

			if (!utftp_client_write(c, base, UTFTP_MODE_OCTET, file, send_block_cb, get_block_size(), get_timeout(), tsize))
				goto cleanup_actor;
		}
	}
	else {
		fprintf(stderr, "unknown operation \"%s\"\n", operation);
		return EXIT_FAILURE;
	}

	struct event *sig_event = evsignal_new(base, SIGINT, handle_sigint, base);

	event_base_dispatch(base);

	event_free(sig_event);

cleanup_actor:
	cleanup(actor);

cleanup_base:
	event_base_free(base);

	return EXIT_SUCCESS;
}

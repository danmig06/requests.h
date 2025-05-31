#ifndef HAVE_REQUEST_H
#define HAVE_REQUEST_H
/* MIT License
 *
 * Copyright (c) 2025 Daniele Migliore
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*	TODO:
 *		- add mbedTLS support
 *		- maybe Input Stream system
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#define closesocket(s) close(s)

#elif defined(WIN32_LEAN_AND_MEAN) || defined(_WIN32) || defined(WIN32)

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>

#else
#error "unsupported platform"
#endif

#ifndef REQUESTS_NO_TLS

#ifdef REQUESTS_USE_WOLFSSL

#include <wolfssl/options.h>
#define OPENSSL_EXTRA
#include <wolfssl/openssl/ssl.h>
#undef MIN

#else

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#endif // #ifdef REQUESTS_USE_WOLFSSL
typedef SSL_CTX TLS_CTX;
typedef SSL TLS_CONN;
typedef X509 TLS_CERT;

#endif // #ifndef REQUESTS_NO_TLS

#define LOGGER_SRCNAME "[requests.h]" 
#define FUNC_LINE_FMT "%s():%d: "
#define REQUESTS_RECV_BUFSIZE 1024 * 32 
#define STATIC_STRSIZE(str) (sizeof(str) - 1)
#define MIN(x, y) ((x < y) ? x : y)
#define OPTION(s, m) (s && (s)->m)

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------
 |				     |
 |	enums, structs & API         |
 |				     |
  ---------------------------------- */

enum HTTPSTATUS {
    NO_STATUS_CODE = 0,

    CONTINUE = 100,
    SWITCHING_PROTOCOLS = 101,
    PROCESSING = 102,
    EARLY_HINTS = 103,

    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    NON_AUTHORITATIVE_INFORMATION = 203,
    NO_CONTENT = 204,
    RESET_CONTENT = 205,
    PARTIAL_CONTENT = 206,
    MULTI_STATUS = 207,
    ALREADY_REPORTED = 208,
    IM_USED = 226,

    MULTIPLE_CHOICES = 300,
    MOVED_PERMANENTLY = 301,
    FOUND = 302,
    SEE_OTHER = 303,
    NOT_MODIFIED = 304,
    USE_PROXY = 305,
    TEMPORARY_REDIRECT = 307,
    PERMANENT_REDIRECT = 308,

    BAD_REQUEST = 400,
    UNAUTHORIZED = 401,
    PAYMENT_REQUIRED = 402,
    FORBIDDEN = 403,
    NOT_FOUND = 404,
    METHOD_NOT_ALLOWED = 405,
    NOT_ACCEPTABLE = 406,
    PROXY_AUTHENTICATION_REQUIRED = 407,
    REQUEST_TIMEOUT = 408,
    CONFLICT = 409,
    GONE = 410,
    LENGTH_REQUIRED = 411,
    PRECONDITION_FAILED = 412,
    PAYLOAD_TOO_LARGE = 413,
    URI_TOO_LONG = 414,
    UNSUPPORTED_MEDIA_TYPE = 415,
    RANGE_NOT_SATISFIABLE = 416,
    EXPECTATION_FAILED = 417,
    IM_A_TEAPOT = 418,
    MISDIRECTED_REQUEST = 421,
    UNPROCESSABLE_ENTITY = 422,
    LOCKED = 423,
    FAILED_DEPENDENCY = 424,
    TOO_EARLY = 425,
    UPGRADE_REQUIRED = 426,
    PRECONDITION_REQUIRED = 428,
    TOO_MANY_REQUESTS = 429,
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
    UNAVAILABLE_FOR_LEGAL_REASONS = 451,

    INTERNAL_SERVER_ERROR = 500,
    NOT_IMPLEMENTED = 501,
    BAD_GATEWAY = 502,
    SERVICE_UNAVAILABLE = 503,
    GATEWAY_TIMEOUT = 504,
    HTTP_VERSION_NOT_SUPPORTED = 505,
    VARIANT_ALSO_NEGOTIATES = 506,
    INSUFFICIENT_STORAGE = 507,
    LOOP_DETECTED = 508,
    NOT_EXTENDED = 510,
    NETWORK_AUTHENTICATION_REQUIRED = 511
};

enum PROTOCOL {
	NO_PROTOCOL = 0,
	HTTP,
	HTTPS
};

enum REQUEST_METHOD {
	GET,
	POST,
	PUT,
	HEAD,
	OPTIONS
};

#define __TRANSFER_MODE_NODATA 0
#define __TRANSFER_MODE_SIZED 1
#define __TRANSFER_MODE_CHUNKED 2

enum HTTPVER {
	HTTP_1_0 = -1,
	HTTP_1_1 = 0
};

enum LOGLEVEL {
	NONE = 1,
	INFO = 2,
	WARN = 4,
	ERR = 8,
	DEBUG = 16,
	ALL = 31
};

struct __sized_buf {
	char* data;
	size_t size;
};

struct parameter {
	char* name;
	char* value;
};

struct params {
	char* repr;
	struct parameter* params;
	size_t num_params;
};

struct url {
	enum PROTOCOL protocol;
	char* hostname;
	char* route;
	short port;
	struct params* params;
};

struct header_entry {
	char* name;
	char* value;
};

struct header {
	struct header_entry* entries;
	size_t num_entries;
};

struct download_state {
	uint64_t bytes_received;
	uint64_t bytes_left;
	struct __sized_buf buffer;
	const uint64_t content_length;
	const enum HTTPSTATUS status_code;
};

typedef void (*requests_user_cb_t)(struct download_state*, void*);

struct request_options {
	struct __sized_buf body;
	enum HTTPVER http_version;
	struct header header;
	struct url* url;
	requests_user_cb_t data_callback;
	void* user_data;
	bool disable_ssl;
	bool ignore_verification;
	char* cert;
};

struct response {
	struct __sized_buf body;
	struct header header;
	char* status_line;
	enum HTTPSTATUS status_code;
	char* reason;
	struct url* url;
};

struct url resolve_url(char* url_str);
char* url_get_filename(struct url* url);
struct url url_redirect(struct url* current, char* location);
struct url clone_url(struct url* u);

void header_add_sized(struct header* headers, char* key, size_t key_size, char* value, size_t value_size);
void header_add(struct header* headers, char* key, char* value);
void header_add_str(struct header* headers, char* header_str);
struct header_entry* header_get(struct header* headers, char* key);
char* header_get_value(struct header* headers, char* key);

struct params* parse_query_string(char* str);
struct parameter* params_get(struct params* params, char* key);
char* params_get_value(struct params* params, char* key);

struct response* requests_perform(char* url, enum REQUEST_METHOD method, struct request_options* options);
struct response* requests_perform_file(char* url, char* filename, enum REQUEST_METHOD method, struct request_options* options);
struct response* requests_perform_fileptr(char* url, FILE* file, enum REQUEST_METHOD method, struct request_options* options);
struct response* requests_perform_no_body(char* url, enum REQUEST_METHOD method, struct request_options* options);

struct response* requests_get(char* url, struct request_options* options);
struct response* requests_get_file(char* url, char* filename, struct request_options* options);
struct response* requests_get_fileptr(char* url, FILE* file, struct request_options* options);

struct response* requests_head(char* url, struct request_options* options);

struct response* requests_post(char* url, struct request_options* options);
struct response* requests_post_file(char* url, char* filename, struct request_options* options);
struct response* requests_post_fileptr(char* url, FILE* file, struct request_options* options);

struct response* requests_put(char* url, struct request_options* options);
struct response* requests_put_file(char* url, char* filename, struct request_options* options);
struct response* requests_put_fileptr(char* url, FILE* file, struct request_options* options);

struct response* requests_options(char* url, struct request_options* options);

void requests_set_log_level(enum LOGLEVEL mask);

#ifndef REQUESTS_NO_TLS
TLS_CTX* requests_get_tls_context(void);
void requests_free_tls_context(void);
#endif

struct response* alloc_response(void);
void free_response(struct response* freeptr);
void free_header(struct header* freeptr);
void free_url(struct url* freeptr);

/* ------------------------------------------------------------------------------------------------------
 |				     									 |
 |	  					IMPLEMENTATIONS            				 |
 |				     									 |
  ------------------------------------------------------------------------------------------------------ */
#ifdef REQUESTS_IMPLEMENTATION
/* ----------------------------------
 |				     |
 |	  custom realloc()           |
 |				     |
  ---------------------------------- */

static void* reallocate(void* ptr, size_t oldsz, size_t newsz) {
	void* newptr = NULL;

	newptr = malloc(newsz);
	if(newptr != NULL && ptr != NULL) {
		memcpy(newptr, ptr, MIN(oldsz, newsz));
		free(ptr);
	}
	return newptr;
}

/* ----------------------------------
 |				     |
 |	  internal logger            |
 |				     |
  ---------------------------------- */

#define COLOR(id) "\033[38;5;" id "m"
#define INFO_CLR COLOR("45")
#define WARN_CLR COLOR("220")
#define ERROR_CLR COLOR("196")
#define DEBUG_CLR COLOR("250")
#define RESET_CLR "\033[0m"

#ifndef REQUESTS_DISABLE_LOGGING

#define info(fmt, ...) logger_log(INFO, stdout, fmt, ##__VA_ARGS__)
#define warn(fmt, ...) logger_log(WARN, stdout, fmt, ##__VA_ARGS__)
#define error(fmt, ...) logger_log(ERR, stdout, fmt, ##__VA_ARGS__)
#define debug(fmt, ...) logger_log(DEBUG, stdout, fmt, ##__VA_ARGS__)

#else

#define info(fmt, ...) 
#define warn(fmt, ...) 
#define error(fmt, ...) 
#define debug(fmt, ...) 

#endif // #ifndef REQUESTS_DISABLE_LOGGING

static enum LOGLEVEL current_log_level = NONE;

static void logger_set_level(enum LOGLEVEL mask) {
	current_log_level = mask;
}

static void logger_log(enum LOGLEVEL l, FILE* stream, char* fmt, ...) {
	va_list args;
	switch(l & current_log_level) {
	case INFO:
		fputs(INFO_CLR LOGGER_SRCNAME " INFO: ", stream);
		break;
	case WARN:
		fputs(WARN_CLR LOGGER_SRCNAME " WARN: ", stream);
		break;
	case ERR:
		fputs(ERROR_CLR LOGGER_SRCNAME " ERROR: ", stream);
		break;
	case DEBUG:
		fputs(DEBUG_CLR LOGGER_SRCNAME " DEBUG: ", stream);
		break;
	default:
		return;
	}

	va_start(args, fmt);
	vfprintf(stream, fmt, args);
	fputs(RESET_CLR, stream);
}

#undef LOGGER_SRCNAME
#undef COLOR
#undef INFO_CLR
#undef WARN_CLR
#undef ERROR_CLR
#undef DEBUG_CLR
#undef RESET_CLR

void requests_set_log_level(enum LOGLEVEL l) {
	logger_set_level(l);
}

/* ----------------------------------
 |				     |
 |	  network I/O functions      |
 |				     |
  ---------------------------------- */

struct netio;
typedef ssize_t (*netiofunc_t)(struct netio*, void*, size_t);

struct netio {
#ifndef REQUESTS_NO_TLS
	TLS_CONN* ssl;
#endif
	int socket;
	netiofunc_t send;
	netiofunc_t recv;
};

static ssize_t __not_secure_send(struct netio* conn_io, void* buf, size_t num); 
static ssize_t __not_secure_recv(struct netio* conn_io, void* buf, size_t num); 
#ifndef REQUESTS_NO_TLS
static ssize_t __secure_send(struct netio* conn_io, void* buf, size_t num); 
static ssize_t __secure_recv(struct netio* conn_io, void* buf, size_t num); 
#endif

static ssize_t __not_secure_send(struct netio* conn_io, void* buf, size_t num) {
	return send(conn_io->socket, buf, num, 0);
}

static ssize_t __not_secure_recv(struct netio* conn_io, void* buf, size_t num) { 
	return recv(conn_io->socket, buf, num, 0);
}

struct netreader {
	uint8_t*      buf;
	size_t        off;
	size_t        len;
	struct netio* io;
	bool          eof;
};

static struct netreader net_rd_new(struct netio* io) {
	struct netreader rd = { 0 };
	rd.buf = malloc(REQUESTS_RECV_BUFSIZE);
	rd.io = io;
	return rd;
}

static void net_rd_refill(struct netreader* rd) {
	if(!rd->eof) {
		size_t len = rd->io->recv(rd->io, rd->buf, REQUESTS_RECV_BUFSIZE);	
		if(len > 0) {
			rd->len = len;
		} else {
			rd->eof = true;
			rd->len = 0;
		}
		rd->off = 0;
	}
}

static uint8_t net_rd_nextbyte(struct netreader* rd) {
	if(rd->off == rd->len) {
		net_rd_refill(rd);
	}

	if(rd->eof) {
		return 0;
	}

	return rd->buf[rd->off++];
}

static inline bool net_rd_eof(struct netreader* rd) {
	return rd->eof;
}

static size_t net_rd_recv(struct netreader* rd, void* mem, size_t n) {
	uint8_t* buf = mem;
	size_t i;
	for(i = 0; i < n; i++) {
		if(net_rd_eof(rd)) {
			break;
		}
		buf[i] = net_rd_nextbyte(rd);
	}
	return i;
}

/* ----------------------------------
 |				     |
 |	  I/O stream objects         |
 |				     |
  ---------------------------------- */

struct ostream;

typedef size_t (*oswritefunc_t)(struct ostream*, void*, size_t);
typedef void (*osclosefunc_t)(struct ostream*);

struct ostream {
	void* object;
	oswritefunc_t write;
	osclosefunc_t close;
};

static size_t __os_write_file(struct ostream* os, void* buf, size_t num);
static size_t __os_write_buf(struct ostream* os, void* buf, size_t num); 
static void __os_close_file(struct ostream* os);
static void __os_close_buf(struct ostream* os); 

static struct ostream os_create_fileptr(FILE* fptr) {
	return (struct ostream){ .object = fptr, .write = __os_write_file, .close = __os_close_file };
}

static struct ostream os_create_file(char* filename) {
	FILE* f = fopen(filename, "wb");
	if(!f) {
		error(FUNC_LINE_FMT "failed to open file '%s'\n", __func__, __LINE__, filename);
		return (struct ostream){ NULL };
	}
	return (struct ostream){ .object = f, .write = __os_write_file, .close = __os_close_file };
}

static struct ostream os_create_buf(struct __sized_buf* buffer) {
	return (struct ostream){ .object = buffer, .write = __os_write_buf, .close = __os_close_buf };
}

static size_t __os_write_file(struct ostream* os, void* buf, size_t num) {
	FILE* f = (FILE*)os->object;
	return fwrite(buf, num, 1, f);
}

static size_t __os_write_buf(struct ostream* os, void* buf, size_t num) {
	struct __sized_buf* b = os->object;
	b->data = reallocate(b->data, b->size, b->size + num);
	memcpy(&b->data[b->size], buf, num);
	b->size += num;
	return num;
}

static void __os_close_file(struct ostream* os) {
	fclose(os->object);
	memset(os, 0, sizeof(*os));
}

static void __os_close_buf(struct ostream* os) {
	struct __sized_buf* b = os->object;
	if(b->data != NULL) {
		b->data = reallocate(b->data, b->size, b->size + 1);
		b->data[b->size] = '\0';
	}
	memset(os, 0, sizeof(*os));
}

/* ----------------------------------
 |				     |
 |	  TLS library API            |
 |				     |
  ---------------------------------- */
#ifndef REQUESTS_NO_TLS
static TLS_CTX* g_tlslib_ctx = NULL;

static TLS_CTX* tls_init_context(void) {
	if(g_tlslib_ctx) {
		return g_tlslib_ctx;
	}
	g_tlslib_ctx = SSL_CTX_new(TLS_client_method());
	if(!g_tlslib_ctx) {
		error(FUNC_LINE_FMT "TLS context initialization failed\n", __func__, __LINE__);
		return NULL;
	}
	SSL_CTX_set_default_verify_paths(g_tlslib_ctx);
	return g_tlslib_ctx;
}

TLS_CTX* requests_get_tls_context(void) {
	return g_tlslib_ctx;
}

static TLS_CONN* tls_conn_new(void) {
	SSL* ssl = SSL_new(g_tlslib_ctx);
	return ssl;
}

static void tls_conn_free(TLS_CONN* tls) {
	SSL_free(tls);
}

static void tls_set_fd(TLS_CONN* tls, struct netio* io) {
	SSL_set_fd(tls, io->socket);
}

static void tls_configure_verify(TLS_CONN* tls) {
	SSL_set_verify(tls, SSL_VERIFY_PEER, NULL);
}

static int tls_connect(TLS_CONN* tls) {
	return SSL_connect(tls);
}

static void tls_set_sni(TLS_CONN* tls, char* hostname) {
	SSL_set_tlsext_host_name(tls, hostname);
}

static void tls_use_certificate_file(TLS_CONN* tls, char* certfile) {
	SSL_use_certificate_file(tls, certfile, SSL_FILETYPE_PEM);
}

static TLS_CERT* tls_get_peer_certificate(TLS_CONN* tls) {
	return SSL_get_peer_certificate(tls);
}

static void tls_cert_free(TLS_CERT* cert) {
	X509_free(cert);
}

static bool tls_get_verify_result(TLS_CONN* tls) {
	long result = SSL_get_verify_result(tls);
	if(result != X509_V_OK) {
		error(FUNC_LINE_FMT "certificate verification failed: code %ld\n", __func__, __LINE__, result);
		return false;
	}
	return true;
}

static int tls_write(TLS_CONN* tls, void* buf, size_t num) {
	return SSL_write(tls, buf, num);
}

static int tls_read(TLS_CONN* tls, void* buf, size_t num) {
	return SSL_read(tls, buf, num);
}

void requests_free_tls_context(void) {
	if(g_tlslib_ctx) {
		SSL_CTX_free(g_tlslib_ctx);
		g_tlslib_ctx = NULL;
	}
}

static ssize_t __secure_send(struct netio* conn_io, void* buf, size_t num) {
	return (ssize_t)tls_write(conn_io->ssl, buf, num);
}

static ssize_t __secure_recv(struct netio* conn_io, void* buf, size_t num) {
	return (ssize_t)tls_read(conn_io->ssl, buf, num);
}

void netio_close(struct netio* freeptr) {
	closesocket(freeptr->socket);
	if(freeptr->ssl) {
		tls_conn_free(freeptr->ssl);
	}
}

#else

void netio_close(struct netio* freeptr) {
	closesocket(freeptr->socket);
}

void* requests_get_tls_context(void) {
	return NULL;
}

void requests_free_tls_context(void) {
	return;
}

#endif // #ifndef REQUESTS_NO_TLS

/* ----------------------------------
 |				     |
 |	  utility functions          |
 |				     |
  ---------------------------------- */

static char* method_to_str(enum REQUEST_METHOD method) {
	switch(method) {
	case GET:
		return "GET";
	case POST:
		return "POST";
	case PUT:
		return "PUT";
	case OPTIONS:
		return "OPTIONS";
	case HEAD:
		return "HEAD";
	default:
		return NULL;
	}
}

static char* http_version_str(enum HTTPVER ver) {
	switch(ver) {
	case HTTP_1_0:
		return "HTTP/1.0";
	case HTTP_1_1:
		return "HTTP/1.1";
	default:
		return NULL;
	}
}

static char* clone_string(char* src, int len) {
	if(len == 0) {
		return NULL;
	}
	char* dst = malloc(len + 1);
	strncpy(dst, src, len);
	dst[len] = '\0';
	return dst;
}

static int cistrcmp(const char* a, const char* b) {
	uint8_t diff = 0;
	while(diff == 0 && *a && *b) {
		diff = tolower(*a) - tolower(*b);
		a++, b++;
	}
	return diff;
}

static int cistrncmp(const char* a, const char* b, int n) {
	uint8_t diff = 0;
	while(diff == 0 && *a && *b && n > 0) {
		diff = tolower(*a) - tolower(*b);
		n--, a++, b++;
	}
	return diff;
}

void header_add_sized(struct header* headers, char* key, size_t key_size, char* value, size_t value_size) {
	size_t n_entries = headers->num_entries;
	headers->entries = reallocate(headers->entries, 
			n_entries * sizeof(*headers->entries), (n_entries + 1) * sizeof(*headers->entries));
	headers->num_entries++;
	headers->entries[n_entries].name = clone_string(key, key_size);
	headers->entries[n_entries].value = clone_string(value, value_size);
}

void header_add(struct header* headers, char* key, char* value) {
	size_t n_entries = headers->num_entries;
	headers->entries = reallocate(headers->entries, 
			n_entries * sizeof(*headers->entries), (n_entries + 1) * sizeof(*headers->entries));
	headers->num_entries++;
	headers->entries[n_entries].name = clone_string(key, strlen(key));
	headers->entries[n_entries].value = clone_string(value, strlen(value));
}

struct response* alloc_response(void) {
	struct response* response = malloc(sizeof(*response));
	memset(response, 0, sizeof(*response));
	return response;
}

void free_header(struct header* freeptr) {
	if(!freeptr || freeptr->entries == NULL) return;
	for(size_t i = 0; i < freeptr->num_entries; i++) {
		free(freeptr->entries[i].name);
		if(freeptr->entries[i].value != NULL) {
			free(freeptr->entries[i].value);
		}
	}
	free(freeptr->entries);
}

struct params* clone_params(struct params* p) {
	struct params* new = malloc(sizeof(*new));
	new->num_params = p->num_params;
	new->params = malloc(new->num_params * sizeof(*new->params));
	for(size_t i = 0; i < new->num_params; i++) {
		new->params[i].name = clone_string(p->params[i].name, strlen(p->params[i].name));
		new->params[i].value = clone_string(p->params[i].value, strlen(p->params[i].value));
	}
	new->repr = clone_string(p->repr, strlen(p->repr));
	return new;
}

struct url clone_url(struct url* u) {
	struct url new = { 0 };
	new.port = u->port;
	new.protocol = u->protocol;
	if(u->route) {
		new.route = clone_string(u->route, strlen(u->route));
	}
	if(u->hostname) {
		new.hostname = clone_string(u->hostname, strlen(u->hostname));
	}
	if(u->params) {
		new.params = clone_params(u->params);
	}
	return new;
}

struct url url_redirect(struct url* current, char* location) {
	if(!location) return (struct url){ 0 };
	if(location[0] == '/') {
		struct url src = *current;
		src.route = NULL;
		src.params = NULL;
		struct url new = clone_url(&src);
		struct url redirect = resolve_url(location);
		new.route = redirect.route;
		new.params = redirect.params;
		return new;
	} else {
		return resolve_url(location);
	}
}

char* url_get_filename(struct url* url) {
	char* filename = NULL;
	if(url->route) {
		char* destination = strrchr(url->route, '/');
		if(!destination) {
			return NULL;
		}

		destination++;
		if(*destination != '\0') {
			filename = destination;
		}
	}
	return filename;
}

static void recv_data_buffered(struct netreader* rd, struct ostream* outstream, uint64_t data_length, enum HTTPSTATUS code, requests_user_cb_t user_cb, void* user_data) {
	char buf[REQUESTS_RECV_BUFSIZE] = { 0 };
	struct download_state s = { .buffer.data = buf, .content_length = data_length, .bytes_left = data_length, .status_code = code };

	while(s.bytes_left > 0 && (s.buffer.size = net_rd_recv(rd, s.buffer.data, MIN(s.bytes_left, REQUESTS_RECV_BUFSIZE))) > 0) {
		s.bytes_left -= s.buffer.size;
		if(user_cb != NULL) {
			user_cb(&s, user_data);
		}
		outstream->write(outstream, s.buffer.data, s.buffer.size);
	}
}

static void send_data_buffered(struct netio* io, struct __sized_buf* buffer) {
	size_t bytes_left = buffer->size;
	size_t buf_idx = 0;
	size_t bytes_sent = 0;
	while(bytes_left > 0 && (bytes_sent = io->send(io, &(buffer->data[buf_idx]), bytes_left)) > 0) {
		bytes_left -= bytes_sent;
		buf_idx += bytes_sent;
	}
}

void free_params(struct params* freeptr) {
	if(!freeptr || freeptr->params == NULL) return;
	if(freeptr->repr) {
		free(freeptr->repr);
	}

	for(size_t i = 0; i < freeptr->num_params; i++) {
		free(freeptr->params[i].name);
		if(freeptr->params[i].value != NULL) {
			free(freeptr->params[i].value);
		}
	}
	free(freeptr->params);
}

static void free_url_strings(struct url* freeptr) {
	if(freeptr->route) {
		free(freeptr->route);
	}
	if(freeptr->hostname) {
		free(freeptr->hostname);
	}
}

void free_url(struct url* freeptr) {
	if(!freeptr) return;
	free_url_strings(freeptr);
	if(freeptr->params) {
		free_params(freeptr->params);
		free(freeptr->params);
	}
}

void free_response(struct response* freeptr) {
	free_header(&freeptr->header);
	free(freeptr->status_line);
	if(freeptr->url) {
		free_url(freeptr->url);
		free(freeptr->url);
	}
	if(freeptr->body.data) {
		free(freeptr->body.data);
	}
	free(freeptr);
}

static void net_rd_close(struct netreader* rd) {
	netio_close(rd->io);
	free(rd->buf);
	memset(rd, 0, sizeof(*rd));
}

/* ----------------------------------
 |				     |
 |	  connection functions       |
 |				     |
  ---------------------------------- */

static int connect_to_host(struct url* url) {
	int socket_fd;
        struct addrinfo hints = {0};
        struct addrinfo *hostinfo, *conn;

        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        int err = getaddrinfo(url->hostname, NULL, &hints, &hostinfo);
        if(err) {
        	error(FUNC_LINE_FMT "getaddrinfo failed: %s\n", __func__, __LINE__, gai_strerror(err));
		return -1;
        }

	struct sockaddr_in* socket_address = NULL;
        for(conn = hostinfo; conn != NULL; conn = conn->ai_next) {
		socket_address = (struct sockaddr_in*)conn->ai_addr;
		socket_address->sin_port = htons(url->port);
		debug(FUNC_LINE_FMT "found host ip: '%s'\n", __func__, __LINE__, inet_ntoa(socket_address->sin_addr));
        	socket_fd = socket(conn->ai_family, conn->ai_socktype, conn->ai_protocol);
        	if(socket_fd == -1)
        		continue;

		if(connect(socket_fd, conn->ai_addr, conn->ai_addrlen) != -1)
         		break;

        	closesocket(socket_fd);
        }

        freeaddrinfo(hostinfo);

        if(conn == NULL) {
        	error(FUNC_LINE_FMT "Failed to connect to %s://%s:%d%s\n", 
				__func__, __LINE__, (url->protocol == HTTP) ? "http" : "https", url->hostname, url->port, url->route);
		return -1;
        }
	return socket_fd;
}

#ifndef REQUESTS_NO_TLS
static bool connect_secure(struct netio* io, char* vfy_hostname, char* certfile, bool ignore_vfy) {
	if(io->socket < 0) return false;
	if(!tls_init_context()) {
		error(FUNC_LINE_FMT "failed to initialize SSL context\n", __func__, __LINE__);
		return false;
	}

	if(!(io->ssl = tls_conn_new())) {
		error(FUNC_LINE_FMT "failed to create SSL object\n", __func__, __LINE__);
		return false;
	}
	if(certfile) {
		debug(FUNC_LINE_FMT "Using custom certificate from '%s'\n", __func__, __LINE__, certfile);
		tls_use_certificate_file(io->ssl, certfile);
	}
	tls_set_sni(io->ssl, vfy_hostname);
	tls_set_fd(io->ssl, io);
	if(tls_connect(io->ssl)) {
		tls_configure_verify(io->ssl);
		TLS_CERT* server_cert = tls_get_peer_certificate(io->ssl);
		if(!server_cert) { 
			error(FUNC_LINE_FMT "No certificate was provided by the server\n", __func__, __LINE__);
			goto cleanup;
		}
		tls_cert_free(server_cert);
		if(!ignore_vfy && !tls_get_verify_result(io->ssl)) {
			goto cleanup;
		}
		io->send = __secure_send;
		io->recv = __secure_recv;
		return true;
	}

cleanup:
	tls_conn_free(io->ssl);
	io->ssl = NULL;
	return false;
}
#endif // #ifndef REQUESTS_NO_TLS

/* ----------------------------------
 |				     |
 |	  custom send functions      |
 |				     |
  ---------------------------------- */

static void send_format(struct netio* io, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	struct __sized_buf string = { 0 };
	string.size = vsnprintf(NULL, 0, fmt, args);
	string.data = malloc(string.size + 1);
	va_start(args, fmt);
	vsnprintf(string.data, string.size + 1, fmt, args);
	send_data_buffered(io, &string);
	free(string.data);
}

static void send_headers(struct netio* io, struct header* headers) {
	for(size_t i = 0; i < headers->num_entries; i++) {
		send_format(io, "%s: %s\r\n", headers->entries[i].name, headers->entries[i].value);
	}
	send_format(io, "\r\n");
}

static void send_host_header(struct netio* io, struct url* src_url) {
	send_format(io, "host: %s", src_url->hostname);
	if((src_url->protocol == HTTP && src_url->port != 80) ||
	   (src_url->protocol == HTTPS && src_url->port != 443)) {
		send_format(io, ":%d", src_url->port);
	}
	send_format(io, "\r\n");
}

static void send_content_length(struct netio* io, uint64_t content_length) {
	send_format(io, "Content-Length: %zu\r\n", content_length);
}

static void send_request_line(struct netio* io, enum REQUEST_METHOD method, enum HTTPVER version, struct url* host_url) {
	char* method_str = method_to_str(method);
	char* ver = http_version_str(version);
	char* get_params = "";
	if((host_url->params && host_url->params->repr != NULL) && method == GET) {
		get_params = host_url->params->repr;
	}

	send_format(io, "%s %s%s %s\r\n", method_str, host_url->route, get_params, ver);
}

/* ----------------------------------
 |				     |
 |	  parsing functions          |
 |				     |
  ---------------------------------- */

void header_add_str(struct header* headers, char* header_str) {
	char *name, *name_end, *value, *value_end;
	size_t name_size, value_size;
	name = header_str;
	name_end = strchr(name, ':');
	if(!name_end) {
		warn(FUNC_LINE_FMT "Header string is missing ':'\n", __func__, __LINE__);
		return;
	}
	name_size = name_end - name;
	value = name_end + 1;
	while(*value == ' ') {
		value++;
	}
	if(*value == '\0') {
		warn(FUNC_LINE_FMT "Header string has no value\n", __func__, __LINE__);
		return;
	}

	value_end = &value[strlen(value) - 1];
	if(value_end >= value) {
		while(*value_end == ' ') {
			value_end--;
		}
		value_size = (value_end + 1) - value;
	} else {
		value_size = 0;
	}
	header_add_sized(headers, name, name_size, value, value_size);
}

static char* parse_status_line(char* status_line, enum HTTPSTATUS* status_code) {
	char* reason_str = NULL;
	if(status_line) {
		char* status_code_str = strchr(status_line, ' ');
		if(!status_code_str) {
			return NULL;
		}
		reason_str = strchr(status_code_str, ' ');
		if(reason_str) {
			reason_str++;
		}
		*status_code = strtol(status_code_str, NULL, 10);
	}
	return reason_str;
}

static char* parse_query_pair(struct params* p, char* pair) {
	char* equal_sign = NULL;
	char* pair_end = NULL;
	char* value = NULL;
	size_t name_size = 0;
	size_t value_size = 0;
	size_t param_idx = 0;

	while(*pair == '&' || *pair == '?') {
		pair++;
	}

	if(!(pair_end = strchr(pair, '&'))) {
		pair_end = &pair[strlen(pair)];
	}

	if((equal_sign = strchr(pair, '=')) && equal_sign < pair_end) {
		param_idx = p->num_params;
		name_size = (equal_sign - pair);
		if(name_size <= 0) {
			return pair_end;
		}
		value = equal_sign + 1;
		value_size = (pair_end - value);

		p->params = reallocate(p->params, (param_idx) * sizeof(*p->params), (param_idx + 1) * sizeof(*p->params));

		p->params[param_idx].name = clone_string(pair, name_size);
		p->params[param_idx].value = clone_string(value, value_size);
		
		p->num_params++;

		debug(FUNC_LINE_FMT "parsed query pair: {\n\tname: \"%s\"\n\tvalue: \"%s\"\n}\n", 
				__func__, __LINE__, p->params[param_idx].name, p->params[param_idx].value);
	}

	return pair_end;
}

struct params* parse_query_string(char* str) {
	struct params* params = malloc(sizeof(*params));
	memset(params, 0, sizeof(*params));
	char* pair_begin = str;
	while(*pair_begin) {
		pair_begin = parse_query_pair(params, pair_begin);
	}
	return params;
}

struct url resolve_url(char* url_str) {
	struct url host_url = { .protocol = HTTP, .port = 80 };
	if(!url_str) {
		return (struct url){ 0 };
	}

	char* protocol_end = strchr(url_str, ':');
	if(protocol_end != NULL) {
		if(strlen(protocol_end) > STATIC_STRSIZE("://") && strncmp(protocol_end, "://", STATIC_STRSIZE("://")) == 0) {
			int protocol_size = protocol_end - url_str;

			if(protocol_size == STATIC_STRSIZE("https") && cistrncmp(url_str, "https", STATIC_STRSIZE("https")) == 0) {
				host_url.protocol = HTTPS;
				host_url.port = 443;
			}
		} else {
			protocol_end = NULL;
		}
	}

	char* hostname = (protocol_end != NULL) ? protocol_end + STATIC_STRSIZE("://") : url_str;
	size_t hostname_size;
	char* route_begin = strchr(hostname, '/');
	char* params_begin = NULL;
	if(route_begin != NULL) {
		size_t route_size = 0;
		hostname_size = (route_begin - hostname);
		if((params_begin = strchr(route_begin, '?'))) {
			route_size = (params_begin - route_begin);
			host_url.params = parse_query_string(params_begin);
			host_url.params->repr = clone_string(params_begin, strlen(params_begin));
		} else {
			route_size = strlen(route_begin);
		}
		
		host_url.route = clone_string(route_begin, route_size);
	} else {
		if((params_begin = strchr(hostname, '?'))) {
			hostname_size = (params_begin - hostname);
			host_url.params = parse_query_string(params_begin);
			host_url.params->repr = clone_string(params_begin, strlen(params_begin));
		} else {
			hostname_size = strlen(hostname);
		}

		host_url.route = clone_string("/", STATIC_STRSIZE("/"));
	}

	char* port_str = NULL;
	host_url.hostname = clone_string(hostname, hostname_size);
	if(host_url.hostname && (port_str = strchr(host_url.hostname, ':')) != NULL) {
		short port = strtol(port_str + 1, NULL, 10);
		if(errno == 0 && port >= 0) {
			host_url.port = port;
		}
		*port_str = '\0';
	}

	debug(FUNC_LINE_FMT "parsed url: {\n\tprotocol: %s\n\thostname: %s\n\troute: %s\n\tport: %d\n}\n",
			__func__, __LINE__, (host_url.protocol == HTTP) ? "HTTP" : "HTTPS", host_url.hostname, host_url.route, host_url.port);
	return host_url;
}

/* ----------------------------------
 |				     |
 |	request/response handlers    |
 |				     |
  ---------------------------------- */

static int determine_transfer_mode(struct header* headers, uint64_t* content_length) {
	char *cl_string, *te_string;
	if((cl_string = header_get_value(headers, "Content-Length"))) {
		*content_length = strtoull(cl_string, NULL, 10);
		return __TRANSFER_MODE_SIZED;
	} else if((te_string = header_get_value(headers, "Transfer-Encoding")) && cistrcmp(te_string, "chunked") == 0) {
		return __TRANSFER_MODE_CHUNKED;
	} else {
		return __TRANSFER_MODE_NODATA;
	}
}

static char* response_getline(char** raw_response) {
	char* line = *raw_response;
	char* new_line = NULL;
	char* line_end;
	size_t line_size;
        line_end = strchr(line, '\r');
	if(line_end != NULL && line_end[1] == '\n') {
		line_size = line_end - line;
		if(line_size > 0) {
			new_line = clone_string(line, line_size);
		}
		line_end += STATIC_STRSIZE("\r\n");
	} else {
		line_end = &line[strlen(line)];
		new_line = clone_string(line, strlen(line));
	}
	*raw_response = line_end;
	return new_line;
}

struct header_entry* header_get(struct header* headers, char* key) {
	for(size_t i = 0; i < headers->num_entries; i++) {
		if(cistrcmp(headers->entries[i].name, key) == 0)
			return &headers->entries[i];
	}
	return NULL;
}

char* header_get_value(struct header* headers, char* key) {
	struct header_entry* e = NULL;
	if((e = header_get(headers, key))) {
		return e->value;
	}
	return NULL;
}

struct parameter* params_get(struct params* params, char* key) {
	for(size_t i = 0; i < params->num_params; i++) {
		if(strcmp(params->params[i].name, key) == 0)
			return &params->params[i];
	}
	return NULL;
}

char* params_get_value(struct params* params, char* key) {
	struct parameter* p = NULL;
	if((p = params_get(params, key))) {
		return p->value;
	}
	return NULL;
}

static char* retrieve_raw_headers(struct netreader* rd) {
	char matchstr[] = "\r\n\r\n";
	uint8_t received = 0;
	char* buf = NULL;
	int match_counter = 0;
	uint64_t buf_idx = 0;
	char current_byte = '\0';
	while((received = net_rd_recv(rd, &current_byte, 1))) {
		if(matchstr[match_counter] == current_byte) {
			match_counter++;
		} else {
			match_counter = 0;
		}
		buf = reallocate(buf, buf_idx, buf_idx + 1);
		buf[buf_idx] = current_byte;
		buf_idx++;
		if(match_counter == STATIC_STRSIZE(matchstr)) {
			break;
		}
	}

	if(buf) {
		buf = reallocate(buf, buf_idx, buf_idx + 1);
		buf[buf_idx] = '\0';
	}
	return buf;
}

static char* parse_headers(struct response* resp, char* raw_headers) {
	char* endptr = raw_headers;
	char* line = response_getline(&endptr);
	debug("got status line: %s\n", line);
	resp->status_line = line;
	resp->reason = parse_status_line(resp->status_line, &resp->status_code);
	while(*endptr != '\0') {
		line = response_getline(&endptr);
		if(line == NULL) {
			break;
		}
		header_add_str(&resp->header, line);
		if(resp->header.num_entries > 0) {
			debug(FUNC_LINE_FMT "parsed header: {\n\tname: \"%s\",\n\tvalue: \"%s\"\n}\n", __func__, __LINE__, 
				resp->header.entries[resp->header.num_entries - 1].name, resp->header.entries[resp->header.num_entries - 1].value);
		}
		free(line);
	}
	return endptr;
}

static uint64_t get_chunk_length(struct netreader* rd) {
	uint64_t len = 0;
	char current_byte = '\0';
	uint8_t match_counter = 0;
	char sequence[] = "\r\n";
	uint8_t received = 0;
	size_t buf_idx = 0;
	char* buf = NULL;
	while((received = net_rd_recv(rd, &current_byte, 1))) {
		if(sequence[match_counter] == current_byte) {
			match_counter++;
		} else {
			match_counter = 0;
		}
		buf = reallocate(buf, buf_idx, buf_idx + 1);
		buf[buf_idx] = current_byte;
		buf_idx++;
		if(match_counter == STATIC_STRSIZE(sequence)) {
			buf = reallocate(buf, buf_idx, buf_idx + 1);
			buf[buf_idx] = '\0';
			len = strtoull(buf, NULL, 16);
			break;
		}
	}
	if(buf)
		free(buf);
	return len;
}

static struct response* retrieve_response(struct netreader* rd, struct ostream* outstream, requests_user_cb_t user_cb, void* user_data) {
	char* raw_headers = retrieve_raw_headers(rd);
	if(!raw_headers) {
		return NULL;
	}

	struct response* resp = alloc_response();
	parse_headers(resp, raw_headers);
	free(raw_headers);
	if(!outstream) {
		return resp;
	}

	uint64_t content_length = 0;
	uint8_t transfer_mode = determine_transfer_mode(&resp->header, &content_length);

	switch(transfer_mode) {
	case __TRANSFER_MODE_SIZED: {
		recv_data_buffered(rd, outstream, content_length, resp->status_code, user_cb, user_data);
		break;
	}

	case __TRANSFER_MODE_CHUNKED: {
		char endbuf[3] = {0};
		do {
			content_length = get_chunk_length(rd);
			recv_data_buffered(rd, outstream, content_length, resp->status_code, user_cb, user_data);
			net_rd_recv(rd, endbuf, 2);
		} while(content_length > 0);
		break;
	}

	case __TRANSFER_MODE_NODATA:
	default:
		break;
	}

	return resp;
}

static void do_request(struct netio* io, struct url* host_url, enum REQUEST_METHOD method, struct request_options* options) {
	bool have_to_send_body = OPTION(options, body.data) && (method == POST || method == PUT);
	send_request_line(io, method, (options) ? options->http_version : HTTP_1_1, host_url);
	if(options) {
		if(!header_get_value(&options->header, "host")) {
			send_host_header(io, host_url);
		}
		if(have_to_send_body && !header_get_value(&options->header, "Content-Length")) {
			send_content_length(io, options->body.size);
		}
		send_headers(io, &options->header);
	} else {
		send_host_header(io, host_url);
		send_format(io, "\r\n");
	}
	if(have_to_send_body) {
		send_data_buffered(io, &options->body);
	}
}

static struct response* perform_request(char* url_str, enum REQUEST_METHOD method, struct ostream* outstream, struct request_options* options) {
	struct url host_url = { 0 };
	struct netio conn_io = { .send = __not_secure_send, .recv = __not_secure_recv };
	host_url = OPTION(options, url) ? *options->url : resolve_url(url_str);	
	struct response* resp = NULL;
	
	if((conn_io.socket = connect_to_host(&host_url)) < 0) {
		error(FUNC_LINE_FMT "Failed to create socket\n", __func__, __LINE__);
		return NULL;
	}
#ifndef REQUESTS_NO_TLS
	if(!OPTION(options, disable_ssl) && host_url.protocol == HTTPS) {
		char* certfile = OPTION(options, cert) ? options->cert : NULL;
		if(!connect_secure(&conn_io, host_url.hostname, certfile, OPTION(options, ignore_verification))) {
			return NULL;
		}
	}
#endif // #ifndef REQUESTS_NO_TLS

	do_request(&conn_io, &host_url, method, options);

	requests_user_cb_t user_callback = OPTION(options, data_callback) ? options->data_callback : NULL;
	void* callback_data = OPTION(options, user_data) ? options->user_data : NULL;

	struct netreader conn_reader = net_rd_new(&conn_io);
	if((resp = retrieve_response(&conn_reader, outstream, user_callback, callback_data))) {
		resp->url = malloc(sizeof(*resp->url));
		memset(resp->url, 0, sizeof(*resp->url));
		*resp->url = OPTION(options, url) ? clone_url(&host_url) : host_url;
	}

	net_rd_close(&conn_reader);

	return resp;
}

struct response* requests_perform(char* url, enum REQUEST_METHOD method, struct request_options* options) {
	struct __sized_buf b = { 0 };
	struct ostream buffer_stream = os_create_buf(&b);
	struct response* r = NULL;
	r = perform_request(url, method, &buffer_stream, options);
	buffer_stream.close(&buffer_stream);
	if(r) {
		r->body = b;
	}
	return r;
}

struct response* requests_perform_file(char* url, char* filename, enum REQUEST_METHOD method, struct request_options* options) {
	struct ostream file_stream = os_create_file(filename);
	if(!file_stream.object) {
		return NULL;
	}
	struct response* r = perform_request(url, method, &file_stream, options);
	file_stream.close(&file_stream);
	return r;
}

struct response* requests_perform_fileptr(char* url, FILE* file, enum REQUEST_METHOD method, struct request_options* options) {
	if(!file) {
		error(FUNC_LINE_FMT "invalid file pointer\n", __func__, __LINE__);
		return NULL;
	}
	struct ostream file_stream = os_create_fileptr(file);
	struct response* r = perform_request(url, method, &file_stream, options);
	file_stream.close(&file_stream);
	return r;
}

struct response* requests_perform_no_body(char* url, enum REQUEST_METHOD method, struct request_options* options) {
	return perform_request(url, method, NULL, options);
}

struct response* requests_get(char* url, struct request_options* options) {
	return requests_perform(url, GET, options);
}

struct response* requests_get_file(char* url, char* filename, struct request_options* options) {
	return requests_perform_file(url, filename, GET, options);
}

struct response* requests_get_fileptr(char* url, FILE* file, struct request_options* options) {
	return requests_perform_fileptr(url, file, GET, options);
}

struct response* requests_head(char* url, struct request_options* options) {
	return requests_perform_no_body(url, HEAD, options);
}

struct response* requests_post(char* url, struct request_options* options) {
	return requests_perform(url, POST, options);
}

struct response* requests_post_file(char* url, char* filename, struct request_options* options) {
	return requests_perform_file(url, filename, POST, options);
}

struct response* requests_post_fileptr(char* url, FILE* file, struct request_options* options) {
	return requests_perform_fileptr(url, file, POST, options);
}

struct response* requests_put(char* url, struct request_options* options) {
	return requests_perform(url, PUT, options);
}

struct response* requests_put_file(char* url, char* filename, struct request_options* options) {
	return requests_perform_file(url, filename, PUT, options);
}

struct response* requests_put_fileptr(char* url, FILE* file, struct request_options* options) {
	return requests_perform_fileptr(url, file, PUT, options);
}

struct response* requests_options(char* url, struct request_options* options) {
	return requests_perform_no_body(url, OPTIONS, options);
}

#undef REQUESTS_IMPLEMENTATION
#endif // #ifdef REQUESTS_IMPLEMENTATION

#undef info
#undef warn
#undef error
#undef debug

#undef OPTION

#ifdef __cplusplus
}
#endif

#endif // #ifndef HAVE_REQUEST_H

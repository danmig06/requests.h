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
 *		- URL parameter parsing
 *		- User download callback
 *		- automatic filename detection on NULL filename
 *		- maybe Input Stream system
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <dlfcn.h>
#define LIBCRYPTO_NAME "libcrypto.so"
#define LIBSSL_NAME "libssl.so"
#define closesocket(s) close(s)

#elif defined(WIN32_LEAN_AND_MEAN) || defined(_WIN32) || defined(WIN32)

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>

#define RTLD_LAZY 0
#define RTLD_GLOBAL 0
#define dlopen(name, flags) LoadLibraryA(name)
#define dlsym(lib, name) (void*)GetProcAddress(lib, name)
#define dlclose(lib) FreeLibrary(lib)
#define LIBCRYPTO_NAME "libcrypto-3-x64.dll"
#define LIBSSL_NAME "libssl-3-x64.dll"

static char windows_errbuf[65536] = {0};
char* dlerror() {
	DWORD err = GetLastError();
	if(!err) {
		return NULL;	
	}

	snprintf(windows_errbuf, sizeof(windows_errbuf), "WinAPI error %d", err);

	return windows_errbuf;
}

#else
#error "unsupported platform"
#endif

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define LOGGER_SRCNAME "[requests.h]" 
#define FUNC_LINE_FMT "%s():%d: "
#define REQUESTS_RECV_BUFSIZE 1024 * 256 
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

struct url {
	enum PROTOCOL protocol;
	char* hostname;
	char* route;
	short port;
};

struct header_entry {
	char* name;
	char* value;
};

struct header {
	struct header_entry* entries;
	size_t num_entries;
};

struct request_options {
	struct __sized_buf body;
	bool disable_ssl;
	enum HTTPVER http_version;
	struct header header;
	struct url* url;
	char* params;
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
struct url* clone_url(struct url* u);

void header_add_sized(struct header* headers, char* key, size_t key_size, char* value, size_t value_size);
void header_add(struct header* headers, char* key, char* value);
void header_add_str(struct header* headers, char* header_str);

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

struct header_entry* header_get(struct header* headers, char* key);
char* header_get_value(struct header* headers, char* key);

struct response* alloc_response(void);
void free_response(struct response* freeptr);
void free_header(struct header* freeptr);

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
	SSL* ssl;
	int socket;
	netiofunc_t send;
	netiofunc_t recv;
};

static ssize_t __not_secure_send(struct netio* conn_io, void* buf, size_t num); 
static ssize_t __secure_send(struct netio* conn_io, void* buf, size_t num); 
static ssize_t __not_secure_recv(struct netio* conn_io, void* buf, size_t num); 
static ssize_t __secure_recv(struct netio* conn_io, void* buf, size_t num); 

static ssize_t __not_secure_send(struct netio* conn_io, void* buf, size_t num) {
	return send(conn_io->socket, buf, num, 0);
}

static ssize_t __not_secure_recv(struct netio* conn_io, void* buf, size_t num) { 
	return recv(conn_io->socket, buf, num, 0);
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
	b->data = reallocate(b->data, b->size, b->size + 1);
	b->data[b->size] = '\0';
	memset(os, 0, sizeof(*os));
}

/* ----------------------------------
 |				     |
 |	  SSL/crypto loader          |
 |				     |
  ---------------------------------- */

static struct {
	void* libcrypto;
	void* self;
	int (*init)(uint64_t, OPENSSL_INIT_SETTINGS*);
	SSL* (*new)(SSL_CTX*);
	SSL_CTX* (*ctx_new)(SSL_METHOD*);
	void (*ctx_set_options)(SSL_CTX*, uint64_t);
	SSL_METHOD* (*client_method)(void);
	void (*set_fd)(SSL*, int);
	int (*connect)(SSL*);
	int (*write)(SSL*, void*, size_t, size_t*);
	int (*read)(SSL*, void*, size_t, size_t*);
	long (*ctrl)(SSL*, int, long, void*);
	void (*set_verify)(SSL*, int, SSL_verify_cb);
	X509* (*get_peer_certificate)(SSL*);
	int (*ctx_set_default_verify_paths)(SSL_CTX *ctx);
	long (*get_verify_result)(SSL*);
	int (*use_certificate_file)(SSL*, char*, int);
	void (*free_ssl)(SSL*);
	void (*free_ssl_ctx)(SSL_CTX*);
	void (*free_x509)(X509*);
} libssl = { NULL };
static SSL_CTX* g_ssl_ctx = NULL;

static ssize_t __secure_send(struct netio* conn_io, void* buf, size_t num) {
	size_t wrotebytes = 0;
	libssl.write(conn_io->ssl, buf, num, &wrotebytes);
	return (ssize_t)wrotebytes;
}

static ssize_t __secure_recv(struct netio* conn_io, void* buf, size_t num) {
	size_t readbytes = 0;
	libssl.read(conn_io->ssl, buf, num, &readbytes);
	return (ssize_t)readbytes;
}

#ifndef REQUESTS_USE_SSL_STATIC

static void* __load_func(char* name, char** errptr) {
	void* fn = dlsym(libssl.self, name);
	if(!fn) {
		*errptr = dlerror();
		if((fn = dlsym(libssl.libcrypto, name))) {
			*errptr = NULL;
		} else {
			dlerror();
		}
	}
	return fn;
}

#define LOAD_FUNC(dst, func) \
	do { \
		char* err = NULL; \
		dst = __load_func(#func, &err); \
		if(err) { \
			error("Failed to load function " #func " from libssl: %s\n", err); \
			errcnt++; \
		} \
	} while(0);

#else

#define LOAD_FUNC(dst, func) \
	dst = (void*)func

#endif

static void* load_ssl_functions(void) {
	uint8_t errcnt = 0;
	if((libssl.libcrypto = dlopen(LIBCRYPTO_NAME, RTLD_LAZY | RTLD_GLOBAL)) == NULL) {
		error(FUNC_LINE_FMT "Failed to load libcrypto, libssl loading aborted: %s\n", __func__, __LINE__, dlerror());
		return NULL;
	}
	if((libssl.self = dlopen(LIBSSL_NAME, RTLD_LAZY)) == NULL) {
		error(FUNC_LINE_FMT "Failed to load libssl: %s\n", __func__, __LINE__, dlerror());
		dlclose(libssl.libcrypto);
		libssl.libcrypto = NULL;
		return NULL;
	}

	LOAD_FUNC(libssl.init, OPENSSL_init_ssl);
 	LOAD_FUNC(libssl.new, SSL_new);
	LOAD_FUNC(libssl.ctx_new, SSL_CTX_new);
	LOAD_FUNC(libssl.ctx_set_options, SSL_CTX_set_options);
	LOAD_FUNC(libssl.client_method, TLS_client_method);
	LOAD_FUNC(libssl.set_fd, SSL_set_fd);
	LOAD_FUNC(libssl.connect, SSL_connect);
	LOAD_FUNC(libssl.write, SSL_write_ex);
	LOAD_FUNC(libssl.read, SSL_read_ex);
	LOAD_FUNC(libssl.ctrl, SSL_ctrl);
	LOAD_FUNC(libssl.set_verify, SSL_set_verify);
	LOAD_FUNC(libssl.get_peer_certificate, SSL_get1_peer_certificate);
	LOAD_FUNC(libssl.ctx_set_default_verify_paths, SSL_CTX_set_default_verify_paths);
	LOAD_FUNC(libssl.get_verify_result, SSL_get_verify_result);
	LOAD_FUNC(libssl.use_certificate_file, SSL_use_certificate_file);
	LOAD_FUNC(libssl.free_ssl, SSL_free);
	LOAD_FUNC(libssl.free_ssl_ctx, SSL_CTX_free);
	LOAD_FUNC(libssl.free_x509, X509_free);

	if(errcnt > 0) {
		error(FUNC_LINE_FMT "Failed to load %d functions from libssl\n", __func__, __LINE__, errcnt);
		dlclose(libssl.libcrypto);
		dlclose(libssl.self);
		memset(&libssl, 0, sizeof(libssl));
	} else {
		info(FUNC_LINE_FMT "All libssl functions loaded successfully\n", __func__, __LINE__);
	}
	return libssl.self;
}
#undef LOAD_FUNC

static SSL_CTX* init_ssl_context(void) {
	if(g_ssl_ctx) {
		warn(FUNC_LINE_FMT "SSL context is already initialized\n", __func__, __LINE__);
		return g_ssl_ctx;
	}
	g_ssl_ctx = libssl.ctx_new(libssl.client_method());
	libssl.ctx_set_default_verify_paths(g_ssl_ctx);
	if(!g_ssl_ctx) {
		error(FUNC_LINE_FMT "SSL context initialization failed\n", __func__, __LINE__);
		return NULL;
	}
	return g_ssl_ctx;
}

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
	for(size_t i = 0; i < freeptr->num_entries; i++) {
		free(freeptr->entries[i].name);
		free(freeptr->entries[i].value);
	}
	free(freeptr->entries);
}

struct url* clone_url(struct url* u) {
	struct url* new = malloc(sizeof(*new));
	new->port = u->port;
	new->protocol = u->protocol;
	new->route = clone_string(u->route, strlen(u->route));
	new->hostname = clone_string(u->hostname, strlen(u->hostname));
	return new;
}

void free_url(struct url* freeptr) {
	free(freeptr->route);
	free(freeptr->hostname);
	free(freeptr);
}

void free_response(struct response* freeptr) {
	free_header(&freeptr->header);
	free(freeptr->status_line);
	free_url(freeptr->url);
	if(freeptr->body.data) {
		free(freeptr->body.data);
	}
	free(freeptr);
}

void netio_close(struct netio* freeptr) {
	closesocket(freeptr->socket);
	if(freeptr->ssl) {
		libssl.free_ssl(freeptr->ssl);
	}
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
        	if (socket_fd == -1)
        		continue;

      		if (connect(socket_fd, conn->ai_addr, conn->ai_addrlen) != -1)
         		break;

        	closesocket(socket_fd);
        }

        freeaddrinfo(hostinfo);

        if(conn == NULL) {
        	error(FUNC_LINE_FMT "Failed to connect to %s://%s%s:%d\n", __func__, __LINE__, (url->protocol == HTTP) ? "http" : "https", url->hostname, url->route, url->port);
		return -1;
        }
	return socket_fd;
}

static bool connect_secure(struct netio* io, char* vfy_hostname, char* certfile) {
	if(io->socket < 0) return false;
	if(!libssl.self) {
		if(!load_ssl_functions()) {
			return false;
		}
		if(!init_ssl_context()) {
			error(FUNC_LINE_FMT "failed to initialize SSL context\n", __func__, __LINE__);
			return false;
		}
	}
	if(!(io->ssl = libssl.new(g_ssl_ctx))) {
		error(FUNC_LINE_FMT "failed to create SSL object\n", __func__, __LINE__);
		return false;
	}
	if(certfile) {
		debug(FUNC_LINE_FMT "Using custom certificate from '%s'\n", __func__, __LINE__, certfile);
		libssl.use_certificate_file(io->ssl, certfile, SSL_FILETYPE_PEM);
	}
	// SSL_set_tlsext_host_name(io->ssl, vfy_hostname) -- very important, this sets up the Server Name Indication for cert verification
	libssl.ctrl(io->ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, vfy_hostname);
	libssl.set_fd(io->ssl, io->socket);
	if(libssl.connect(io->ssl)) {
		libssl.set_verify(io->ssl, SSL_VERIFY_PEER, NULL);
		X509* server_cert = libssl.get_peer_certificate(io->ssl);
		if(!server_cert) { 
			error(FUNC_LINE_FMT "No certificate was provided by the server\n", __func__, __LINE__);
			goto cleanup;
		}
		libssl.free_x509(server_cert);
		long result = 0;
		if((result = libssl.get_verify_result(io->ssl)) != X509_V_OK) {
			error(FUNC_LINE_FMT "certificate verification failed, code %ld\n", __func__, __LINE__, result);
			goto cleanup;
		}
		io->send = __secure_send;
		io->recv = __secure_recv;
		return true;
	}

cleanup:
	libssl.free_ssl(io->ssl);
	io->ssl = NULL;
	return false;
}

/* ----------------------------------
 |				     |
 |	  custom send functions      |
 |				     |
  ---------------------------------- */

static ssize_t send_format(struct netio* io, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	int str_len = vsnprintf(NULL, 0, fmt, args);
	char* string = malloc(str_len + 1);
	va_start(args, fmt);
	vsnprintf(string, str_len + 1, fmt, args);
	ssize_t bytes_sent = io->send(io, string, str_len);
	free(string);
	return bytes_sent;
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

static void send_request_line(struct netio* io, enum REQUEST_METHOD method, enum HTTPVER version, char* location) {
	char* method_str = method_to_str(method);
	char* ver = http_version_str(version);

	send_format(io, "%s %s %s\r\n", method_str, location, ver);
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
		warn(FUNC_LINE_FMT "Header string is missing ':'", __func__, __LINE__);
		return;
	}
	name_size = name_end - name;
	value = name_end + STATIC_STRSIZE(": ");
	value_end = &value[strlen(value)];
	value_size = value_end - value;
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
	if(route_begin != NULL) {
		hostname_size = (route_begin - hostname);
		host_url.route = clone_string(route_begin, strlen(route_begin));
	} else {
		hostname_size = strlen(hostname);
		host_url.route = clone_string("/", STATIC_STRSIZE("/"));
	}

	char* port_str = NULL;
	host_url.hostname = clone_string(hostname, hostname_size);
	if((port_str = strchr(host_url.hostname, ':')) != NULL) {
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

static int determine_transfer_mode(struct header* headers, int64_t* content_length) {
	char *cl_string, *te_string;
	if((cl_string = header_get_value(headers, "Content-Length"))) {
		*content_length = strtol(cl_string, NULL, 10);
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

static char* retrieve_raw_headers(struct netio* io) {
	char matchstr[] = "\r\n\r\n";
	uint8_t received = 0;
	char* buf = NULL;
	int match_counter = 0;
	int buf_idx = 0;
	char current_byte = '\0';
	while((received = io->recv(io, &current_byte, 1))) {
		if(matchstr[match_counter] == current_byte) {
			match_counter++;
		} else {
			match_counter = 0;
		}
		buf = reallocate(buf, buf_idx, buf_idx + 1);
		buf[buf_idx] = current_byte;
		buf_idx++;
		if(match_counter == STATIC_STRSIZE(matchstr)) {
			char* term_headers = clone_string(buf, buf_idx);
			free(buf);
			buf = term_headers;
			break;
		}
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
		debug(FUNC_LINE_FMT "parsed header: {\n\tname: \"%s\",\n\tvalue: \"%s\"\n}\n", __func__, __LINE__, 
				resp->header.entries[resp->header.num_entries - 1].name, resp->header.entries[resp->header.num_entries - 1].value);
		free(line);
	}
	return endptr;
}

static uint64_t get_chunk_length(struct netio* io) {
	uint64_t len = 0;
	char current_byte = '\0';
	uint8_t match_counter = 0;
	char sequence[] = "\r\n";
	uint8_t received = 0;
	size_t buf_idx = 0;
	char* buf = NULL;
	while((received = io->recv(io, &current_byte, 1))) {
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
			len = strtol(buf, NULL, 16);
			break;
		}
	}
	if(buf)
		free(buf);
	return len;
}

static struct response* retrieve_response(struct netio* io, struct ostream* outstream) {
	char* raw_headers = retrieve_raw_headers(io);
	if(raw_headers == NULL) {
		return NULL;
	}
	int64_t content_length =  -1;
	struct response* resp = alloc_response();
	parse_headers(resp, raw_headers);
	free(raw_headers);
	if(!outstream) {
		return resp;
	}
	uint8_t transfer_mode = determine_transfer_mode(&resp->header, &content_length);
	if(transfer_mode == __TRANSFER_MODE_NODATA) {
		return resp;
	}
	int bytes_received = 0;
	char buf[REQUESTS_RECV_BUFSIZE] = { 0 };
	switch(transfer_mode) {
	case __TRANSFER_MODE_SIZED: {
		while(content_length > 0 && (bytes_received = io->recv(io, buf, MIN(content_length, REQUESTS_RECV_BUFSIZE))) > 0) {
			outstream->write(outstream, buf, bytes_received);
			content_length -= bytes_received;
		}
		break;
	}
	case __TRANSFER_MODE_CHUNKED: {
		char endbuf[3] = {0};
		while(1) {
			content_length = get_chunk_length(io);
			if(content_length == 0) {
				io->recv(io, endbuf, 2);
				break;
			}
			while(content_length > 0 && (bytes_received = io->recv(io, buf, MIN(content_length, REQUESTS_RECV_BUFSIZE))) > 0) {
				outstream->write(outstream, buf, bytes_received);
				content_length -= bytes_received;
			}
			io->recv(io, endbuf, 2);
		}
		break;
	}
	}
	outstream->close(outstream);
	return resp;
}

static void do_request(struct netio* io, struct url* host_url, enum REQUEST_METHOD method, struct request_options* options) {
	bool have_to_send_body = OPTION(options, body.data) && (method == POST || method == PUT);
	send_request_line(io, method, (options) ? options->http_version : HTTP_1_1, host_url->route);
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
		io->send(io, options->body.data, options->body.size);
	}
}

static struct response* perform_request(char* url_str, enum REQUEST_METHOD method, struct ostream* outstream, struct request_options* options) {
	struct url host_url = { 0 };
	struct netio conn_io = { .ssl = NULL, .send = __not_secure_send, .recv = __not_secure_recv };
	host_url = OPTION(options, url) ? *options->url : resolve_url(url_str);	
	
	if((conn_io.socket = connect_to_host(&host_url)) < 0) {
		error(FUNC_LINE_FMT "Failed to create socket\n", __func__, __LINE__);
		return NULL;
	}
	if(!OPTION(options, disable_ssl) && host_url.protocol == HTTPS) {
		char* certfile = OPTION(options, cert) ? options->cert : NULL;
		if(!connect_secure(&conn_io, host_url.hostname, certfile)) {
			return NULL;
		}
	}

	do_request(&conn_io, &host_url, method, options);
	struct response* resp = retrieve_response(&conn_io, outstream);
	if(!resp) {
		error(FUNC_LINE_FMT "no response from '%s'", __func__, __LINE__, host_url.hostname);
		return NULL;
	}
	resp->url = clone_url(&host_url);
	if(!OPTION(options, url)) {
		free(host_url.route);
		free(host_url.hostname);
	}
	netio_close(&conn_io);
	return resp;
}

struct response* requests_get(char* url, struct request_options* options) {
	struct __sized_buf b = { 0 };
	struct ostream buffer_stream = os_create_buf(&b);
	struct response* r = NULL;
	if((r = perform_request(url, GET, &buffer_stream, options))) {
		r->body = b;
	}
	return r;
}

struct response* requests_get_file(char* url, char* filename, struct request_options* options) {
	struct ostream file_stream = os_create_file(filename);
	if(!file_stream.object) {
		return NULL;
	}
	return perform_request(url, GET, &file_stream, options);
}

struct response* requests_get_fileptr(char* url, FILE* file, struct request_options* options) {
	if(!file) {
		error(FUNC_LINE_FMT "invalid file pointer\n", __func__, __LINE__);
		return NULL;
	}
	struct ostream file_stream = os_create_fileptr(file);
	return perform_request(url, GET, &file_stream, options);
}

struct response* requests_head(char* url, struct request_options* options) {
	return perform_request(url, HEAD, NULL, options);
}

struct response* requests_post(char* url, struct request_options* options) {
	struct __sized_buf b = { 0 };
	struct ostream buffer_stream = os_create_buf(&b);
	struct response* r = NULL;
	if((r = perform_request(url, POST, &buffer_stream, options))) {
		r->body = b;
	}
	return r;
}

struct response* requests_post_file(char* url, char* filename, struct request_options* options) {
	struct ostream file_stream = os_create_file(filename);
	if(!file_stream.object) {
		return NULL;
	}
	return perform_request(url, POST, &file_stream, options);
}

struct response* requests_post_fileptr(char* url, FILE* file, struct request_options* options) {
	if(!file) {
		error(FUNC_LINE_FMT "invalid file pointer\n", __func__, __LINE__);
		return NULL;
	}
	struct ostream file_stream = os_create_fileptr(file);
	return perform_request(url, POST, &file_stream, options);
}

struct response* requests_put(char* url, struct request_options* options) {
	struct __sized_buf b = { 0 };
	struct ostream buffer_stream = os_create_buf(&b);
	struct response* r = NULL;
	if((r = perform_request(url, PUT, &buffer_stream, options))) {
		r->body = b;
	}
	return r;
}

struct response* requests_put_file(char* url, char* filename, struct request_options* options) {
	struct ostream file_stream = os_create_file(filename);
	if(!file_stream.object) {
		return NULL;
	}
	return perform_request(url, PUT, &file_stream, options);
}

struct response* requests_put_fileptr(char* url, FILE* file, struct request_options* options) {
	if(!file) {
		error(FUNC_LINE_FMT "invalid file pointer\n", __func__, __LINE__);
		return NULL;
	}
	struct ostream file_stream = os_create_fileptr(file);
	return perform_request(url, PUT, &file_stream, options);
}

struct response* requests_options(char* url, struct request_options* options) {
	return perform_request(url, OPTIONS, NULL, options);
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

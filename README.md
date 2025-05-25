# requests.h

``requests.h``is a single-header HTTP/HTTPS request library written in C99.

The aim of this project is to make HTTP/HTTPS requests simple in C, providing something similar to [python3's requests module](https://github.com/psf/requests).

It currently supports HTTP 1.0 and 1.1, also through TLS/SSL (HTTPS).

# Features

- Simple API focused on Ease-of-Use.
- No initialization required.
- Supports multiple TLS/SSL libraries: OpenSSL and wolfSSL (mbedTLS support coming soon).
- *browser-style* (supports [SNI](https://en.wikipedia.org/wiki/Server_Name_Indication)) certificate validation.
- Written in a little over 1000 lines of portable C99.

# Compiling

To compile your program you will need to satisfy the library's dependencies, these can be changed by using special defines:

- ``REQUESTS_NO_TLS`` allows you to build without any TLS/SSL library, thus removing all dependencies.
- ``REQUESTS_USE_WOLFSSL`` makes the library use wolfSSL (which will then need the LDFLAG ``-lwolfssl``).

not defining any of these will use OpenSSL by default (which requires the LDFLAGS ``-lssl -lcrypto``).

# Usage

here's a basic HTTP/HTTPS request from the [simple_get](https://github.com/danmig06/requests.h/blob/main/samples/simple_get.c) example:
```c
#define REQUESTS_IMPLEMENTATION
#include "requests.h"
#include <stdio.h>

int main(int argc, char** argv) {
        if(argc != 2) {
                printf("usage: %s <url>\n", argv[0]);
                return 1;
        }

#ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

        struct response* r = requests_get(argv[1], NULL);

        if(r) {
                printf("payload:\n%s\n", r->body.data);
                free_response(r);
        }

#ifdef _WIN32
        WSACleanup();
#endif

        return 0;
}
```

The behaviour of each of the ``requests_*`` functions in the API can be manipulated by using the members of the ``struct request_options``:
- ``body``: the body of the request to send, it has 2 members ``data`` and ``size``, if ``data`` is ``NULL`` then the request has no body.
- ``http_version``: the protocol version, can contain only 2 values: ``HTTP_1_0`` (-1) and ``HTTP_1_1`` (0), making HTTP 1.1 the default option.
- ``header``: an additional header to send, it is composed of ``entries``, which have a ``name`` and a ``value``, and ``num_entries``, you can add headers easily by using the ``header_add*`` functions.
- ``url``: an already parsed/split URL, when not ``NULL``, the URL string supplied to any of the ``requests_*`` functions is ignored and this struct is used instead.
- ``data_callback``: a pointer to a user-provided function which (when not ``NULL``) gets called each time data is received, it takes a ``struct download_state*`` and a ``void*``.
- ``user_data``: a pointer to user-supplied data, which gets passed to the ``data_callback`` as the second argument.
- ``ignore_verification``: when set to ``true``, ignores the result of the verification of the server's certificate, it is disabled by default, 
- ``cert``: the path to a custom ``.pem`` certificate file to be used by the selected TLS/SSL library for its handshake.

each of these functions will return a pointer to a ``struct response`` with the following members:
- ``body``: the body of the response, it has 2 members ``data`` and ``size``, if ``data`` is ``NULL`` then the response has no body, if it isn't then it is always terminated, so it can always be printed by using standard functions like ``printf``.
- ``header``: the response header, it is composed of ``entries``, which have a ``name`` and a ``value``, and ``num_entries``, it can be easily queried with the ``header_get*`` functions.
- ``status_line``: the status line, which has a form like ``<HTTP_version> <status_code> <reason>``.
- ``status_code``: the status code in enum form, taken from the status line.
- ``reason``: the reason string from the status line following the status code.
- ``url``: the source URL relative to this response, the lifetime of this object, like the other members, is tied to the whole structure that was returned.

# Useful details

The request functions **won't** take ownership of or modify the input objects passed through the ``struct request_options``, they will clone them if necessary, such as the response URL, which may be a new ``struct url`` or a clone of the input ``struct url`` if supplied.<br>

Using ``REQUESTS_NO_TLS`` implies that any communication is made in plain HTTP without encryption.<br>

You can obtain the context of the TLS/SSL library in use by calling ``requests_get_tls_context``, and may change its configuration.<br>

By default (with ``ignore_verification`` set to ``false``) any requests to untrusted servers **will not** be performed and will fail and, thus, return a ``NULL`` response.

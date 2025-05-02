# requests.h

Single header HTTP/HTTPS request library in C99<br>
The aim of this project is to make HTTP/HTTPS requests simple in C, providing something similar to [python3's requests module](https://github.com/psf/requests).
It currently supports HTTP 1.0 and 1.1, also through SSL (HTTPS).<br>
**This project is still work in progress and still needs many more features!**

# Features

- Simple API focused on Ease-of-Use
- No initialization required
- libssl loading at runtime only when needed, further reducing memory consumption
- Written in less than 1200 lines of GNU C99

# Usage

Compiling is just as easy as compling a regular C program, this library depends on ``libdl`` for SSL support
```bash
gcc <your_sources> <cflags> -ldl
```

basic HTTP/HTTPS request from the [simple_get](https://github.com/danmig06/requests.h/blob/main/samples/simple_get.c) example
```c
#include "requests.h"
#include <stdio.h>

int main(int argc, char** argv) {
        if(argc != 2) {
                printf("usage: %s <url>\n", argv[0]);
                return 1;
        }

        struct response* r = requests_get(argv[1], NULL);

        if(r) {
                printf("payload:\n%s\n", r->body.data);
                free_response(r);
        }
        return 0;
}
```

The behaviour of each of the ``requests_*`` functions in the API can be manipulated by using the members of the ``struct request_options``:
- ``body``: the body of the request to send, it has 2 members ``data`` and ``size``, if ``data`` is ``NULL`` then the request has no body.
- ``disable_ssl``: if set to ``true`` inhibits the use of SSL functions, even if ``libssl`` has been loaded and initialized.
- ``http_version``: the protocol version, can contain only 2 values: ``HTTP_1_0`` (-1) and ``HTTP_1_1`` (0), making HTTP 1.1 the default option.
- ``header``: an additional header to send, it is composed of ``entries``, which have a ``name`` and a ``value``, and ``num_entries``, you can add headers easily by using the ``header_add*`` functions.
- ``url``: an already parsed/split URL, when not ``NULL``, the URL string supplied to any of the ``request_*`` functions is ignored and this struct is used instead, it can be useful when handling redirects.

each of these functions will return a pointer to a ``struct response`` with the following members:
- ``body``: the body of the response, it has 2 members ``data`` and ``size``, if ``data`` is ``NULL`` then the response has no body.
- ``header``: the response header, it is composed of ``entries``, which have a ``name`` and a ``value``, and ``num_entries``, it can be easily queried with the ``header_get*`` functions.
- ``status_line``: the status line, which has a form like ``<HTTP_version> <status_code> <reason>``.
- ``status_code``: the status code in enum form, taken from the status line.
- ``reason``: the reason string from the status line following the status code.
- ``url``: the source URL relative to this response, the lifetime of this object, like the other members, is tied to the whole structure that was returned. 

# Useful details

The library will load ``libssl`` in an on-demand fashon, that means that when a request to an HTTPS site is made and the ``disable_ssl`` flag is not set, ``libssl`` and its dependency ``libcrypto`` will be loaded if not present, this **won't** cause problems if you link your program with ``-lssl -lcrypto``.<br><br>
The request functions **won't** take ownership of or modify the input objects passed through the ``struct request_options``, they will clone them if necessary, such as the response URL, which may be a new ``struct url`` or a clone of the input ``struct url`` if supplied.

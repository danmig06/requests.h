#define REQUESTS_IMPLEMENTATION
#include "requests.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

// basic downloader, detects filenames and follows redirects, tested with archive.org

int main(int argc, char** argv) {
	if(argc != 2) {
		printf("usage: %s <url>\n", argv[0]);
		return 1;
	}

#ifdef _WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

	requests_set_log_level(ALL);
	struct request_options o = { 0 };
	struct url u = resolve_url(argv[1]);
	o.url = &u;
	char* filename = url_get_filename(o.url);
	if(!filename) {
		filename = "page.html";
	}

	struct response* r = requests_get_file(NULL, filename, &o);
	
	if(!r) {
		free_url(o.url);
		return 1;
	}

	while(r->status_code > 300 && r->status_code < 307) {
		char* new_location = header_get_value(&r->header, "location");
		assert(new_location);
		free_url(o.url);
		*o.url = url_redirect(r->url, new_location);
		free_response(r);
		r = requests_get_file(NULL, filename, &o);
		if(!r) {
			free_url(o.url);
			return 0;
		}
	}
	free_response(r);
	free_url(&u);

	requests_unload_ssl();

#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}

#define REQUESTS_IMPLEMENTATION
#include "requests.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define BAR_LENGTH 50

// basic downloader, detects filenames and follows redirects, tested with archive.org

void data_callback(struct download_state* state, void*) {
	if(state->status_code != OK) return;
	uint64_t total_received = state->content_length - state->bytes_left;
	double progress = (double)total_received / (double)state->content_length;
	int n_full = progress * BAR_LENGTH;
	int n_empty = (1.0f - progress) * BAR_LENGTH;
	printf("\r[");
	for(int i = 0; i < n_full; i++) {
		putchar('=');
	}
	for(int i = 0; i < n_empty; i++) {
		putchar(' ');
	}
	printf("] %.1f%%", progress * 100.0f);
}

int main(int argc, char** argv) {
	if(argc < 2) {
		printf("usage: %s <url> [outfile]\n", argv[0]);
		return 1;
	}

#ifdef _WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

	// requests_set_log_level(ALL);
	struct request_options o = { .data_callback = data_callback };
	struct url u = resolve_url(argv[1]);
	o.url = &u;
	char* filename = url_get_filename(o.url);
	if(argc > 2) {
		filename = argv[2];
	}
	if(!filename) {
		filename = "page.html";
	}
	filename = strdup(filename);

	printf("downloading into \"%s\"...\n", filename);
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
	printf("\n");
	free(filename);
	free_response(r);
	free_url(&u);

	requests_free_tls_context();

#ifdef _WIN32
	WSACleanup();
#endif
	return 0;
}

#define REQUESTS_IMPLEMENTATION
#include "requests.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#define BAR_LENGTH 50
uint64_t total_downloaded = 0;
time_t current_time;
char speed_repr[256] = "0 B/s";

// basic downloader which also shows download speed, auto-detects filenames from URLs and follows redirects, tested with archive.org

char* dup_string(char* str) {
	size_t len = strlen(str);
	if(len == 0) {
		return NULL;
	}
	char* new_str = malloc(len + 1);
	strncpy(new_str, str, len);
	new_str[len] = '\0';
	return new_str;
}

void update_speed_ctr(void);

void data_callback(struct download_state* state, void*) {
	if(state->status_code != OK) return;
	time_t t;
	time(&t);
	if(difftime(t, current_time) >= 1.0f) {
		update_speed_ctr();
		total_downloaded = 0;
		time(&current_time);
	}
	uint64_t total_received = state->content_length - state->bytes_left;
	double progress = (double)total_received / (double)state->content_length;
	int n_full = progress * BAR_LENGTH;
	int n_empty = BAR_LENGTH - n_full;
	printf("\r[");
	for(int i = 0; i < n_full; i++) {
		putchar('=');
	}
	for(int i = 0; i < n_empty; i++) {
		putchar(' ');
	}
	printf("] %.1f%% (%s)", progress * 100.0f, speed_repr);
	total_downloaded += state->buffer.size;
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
	filename = dup_string(filename);

	printf("downloading into \"%s\"...\n", filename);
	time(&current_time);
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

enum UNIT {
	BYTES,
	KILOBYTES,
	MEGABYTES,
	GIGABYTES,
	TERABYTES,
	EXABYTES
};

char* get_unit_str(enum UNIT u) {
	switch(u) {
	case BYTES:
		return "B";
	case KILOBYTES:
		return "KB";
	case MEGABYTES:
		return "MB";
	case GIGABYTES:
		return "GB";
	case TERABYTES:
		return "TB";
	case EXABYTES:
		return "EB";
	default:
		return NULL;
	}
}

double get_repr_value(enum UNIT* unit) {
	enum UNIT units[] = {
		BYTES, KILOBYTES,
		MEGABYTES, GIGABYTES,
		TERABYTES, EXABYTES
	};
	double total = total_downloaded;
	int i = 0;

	while(total > 1000.0f) {
		total /= 1000.0f;
		i++;
	}
	*unit = units[i];
	return total;
}

void update_speed_ctr(void) {
	enum UNIT unit = BYTES;
	double speed = get_repr_value(&unit);
	snprintf(speed_repr, sizeof(speed_repr), "%.2f %s/s", speed, get_unit_str(unit));
}


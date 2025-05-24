#define REQUESTS_IMPLEMENTATION
#include "requests.h"
#include <stdio.h>
#include <string.h>

// usage: <program> [city]

char* make_url(char* city) {
	size_t str_len = snprintf(NULL, 0, "https://wttr.in/%s", city);
	char* string = malloc(str_len + 1);
	snprintf(string, str_len + 1, "https://wttr.in/%s", city);
	return string;
}

int main(int argc, char** argv) {

#ifdef _WIN32
	WSADATA wsa;
	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

	struct request_options o = { 0 };

	char* city = "";
	if(argc > 1) {
		city = argv[1];
	}
	char* url = make_url(city);
	header_add(&o.header, "User-Agent", "curl/7.88.1");
	struct response* r = requests_get(url, &o);
	free_header(&o.header);

	if(r && r->status_code == OK) {
		puts(r->body.data);
	}

	free_response(r);

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}

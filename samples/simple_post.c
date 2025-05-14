#define REQUESTS_IMPLEMENTATION
#include "requests.h"
#include <stdio.h>

int main(int argc, char** argv) {
	char message[] = "{\n\t\"message_was\": \"received\"\n}";
	if(argc != 2) {
		printf("usage: %s <url>\n", argv[0]);
		return 1;
	}

#ifdef _WIN32
	WSADATA wsa;
       	WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

	struct request_options o = { .body = { .data = message, .size = sizeof(message) - 1 } };

	struct response* r = requests_post(argv[1], &o);
	
	if(r) {
		printf("payload:\n%s\n", r->body.data);
		free_response(r);
	}

#ifdef _WIN32
	WSACleanup();
#endif

	return 0;
}

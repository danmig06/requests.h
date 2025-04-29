#include "requests.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char** argv) {
	char message[] = "{\n\t\"message_was\": \"received\"\n}";
	if(argc != 2) {
		printf("usage: %s <url>\n", argv[0]);
		return 1;
	}

	struct request_options o = { .body = { .data = message, .size = sizeof(message) - 1 } };

	struct response* r = requests_post(argv[1], &o);
	
	if(r) {
		printf("payload:\n%s\n", r->body.data);
		free_response(r);
	}
	return 0;
}

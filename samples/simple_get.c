#include "requests.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

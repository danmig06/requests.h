#include "requests.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
	struct request_options o;

	header_add(&o.header, "User-Agent", "curl/7.88.1");
	struct response* r = requests_get("https://wttr.in", &o);
	free_header(&o.header);

	if(r->status_code == OK) {
		puts(r->body.data);
	}

	free_response(r);
	return 0;
}

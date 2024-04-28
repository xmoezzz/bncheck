#include <stdlib.h>
char * bug_1() {
	char * buffer = malloc(1024);
	if (!buffer) return NULL;
	buffer[1025] = 1;
	return buffer;
}
char * bug_2() {
	char * buffer = malloc(2048);
	if (!buffer) return NULL;
	buffer = realloc(buffer, 1024);
	if (!buffer) return NULL;
	buffer[1025] = 1;
	return buffer;
}
char bug_3(int flag) {
	char * buffer = NULL;
	if (flag) {
		buffer = malloc(1024);
		if (!buffer) return 'A';
	}
	else {
		buffer = malloc(512);
		if (!buffer) return 'A';
	}
	return  buffer[1025];
}

char bug_4(int flag) {
	char buf[256];
	char *p = &buf[0];
	p += 1024;
	return *p;
}


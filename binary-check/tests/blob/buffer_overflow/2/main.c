#include <stdlib.h>
char * allocate_1024();
char * allocate_2048();
char * reallocate_1024(char * buffer);
char * allocate_512();
char * bug_1(char * buffer) {
	if (!buffer) return NULL;
	buffer[1025] = 1;
	return buffer;
}
char * helper_bug_1() {
	char * buffer = malloc(1024);
	return bug_1(buffer);
}


char * helper_bug_2() {
	char * buffer = malloc(1024);
	return buffer;
}
char * bug_2() {
	char * buffer = helper_bug_2();
	buffer[1025] = 1;
	return buffer;
}


int main() {
	return 0;
}

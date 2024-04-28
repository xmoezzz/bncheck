#include <stdlib.h>
void helper_1(char * buffer) {
	if (buffer == NULL) {
		return;
	}
	free(buffer);
}

char bug_1(char * buffer) {
	helper_1(buffer);
	return buffer[1024];
}

void helper_2(char * buffer) {
	if (buffer == NULL) {
		return;
	}
	if (buffer[0] == 1) { 
		//ref count
		free(buffer);
	}
	return;
}

char good_1(char * buffer) {
	helper_2(buffer);
	return buffer[1024];
}

char bug_2(char * buffer, int flag) {
    if (flag) {
        helper_1(buffer);
    }
    return buffer[1024];
}

char good_2(char ** p_list, int flag) {
    int i = 0;
    char * b;
    while (1) {
        char * a = p_list[i];
        b = a;
        if (a[1]) break;
        if (a[0]) {
            free(a); //A
        }
        i += 1;
    }

    return b[1024];
}

int main() {
    return 0;
}

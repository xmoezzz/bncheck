#include <stdlib.h>
void myf(char * buffer, int a) {
    if (buffer != NULL) {
        free(buffer);
    }
}
int main() {
    char * buffer = malloc(1024);
    myf(buffer, 19272);
}

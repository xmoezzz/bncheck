#include <stdio.h>


int main() {
    void *p = malloc(0x10);
    if (!p) {
        printf("malloc failed\n");
    }
    printf("%p\n", p);
}


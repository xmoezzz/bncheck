#include <stdio.h>


int main() {
    void *p = malloc(0x10);
    printf("%p\n", p);
}


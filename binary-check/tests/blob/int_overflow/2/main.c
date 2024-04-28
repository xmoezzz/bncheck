#include <stdio.h>

int vuln_function(int a, int b) {
    unsigned char* bitmap = (unsigned char*)malloc(a * 114514);
    for (int i = 0; i < a; i++) {
        bitmap[i + 0] = 'R';
        bitmap[i + 1] = 'G';
        bitmap[i + 2] = 'B';
        bitmap[i + 3] = 'A';
    }
    return b;
}

int main() {
    return vuln_function(6, 2333);
}

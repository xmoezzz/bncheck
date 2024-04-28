#include <stdio.h>

int print(int x) {
    return printf("%x", x);
}

int main() {
    int b = 0;
    for (int a = 0; a < 10; a++) {
        if (a > 3) {
            print(a + b);
        }
        else {
            print(a);
            b = a + 1;
        }
    }
    print(b);
    return 0;
}



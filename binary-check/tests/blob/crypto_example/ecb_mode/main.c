#include <stdio.h>

int gcry_cipher_open(void *hd, int algo, int mode, unsigned int flags)
{
    return printf("%p, %d %d %d\n", hd, algo, mode, flags);
}

int main() {
    gcry_cipher_open(0, 0, 1, 0);
}


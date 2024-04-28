#include <stdio.h>
#include <stdint.h>

static uint16_t xxx;

int main(int argc, char** argv)
{
    void* buffer = malloc(10);
    void* proc = (void*)main;
    uint16_t* ppp = &xxx;
    *ppp = 2;
    printf("%s, %p %p", buffer, proc, ppp);
    return 0;
}

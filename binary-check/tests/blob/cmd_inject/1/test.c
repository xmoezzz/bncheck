#include <stdio.h>
#include <stdlib.h>

void bug_function(const char* cmd) {
    char sys[0x100];
    sprintf(sys, "xxx %s", cmd);
    system(sys);
}

int main() {
    const char* name = getenv("2333333");
    system(name);
    bug_function(name);
    return 0;
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    char buf[64];
    if (!fgets(buf, sizeof(buf), stdin)) return 0;
    if (strstr(buf, "CRASH")) {
        /* trigger a crash for demo purposes */
        volatile int *p = NULL;
        *p = 1;
    }
    if (strstr(buf, "HELLO")) {
        printf("hello world\n");
    }
    return 0;
}

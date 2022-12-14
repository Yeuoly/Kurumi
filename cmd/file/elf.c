#include <stdio.h>
#include <stdlib.h>

char flag[] = {
    0x05,0x1f,0x14,0x14,0x0f,0x07,0x5c,0x1b,0x06,0x42,0x0e,0x16,0x2a,0x27,0x1b,0x2f,0x1f,0x37,0x11,0x11,0x0b,0x2c,0x46,0x42,0x12,0x0d
};

char *key = "csustpower";

int main () {
    char buf[27];
    printf("input your flag: ");
    scanf("%26s", buf);
    for (int i = 0; i < 26; i++) {
        buf[i] ^= key[i % 10];
    }

    if (memcmp(buf, flag, 26) == 0) {
        printf("correct\n");
    } else {
        printf("wrong\n");
    }
}
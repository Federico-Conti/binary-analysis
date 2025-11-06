#include <stdio.h>
int main()
{
    int i = 0xcafebabe; /* in this example sizeof(int) is 4 */
    short s = i;
    unsigned short us = i;
    signed char c = i;
    unsigned char uc = i;
    printf("i=%x\n", i);
    printf("s=%x us=%x\n", (int)s, (int)us);
    printf("c=%x uc=%x\n", (int)c, (int)uc);
}
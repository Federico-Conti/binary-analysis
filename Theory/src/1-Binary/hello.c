#include <stdio.h>

static void say_hello_world(void)
{
    printf("Hello, World!");
}

void newline()
{
   putchar('\n');
}

int main()
{
    say_hello_world();
    newline();
    return 0;
}

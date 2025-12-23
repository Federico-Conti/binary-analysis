#include <stdbool.h>

int still_bad_strcmp(const char *s1, const char *s2)
{
    while (*s1 && *s2 && *s1 == *s2)
    {
        ++s1;
        ++s2;
    }
    return *((unsigned char *)s1) - *((unsigned char *)s2);
    // (unsigned) chars are promoted
    // to int to perform the subtraction
}

bool check_password(const char *password)
{
    return still_bad_strcmp(password, "zxgio") == 0;
}

/*Timing Attack (Side-Channel Attack).*/
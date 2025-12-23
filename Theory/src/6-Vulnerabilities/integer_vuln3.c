#include <stdio.h>

int f(int a, int b, int c)
{
    if (b == 0 || c == 0)
    {
        printf("b and c cannot be zero!\n");
        return 0;
    }
    return a / (b * c);
}

int main()
{
    printf("%d\n", f(100, 65536, 65536)); /* Vulnerabilità: divisione per zero --> ovvia */
}




/*
 * Execution steps:
 *
 * 1. Check if b equals 65536:
 *    - If b == 65536, the result is not zero.
 *
 * 2. Check if c equals 65536:
 *    - If c == 65536, the result is not zero.
 *
 * 3. Multiply b and c:
 *    - b * c = 4294967296
 *    - On a 32-bit two's complement system, this value wraps around to 0 due to integer overflow.
 * 
 * b * c = 2^16 * 2^16 = 2^32 ≡ 0  (mod 2^32)
 */
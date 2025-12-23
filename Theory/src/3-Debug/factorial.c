#include <stdio.h>

int fact(int n)
{

    if (n >= 0)
    {
        const int tmp = fact(n - 1);
        return n * tmp;
    }
    return 1;
}
void factorial_of_5()
{
    const int f5 = fact(5);
    printf("The factorial of 5 is %d\n", f5);
}
int main()
{
    factorial_of_5();
    getchar();
    return 0;
}
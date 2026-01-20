#include <stdio.h>

void foo()
{
	char name[32] = "";
	printf("I'm at the beginning of foo(), and this is the current stack content:\n");
	printf("\nPlease enter your name: ");
	gets(name);
	printf("\nHi %s, this is a wonderful day to exploit a BOF vulnerability.\n\nI'm about to return to my caller, and the contents of the stack are:\n", name);
	printf("\n... returning ...\n");
}

int main()
{
	int x = 0xc0ffee;
	printf("+---------------+\n"
	       "|    BOF 101    |\n"
	       "| (x86/32-bits) |\n"
	       "+---------------+\n\n");
	printf("I'm in main().\nSince this is your first challenge, you'll get a leak for free: &x=%p\n\nNow, I'll call foo().\n\n", &x);
	foo();
	printf("\nI'm back in main(); exiting.\n");
}

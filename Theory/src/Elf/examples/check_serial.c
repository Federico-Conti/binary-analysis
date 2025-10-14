#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	if (argc!=2 || strcmp(argv[1], "pippero")) {
		fprintf(stderr, "\n*** WRONG! ***\n\n");
		return EXIT_FAILURE;
	}
	printf("Well done! :-)\n");
}

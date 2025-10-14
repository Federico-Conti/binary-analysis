#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>

int strcmp(const char *s1, const char *s2)
{
	static int (*real_strcmp)(const char *, const char *) = 0;
	if (!real_strcmp)
		real_strcmp = dlsym(RTLD_NEXT, "strcmp");

	int result = real_strcmp(s1, s2);
	fprintf(stderr, "strcmp(%s, %s)=%d\n", s1, s2, result);
	/* return result; */
	return 0;
}


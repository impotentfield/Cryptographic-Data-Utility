#include <stdio.h>
#include <stdarg.h>
#include "error.h"

char *prog;
int my_errno;
char enl;

void merror(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s: ", prog);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

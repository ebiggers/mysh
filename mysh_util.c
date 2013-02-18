/*
 * mysh_util.c
 *
 * Miscellaneous functions
 */

#include "mysh.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SHELL_NAME "mysh"

void mysh_error(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	fputs(SHELL_NAME ": error: ", stderr);
	vfprintf(stderr, fmt, va);
	fputc('\n', stderr);
	va_end(va);
}

void mysh_error_with_errno(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	fputs(SHELL_NAME ": error: ", stderr);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, ": %s", strerror(errno));
	fputc('\n', stderr);
	va_end(va);
}

void *xmalloc(size_t len)
{
	void *p = malloc(len);
	if (!p) {
		mysh_error("out of memory");
		exit(-1);
	}
	return p;
}

void *xstrdup(const char *s)
{
	const char *p = strdup(s);
	if (!p) {
		mysh_error("out of memory");
		exit(-1);
	}
	return p;
}

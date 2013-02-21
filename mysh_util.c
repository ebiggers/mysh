/*
 * mysh_util.c
 *
 * Miscellaneous functions
 */

#define _GNU_SOURCE
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

void *xmalloc(size_t size)
{
	void *p = malloc(size);
	if (!p) {
		mysh_error("out of memory");
		exit(-1);
	}
	return p;
}

void *xrealloc(void *ptr, size_t size)
{
	void *p = realloc(ptr, size);
	if (!p) {
		mysh_error("out of memory");
		exit(-1);
	}
	return p;
}

void *xzalloc(size_t size)
{
	return memset(xmalloc(size), 0, size);
}

char *xstrdup(const char *s)
{
	if (!s)
		return NULL;
	char *p = strdup(s);
	if (!p) {
		mysh_error("out of memory");
		exit(-1);
	}
	return p;
}

/* Allocates a new string with space for @len characters.  flags are initially
 * cleared. */
struct string *
new_string(size_t len)
{
	struct string *s = xmalloc(sizeof(struct string));
	s->chars = xzalloc(len + 1);
	s->len = len;
	s->flags = 0;
	return s;
}

/* Allocates a new string with a copy of the characters at @chars for @len
 * bytes.  flags are initially cleared. */
struct string *
new_string_with_data(const char *chars, size_t len)
{
	struct string *s = new_string(len);
	memcpy(s->chars, chars, len);
	return s;
}

void
clear_string(struct string *s)
{
	free(s->chars);
	s->chars = NULL;
	s->len = 0;
}

/* Frees a string, including the character data */
void
free_string(struct string *s)
{
	if (s) {
		free(s->chars);
		free(s);
	}
}

/* Frees a list of strings */
void
free_string_list(struct list_head *string_list)
{
	struct string *s, *tmp;
	list_for_each_entry_safe(s, tmp, string_list, list) {
		list_del(&s->list);
		free_string(s);
	}
}


/* Concatenates a list of strings and returns the resulting string, with all
 * flags cleared.  The original strings in the list are freed. */
struct string *
join_strings(struct list_head *strings)
{
	struct string *s, *new, *tmp;
	size_t len = 0;
	char *p;

	mysh_assert(!list_empty(strings));
	if (list_is_singular(strings)) /* no-op */
		return list_entry(strings->next, struct string, list);
	list_for_each_entry(s, strings, list)
		len += s->len;
	new = new_string(len);
	p = new->chars;
	list_for_each_entry_safe(s, tmp, strings, list) {
		p = mempcpy(p, s->chars, s->len);
		free_string(s);
	}
	return new;
}

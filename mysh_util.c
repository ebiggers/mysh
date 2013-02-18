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

void *xmalloc(size_t len)
{
	void *p = malloc(len);
	if (!p) {
		mysh_error("out of memory");
		exit(-1);
	}
	return p;
}

void *xzalloc(size_t len)
{
	return memset(xmalloc(len), 0, len);
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

struct string *
new_string(size_t len)
{
	struct string *s = xmalloc(sizeof(struct string));
	s->chars = xzalloc(len + 1);
	s->len = len;
	s->flags = 0;
	return s;
}

struct string *
new_string_with_data(const char *chars, size_t len)
{
	struct string *s = new_string(len);
	memcpy(s->chars, chars, len);
	s->chars[len] = '\0';
	return s;
}

void
free_string(struct string *s)
{
	free(s->chars);
	free(s);
}

void
free_string_list(struct list_head *string_list)
{
	struct string *s, *tmp;
	list_for_each_entry_safe(s, tmp, string_list, list) {
		list_del(&s->list);
		free_string(s);
	}
}


void
append_string(const char *chars, size_t len, struct list_head *out_list)
{
	struct string *s = new_string_with_data(chars, len);
	list_add_tail(&s->list, out_list);
}

struct string *
join_strings(struct list_head *strings)
{
	struct string *s, *new, *tmp;
	size_t len = 0;
	char *p;

	if (strings->next == strings->prev) /* no-op */
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

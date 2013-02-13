/*
 * A simple shell program.
 *
 * This shell can execute commands in the following ways:
 *   - with no command line arguments, in which cases commands are read from
 *   standard input
 *   - with the name of a file as a command line argument, in which case
 *   commands are read from the file
 *   - a single command passed as the argument to the '-c' option.
 *
 * Features include:
 *   - Each line of input is parsed as one or more sets of strings, with each
 *   set of strings separated by the '|' character, to form a pipeline.  An
 *   optional '&' character at the end of the line indicates that the pipeline
 *   is to be executed in the backgroud.  Each set of strings is interpreted as
 *   a program to execute with one or more command line arguments.  It may be
 *   followed by one or both of the special characters '<' and '>' followed by
 *   another string, which perform redirection of standard input and standard
 *   output to a file.
 *   - Strings may be unquoted, single-quoted, or double-quoted.  '\' is an
 *   escape character that escapes single quotes in single-quoted strings,
 *   double quotes in double-quoted strings, backslashes in all types of
 *   strings, and '&', '|', '>', '<', '"', '\'', ' ', and '\t' in unquoted
 *   strings.
 *   - Comments are supported (begin with '#' character)
 *
 * Limitations:
 *   - There are no shell variables.
 *   - Control statements such as 'if', 'for', and 'case' are not supported.
 *   - There are no shell builtins.
 *   - Multi-line commands are not supported (i.e. newline cannot be escaped,
 *     and strings cannot be multi-line).
 *   - ';' cannot be used to separate commands.
 *   - Redirecting standard error is not possible.
 *   - Filename globbing is not supported.
 *   - Functions are not supported.
 *   - Command substitution is not supported.
 *   - Arithmetic expansion is not supported.
 *   - Startup files are not supported.
 *   - Job control is not supported (other than the ability to start a pipeline
 *     in the backgroup)
 *   - Exit status of commands is not made available.
 */

#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHELL_NAME "mysh"

static void *xmalloc(size_t len)
{
	void *p = malloc(len);
	if (!p)
		error(1, 0, "out of memory");
	return p;
}

enum token_type {
	TOK_UNQUOTED_STRING      = 0x1,
	TOK_SINGLE_QUOTED_STRING = 0x2,
	TOK_DOUBLE_QUOTED_STRING = 0x4,
	TOK_PIPE                 = 0x8,
	TOK_STDIN_REDIRECTION    = 0x10,
	TOK_STDOUT_REDIRECTION   = 0x20,
	TOK_AMPERSAND            = 0x40,
	TOK_EOL                  = 0x80,
};

#define TOK_CLASS_STRING \
		(TOK_UNQUOTED_STRING | TOK_SINGLE_QUOTED_STRING | TOK_DOUBLE_QUOTED_STRING)

#define TOK_CLASS_REDIRECTION \
		(TOK_STDIN_REDIRECTION | TOK_STDOUT_REDIRECTION)

struct token {
	enum token_type type;
	char *tok_data;
};

static ssize_t scan_quoted_string(const char **pp, char quote_char,
				  char *out_buf)
{
	const char *p = *pp;
	bool escape = false;
	bool eos = false;
	size_t len = 0;

	while (!eos) {
		bool literal = true;
		char c = *p;
		switch (c) {
		case '\\':
			if (!escape) {
				escape = true;
				literal = false;
			}
			break;
		case '\0':
			fprintf(stderr, SHELL_NAME ": error: no terminating quote\n");
			return -1;
		default:
			if (c == quote_char) {
				if (!escape) {
					eos = true;
					literal = false;
				}
			}
			break;
		}
		if (literal) {
			if (out_buf)
				*out_buf++ = c;
			len++;
			escape = false;
		}
		p++;
	}
	*pp = p;
	return len;
}

static ssize_t scan_unquoted_string(const char **pp, char *out_buf)
{
	bool escape = false;
	const char *p = *pp;
	ssize_t len = 0;
	while (*p) {
		bool literal = true;
		char c = *p;
		switch (c) {
		case '\\':
			if (!escape) {
				escape = true;
				literal = false;
			}
			break;
		case '\'':
		case '"':
		case '&':
		case '#':
		case '|':
		case '>':
		case '<':
		case ' ':
		case '\t':
			if (!escape)
				goto out;
		default:
			break;
		}
		if (literal) {
			if (out_buf)
				*out_buf++ = c;
			len++;
			escape = false;
		}
		p++;
	}
out:
	*pp = p;
	return len;
}

static char *parse_quoted_string(const char **pp, char quote_char)
{
	ssize_t len;
	char *buf;
	const char *p = *pp;
	
	len = scan_quoted_string(&p, quote_char, NULL);
	if (len == -1)
		return NULL;
	buf = xmalloc(len + 1);
	scan_quoted_string(pp, quote_char, buf);
	buf[len] = '\0';
	return buf;
}

static char *parse_unquoted_string(const char **pp)
{
	ssize_t len;
	char *buf;
	const char *p = *pp;
	
	len = scan_unquoted_string(&p, NULL);
	if (len == -1)
		return NULL;
	buf = xmalloc(len + 1);
	scan_unquoted_string(pp, buf);
	buf[len] = '\0';
	return buf;
}

static struct token *next_token(const char **pp)
{
	const char *p = *pp;
	struct token *tok;
	enum token_type type;
	char *tok_data = NULL;

	switch (*p) {
	case '&':
		type = TOK_AMPERSAND;
		p++;
		break;
	case '\'':
		type = TOK_SINGLE_QUOTED_STRING;
		if (!(tok_data = parse_quoted_string(&p, '\'')))
			return NULL;
		break;
	case '"':
		type = TOK_DOUBLE_QUOTED_STRING;
		if (!(tok_data = parse_quoted_string(&p, '"')))
			return NULL;
		break;
	case '|':
		type = TOK_PIPE;
		break;
	case '<':
		type = TOK_STDIN_REDIRECTION;
		break;
	case '>':
		type = TOK_STDOUT_REDIRECTION;
		break;
	case '\0':
	case '#':
		type = TOK_EOL;
		break;
	default:
		type = TOK_UNQUOTED_STRING;
		if (!(tok_data = parse_unquoted_string(&p)))
			return NULL;
		break;
	}
	tok = xmalloc(sizeof(struct token));
	*pp = p;
	tok->type = type;
	tok->tok_data = tok_data;
	return tok;
}

static int execute_line(const char *line)
{
	struct token *tok;
	do {
		tok = next_token(&line);
		if (!tok)
			return -1;
	} while (tok->type != TOK_EOL);
	/* XXX */
	return 0;
}

int main(int argc, char **argv)
{
	int c;
	FILE *in;
	char *line = NULL;
	size_t n;
	ssize_t ret;
	int status;

	while ((c = getopt(argc, argv, "c:")) != -1) {
		switch (c) {
		case 'c':
			return execute_line(argv[1]);
		default:
			error(2, 0, SHELL_NAME ": invalid option");
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		in = fopen(argv[1], "rb");
		if (!in)
			error(1, errno, SHELL_NAME ": can't open %s", argv[1]);
	} else
		in = stdin;

	status = 0;
	while ((ret = getline(&line, &n, in)) >= 0)
		status = execute_line(line);

	if (ferror(in))
		error(1, errno, SHELL_NAME ": error reading from %s",
		      argc == 0 ? "stdin" : argv[1]);
	fclose(in);
	free(line);
	return status;
}

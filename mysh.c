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
 *   - There are no variables (shell variables, environmental variables,
 *     positional parameters)
 *   - Control statements such as 'if', 'for', and 'case' are not supported.
 *   - There are no shell builtins.
 *   - Multi-line commands are not supported (i.e. newline cannot be escaped,
 *     and strings cannot be multi-line).
 *   - ';' cannot be used to separate commands.
 *   - Redirecting standard error is not possible; 2>&1 and similar redirections
 *     will not work at all.
 *   - Filename globbing is not supported.
 *   - Functions are not supported.
 *   - Command substitution is not supported.
 *   - Arithmetic expansion is not supported.
 *   - Startup files are not supported.
 *   - Job control is not supported (other than the ability to start a pipeline
 *     in the backgroup)
 *   - Exit status of commands is not made available, except for the fact that
 *   the shell exit status is equal to the last exit status in the script.
 */

#include <errno.h>
#include <error.h>
#include <getopt.h>
#include <ctype.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHELL_NAME "mysh"
#define DEBUG 1

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

#define TOK_CLASS_CMD_BOUNDARY \
		(TOK_PIPE | TOK_EOL)

struct token {
	enum token_type type;
	char *tok_data;
	struct token *next;
};

static ssize_t scan_quoted_string(const char **pp, char quote_char,
				  char *out_buf)
{
	const char *p = *pp;
	bool escape = false;
	ssize_t len = 0;
	while (1) {
		char c = *p++;
		if (c == '\0') {
			/* string ended before we found the terminating quote */
			fprintf(stderr, SHELL_NAME ": error: no terminating quote\n");
			return -1;
		} else if (c == '\\' && !escape) {
			/* escape the next character */
			escape = true;
		} else if (c == quote_char && !escape) {
			/* found terminating quote */
			break;
		} else {
			/* literal character in the string */
			if (out_buf)
				*out_buf++ = c;
			len++;
			/* clear the escape flag */
			escape = false;
		}
	}
	*pp = p;
	return len;
}

static unsigned char is_special[256] = {
	[ '\\'] = 1,
	[ '\''] = 1,
	[ '"']  = 1,
	[ '&']  = 1,
	[ '#']  = 1,
	[ '|']  = 1,
	[ '>']  = 1,
	[ '<']  = 1,
	[ ' ']  = 1,
	[ '\t'] = 1,
	[ '\n'] = 1,
	[ '\r'] = 1,
};

static ssize_t scan_unquoted_string(const char **pp, char *out_buf)
{
	const char *p;
	ssize_t len = 0;
	bool escape = false;
	for (p = *pp; *p; p++) {
		if (is_special[(unsigned char)*p] && !escape) {
			if (*p == '\\') {
				escape = true;
				continue;
			} else
				break;
		}
		if (out_buf)
			*out_buf++ = *p;
		len++;
		escape = false;
	}
	*pp = p;
	return len;
}

/* Parse a quoted string where the opening quote character was at *((*pp) - 1).
 * Update *pp to point to the next character after the closing quote.
 * @quote_char gives the quote character (double quote or single quote).  Return
 * value is the literal string in newly allocated memory, or NULL on parse
 * error.
 */
static char *parse_quoted_string(const char **pp, char quote_char)
{
	ssize_t len;
	char *buf;
	const char *p = *pp;
	
	/* get string length */
	len = scan_quoted_string(&p, quote_char, NULL);
	if (len == -1)
		return NULL; /* parse error */
	buf = xmalloc(len + 1);
	/* get the string */
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

/* Return the next token from the line pointed to by *pp, and update *pp to
 * point to the next unparsed part of the line.  Returns NULL on parse error. */
static struct token *next_token(const char **pp)
{
	const char *p = *pp;
	struct token *tok;
	enum token_type type;
	char *tok_data = NULL;

	/* ignore whitespace between tokens */
	while (isspace(*p))
		p++;

	/* Choose the token type based on the next character, then parse the
	 * token. */
	switch (*p) {
	case '&':
		type = TOK_AMPERSAND;
		p++;
		break;
	case '\'':
		type = TOK_SINGLE_QUOTED_STRING;
		p++;
		if (!(tok_data = parse_quoted_string(&p, '\'')))
			return NULL; /* parse error */
		break;
	case '"':
		type = TOK_DOUBLE_QUOTED_STRING;
		p++;
		if (!(tok_data = parse_quoted_string(&p, '"')))
			return NULL; /* parse error */
		break;
	case '|':
		type = TOK_PIPE;
		p++;
		break;
	case '<':
		type = TOK_STDIN_REDIRECTION;
		p++;
		break;
	case '>':
		type = TOK_STDOUT_REDIRECTION;
		p++;
		break;
	case '\0': /* real end-of-line */
	case '#': /* everything after '#' character is a comment */
		type = TOK_EOL;
		break;
	default:
		/* anything that didn't match one of the special characters is
		 * treated as the beginning of an unquoted string */
		type = TOK_UNQUOTED_STRING;
		if (!(tok_data = parse_unquoted_string(&p)))
			return NULL; /* parse error */
		break;
	}
	/* allocate and initialize the token */
	tok = xmalloc(sizeof(struct token));
	tok->type = type;
	/* tok_data defaults to NULL if not explicitly set for a string token */
	tok->tok_data = tok_data;

	/* return the token and the pointer to the next unparsed character */
	*pp = p;
	return tok;
}

/* command -> string args redirections
 * args -> e | args string
 * redirections -> stdin_redirection stdout_redirection
 * stdin_redirection -> '<' STRING | e
 * stdout_redirection -> '<' STRING | e
 */
static int execute_pipeline(struct token *pipe_commands[],
			    unsigned int ncommands)
{
#ifdef DEBUG
	{
		unsigned i;
		printf("executing pipeline containing %u commands\n", ncommands);
		for (i = 0; i < ncommands; i++) {
			struct token *tok;
			printf("command %u: ", i);
			for (tok = pipe_commands[i]; tok; tok = tok->next) {
				switch (tok->type) {
				case TOK_UNQUOTED_STRING:
					printf("TOK_UNQUOTED_STRING(%s) ", tok->tok_data);
					break;
				case TOK_SINGLE_QUOTED_STRING:
					printf("TOK_SINGLE_QUOTED_STRING(%s) ", tok->tok_data);
					break;
				case TOK_DOUBLE_QUOTED_STRING:
					printf("TOK_DOUBLE_QUOTED_STRING(%s) ", tok->tok_data);
					break;
				case TOK_AMPERSAND:
					printf("TOK_AMPERSAND ");
					break;
				case TOK_STDIN_REDIRECTION:
					printf("TOK_STDIN_REDIRECTION ");
					break;
				case TOK_STDOUT_REDIRECTION:
					printf("TOK_STDOUT_REDIRECTION ");
					break;
				case TOK_EOL:
					printf("TOK_EOL ");
					break;
				case TOK_PIPE:
					printf("TOK_PIPE ");
					break;
				default:
					assert(0);
				}
			}
			putchar('\n');
		}
	}
#endif
}

/* Execute a line of input that has been parsed into tokens */
static int execute_tok_list(struct token *tok_list)
{
	struct token *tok, *prev;
	unsigned ncommands = 1;
	unsigned cmd_idx;
	bool cmd_boundary;


	tok = tok_list;
	if (tok->type == TOK_EOL) /* empty line */
		return 0;
	do {
		if (tok->type == TOK_PIPE)
			ncommands++;
		tok = tok->next;
	} while (tok->type != TOK_EOL);

	struct token *commands[ncommands];

	/* split the tokens into individual lists, around the '|' signs. */
	cmd_idx = 0;
	cmd_boundary = true;
	for (tok = tok_list, prev = NULL;
	     ;
	     prev = tok, tok = tok->next)
	{
		if (tok->type & TOK_CLASS_CMD_BOUNDARY) {
			if (cmd_boundary) {
				fprintf(stderr,
					SHELL_NAME ": error: empty command in pipeline\n");
				return -1;
			}
			prev->next = NULL;
			if (tok->type == TOK_EOL)
				break;
			cmd_boundary = true;
		} else if (cmd_boundary) {
			/* begin token list for next command */
			commands[cmd_idx++] = tok;
			cmd_boundary = false;
		}
	}
	return execute_pipeline(commands, cmd_idx);
}

/* Execute a line of input to the shell.  On parse error, returns -1.  On memory
 * allocation failure, aborts the program.  Otherwise, the return value is the
 * exit status of the last command in the pipeline executed, or 0 if there were
 * no commands in the pipeline (for example, just a comment). */
static int execute_line(const char *line)
{
	/* Parse the line into tokens, then pass control off to
	 * execute_tok_list(). */
	struct token *tok, *tok_list = NULL, *tok_list_tail = NULL;
	do {
		tok = next_token(&line);
		if (!tok) /* parse error */
			return -1;
		if (tok_list_tail)
			tok_list_tail->next = tok;
		else
			tok_list = tok;
		tok_list_tail = tok;
	} while (tok->type != TOK_EOL);
	return execute_tok_list(tok_list);
}

int main(int argc, char **argv)
{
	int c;
	FILE *in;
	char *line;
	size_t n;
	int status;

	while ((c = getopt(argc, argv, "c:")) != -1) {
		switch (c) {
		case 'c':
			return execute_line(optarg);
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
	line = NULL;
	while (1) {
		if (in == stdin)
			fputs("$ ", stdout);
		if (getline(&line, &n, in) == -1)
			break;
		status = execute_line(line);
	}

	if (ferror(in))
		error(1, errno, SHELL_NAME ": error reading from %s",
		      (argc == 0 ? "stdin" : argv[1]));
	fclose(in);
	free(line);
	return status;
}

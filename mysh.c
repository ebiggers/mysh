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
#include <getopt.h>
#include <ctype.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#define SHELL_NAME "mysh"
#define DEBUG 1

#ifdef DEBUG
#define MYSH_DEBUG printf
#endif

static void mysh_error(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	fputs(SHELL_NAME ": error: ", stderr);
	vfprintf(stderr, fmt, va);
	fputc('\n', stderr);
	va_end(va);
}

static void mysh_error_with_errno(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	fputs(SHELL_NAME ": error: ", stderr);
	vfprintf(stderr, fmt, va);
	fprintf(stderr, ": %s", strerror(errno));
	fputc('\n', stderr);
	va_end(va);
}

static void *xmalloc(size_t len)
{
	void *p = malloc(len);
	if (!p) {
		mysh_error("out of memory");
		exit(1);
	}
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

/* single quotes preserve the literal value of every character in the string. */
static ssize_t scan_single_quoted_string(const char **pp, char *out_buf)
{
	ssize_t len;
	char *term_quote = strchr(*pp, '\'');
	if (term_quote) {
		len = term_quote - *pp;
		if (out_buf)
			memcpy(out_buf, *pp, len);
		*pp = term_quote + 1;
	} else {
		/* string ended before we found the terminating quote */
		mysh_error("no terminating quote");
		len = -1;
	}
	return len;
}

static ssize_t scan_double_quoted_string(const char **pp, char *out_buf)
{
	const char *p = *pp;
	bool escape = false;
	ssize_t len = 0;
	while (1) {
		char c = *p++;
		if (c == '\0') {
			/* string ended before we found the terminating quote */
			mysh_error("no terminating quote");
			return -1;
		} else if (c == '\\' && !escape) {
			/* backslash: try to escape the next character */
			escape = true;
		} else if (c == '"' && !escape) {
			/* found terminating double-quote */
			break;
		} else if (c == '$' && !escape) {
			mysh_error("found '$' in double-quoted string, "
				   "but variable expansion is not supported");
			return -1;
		} else if (c == '`' && !escape) {
			mysh_error("found '`' in double-quoted string, "
				   "but command expansion is not supported");
			return -1;
		} else {
			if (escape && c != '$' && c != '`' && c != '\\' && c != '"') {
				/* backslash followed by a character that does
				 * not give backslash a special meaning */
				if (out_buf)
					*out_buf++ = '\\';
				len++;
			}
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

typedef ssize_t (*scan_string_t)(const char **pp, char *out_buf);

/* Parse a string (single-quoted, double-quoted, or unquoted, depending on the
 * @scan_string function).  Update *pp to point to the next character after the
 * end of the string.  Return value is the literal string in newly allocated
 * memory, or NULL on parse error.  */
static char *parse_string(const char **pp, scan_string_t scan_string)
{
	ssize_t len;
	char *buf;
	const char *p;
	
	/* get string length */
	p = *pp;
	len = scan_string(&p, NULL);
	if (len == -1)
		return NULL; /* parse error */
	buf = xmalloc(len + 1);
	/* get the string */
	scan_string(pp, buf);
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
	char *tok_data;

	/* ignore whitespace between tokens */
	while (isspace(*p))
		p++;

	/* Choose the token type based on the next character, then parse the
	 * token. */
	tok_data = NULL;
	switch (*p) {
	case '&':
		type = TOK_AMPERSAND;
		p++;
		break;
	case '\'':
		type = TOK_SINGLE_QUOTED_STRING;
		p++;
		if (!(tok_data = parse_string(&p, scan_single_quoted_string)))
			return NULL; /* parse error */
		break;
	case '"':
		type = TOK_DOUBLE_QUOTED_STRING;
		p++;
		if (!(tok_data = parse_string(&p, scan_double_quoted_string)))
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
		if (!(tok_data = parse_string(&p, scan_unquoted_string)))
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

struct redirections {
	const char *stdin_filename;
	const char *stdout_filename;
	int stdin_fd;
	int stdout_fd;
};

/* command -> string args redirections
 * args -> e | args string
 * redirections -> stdin_redirection stdout_redirection
 * stdin_redirection -> '<' STRING | e
 * stdout_redirection -> '<' STRING | e */
static int verify_command(const struct token *tok,
			  const bool is_last,
			  bool *async_ret,
			  unsigned *nargs_ret,
			  struct redirections *redirs_ret)
{
	unsigned nargs = 0;
	if (!(tok->type & TOK_CLASS_STRING)) {
		mysh_error("expected string as first token of command");
		return -1;
	}
	do {
		tok = tok->next;
		nargs++;
		if (!tok)
			return 0;
	} while (tok->type & TOK_CLASS_STRING);

	while (tok->type & TOK_CLASS_REDIRECTION) {
		const char **filename_p;
		if (!tok->next || !(tok->next->type & TOK_CLASS_STRING)) {
			mysh_error("expected filename after redirection operator");
			return -1;
		}
		if (tok->type == TOK_STDIN_REDIRECTION)
			filename_p = &redirs_ret->stdin_filename;
		else
			filename_p = &redirs_ret->stdout_filename;
		if (*filename_p)
			mysh_error("found multiple redirections for same stream");
		tok = tok->next;
		*filename_p = tok->tok_data;
		tok = tok->next;
		if (!tok)
			return 0;
	}
	if (is_last && tok->type == TOK_AMPERSAND) {
		*async_ret = true;
		tok = tok->next;
	}
	if (tok) {
		mysh_error("found trailing tokens in command");
		return -1;
	}
	return 0;
}

static int execute_pipeline(struct token *pipe_commands[],
			    unsigned int ncommands)
{
	unsigned i;
	unsigned npipes;
	unsigned nchildren;
	int ret;
	struct redirections redirs[ncommands];
	int pipe_fds[ncommands - 1][2];
	unsigned command_nargs[ncommands];
	pid_t child_pids[ncommands];
	bool async = false;

#ifdef DEBUG
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
#endif
	memset(redirs, 0, sizeof(redirs));
	for (i = 0; i < ncommands; i++) {
		ret = verify_command(pipe_commands[i],
				     (i == ncommands - 1),
				     &async, 
				     &command_nargs[i],
				     &redirs[i]);
		if (ret)
			return ret;
	}

	/* open pipes */
	for (npipes = 0; npipes < ncommands - 1; npipes++) {
		if (pipe(pipe_fds[npipes])) {
			mysh_error_with_errno("can't create pipe fds");
			ret = -1;
			goto out_close_pipes;
		}
	}

	/* open redirection files */
	for (i = 0; i < ncommands; i++) {
		if (redirs[i].stdin_filename != NULL) {
			redirs[i].stdin_fd = open(redirs[i].stdin_filename, O_RDONLY);
			if (redirs[i].stdin_fd <= 0) {
				mysh_error_with_errno("can't open %s for reading",
						      redirs[i].stdin_filename);
				ret = -1;
				goto out_close_redirection_files;
			}
		}
		if (redirs[i].stdout_filename != NULL) {
			redirs[i].stdout_fd = open(redirs[i].stdout_filename, O_WRONLY);
			if (redirs[i].stdout_fd <= 0) {
				mysh_error_with_errno("can't open %s for writing",
						      redirs[i].stdout_filename);
				ret = -1;
				goto out_close_redirection_files;
			}
		}
	}

	/* execute the commands */
	for (nchildren = 0; nchildren < ncommands; nchildren++) {
		ret = fork();
		if (ret == -1) {
			/* fork() error */
			mysh_error_with_errno("can't fork child process");
			goto out_wait_children;
		} else if (ret == 0) {
			/* child */
			int new_stdout_fd = -1;
			int new_stdin_fd = -1;
			if (nchildren != ncommands - 1) {
				/* not last in pipeline: stdout may be pipe */
				new_stdout_fd = pipe_fds[nchildren][1];
			}
			if (nchildren != 0) {
				/* not first in pipeline: stdin may be pipe */
				new_stdin_fd = pipe_fds[nchildren - 1][0];
			}
			/* overwrite pipes with redirections */
			if (redirs[nchildren].stdin_fd > 0)
				new_stdin_fd = redirs[nchildren].stdin_fd;
			if (redirs[nchildren].stdout_fd > 0)
				new_stdout_fd = redirs[nchildren].stdout_fd;
			if (new_stdin_fd > 0) {
				MYSH_DEBUG("dup stdin %d to %d\n", new_stdin_fd, 0);
				if (dup2(new_stdin_fd, 0) < 0) {
					mysh_error_with_errno("Failed to duplicate stdin "
							      "file descriptor");
					exit(-1);
				}
			}
			if (new_stdout_fd > 0) {
				MYSH_DEBUG("dup stdout %d to %d\n", new_stdout_fd, 1);
				if (dup2(new_stdout_fd, 1) < 0) {
					mysh_error_with_errno("Failed to duplicate stdout "
							      "file descriptor");
					exit(-1);
				}
			}

			char *argv[command_nargs[nchildren] + 1];
			struct token *tok = pipe_commands[nchildren];
			i = 0;
			argv[i++] = tok->tok_data;
			for (tok = tok->next; 
			     tok != NULL && (tok->type & TOK_CLASS_STRING);
			     tok = tok->next)
			{
				argv[i++] = tok->tok_data;
			}
			argv[i] = NULL;
			execvp(argv[0], argv);
			mysh_error_with_errno("Failed to execute %s", argv[0]);
			exit(-1);
		} else {
			child_pids[nchildren] = ret;
			/* parent */
		}
	}

	ret = 0;
out_wait_children:
	for (i = 0; i < nchildren; i++) {
		int status;
		if (waitpid(child_pids[i], &status, 0) == -1) {
			if (ret == 0)
				ret = -1;
			mysh_error_with_errno("Failed to wait for child with "
					      "pid %d to terminate", child_pids[i]);
		}
		if (WIFEXITED(status)) {
			if (ret == 0)
				ret = WEXITSTATUS(status);
		} else {
			mysh_error("Child process with pid %d was abnormally "
				   "terminated", child_pids[i]);
			if (ret == 0)
				ret = -1;
		}
	}
out_close_redirection_files:
	for (i = 0; i < ncommands; i++) {
		if (redirs[i].stdin_fd > 0)
			close(redirs[i].stdin_fd);
		if (redirs[i].stdout_fd > 0)
			close(redirs[i].stdout_fd);
	}
out_close_pipes:
	for (i = 0; i < npipes; i++) {
		close(pipe_fds[i][0]);
		close(pipe_fds[i][1]);
	}
	return ret;
}

/* Execute a line of input that has been parsed into tokens */
static int execute_tok_list(struct token *tok_list)
{
	struct token *tok, *prev;
	unsigned ncommands;
	unsigned cmd_idx;
	bool cmd_boundary;


	tok = tok_list;
	if (tok->type == TOK_EOL) /* empty line */
		return 0;

	/* split the tokens into individual lists (commands), around the '|'
	 * signs. */
	ncommands = 1;
	do {
		if (tok->type == TOK_PIPE)
			ncommands++;
		tok = tok->next;
	} while (tok->type != TOK_EOL);

	struct token *commands[ncommands];

	cmd_idx = 0;
	cmd_boundary = true;
	for (tok = tok_list, prev = NULL;
	     ;
	     prev = tok, tok = tok->next)
	{
		if (tok->type & TOK_CLASS_CMD_BOUNDARY) {
			if (cmd_boundary) {
				mysh_error("empty command in pipeline");
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
			mysh_error("invalid option");
			exit(2);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc) {
		in = fopen(argv[1], "rb");
		if (!in) {
			mysh_error("can't open %s: %s", strerror(errno));
			exit(1);
		}
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

	if (ferror(in)) {
		mysh_error("error reading from %s: %s",
			   (argc == 0 ? "stdin" : argv[1]), strerror(errno));
		status = 1;
	}
	fclose(in);
	free(line);
	return status;
}

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

/*#define DEBUG*/
#ifdef DEBUG
#define MYSH_DEBUG(fmt, ...) fprintf(stderr, fmt, ## __VA_ARGS__)
#else
#define MYSH_DEBUG(fmt, ...)
#endif

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))

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
	#if 0
		} else if (c == '$' && !escape) {
			mysh_error("found '$' in double-quoted string, "
				   "but variable expansion is not supported");
			return -1;
		} else if (c == '`' && !escape) {
			mysh_error("found '`' in double-quoted string, "
				   "but command expansion is not supported");
			return -1;
	#endif
		} else {
			if (
			    escape &&
			#if 0
			    c != '$' && c != '`' &&
			#endif
			    c != '\\' && c != '"') {
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

static const unsigned char is_special[256] = {
	['\0'] = 1,
	['\\'] = 1,
	['\''] = 1,
	['"']  = 1,
	['&']  = 1,
	['#']  = 1,
	['|']  = 1,
	['>']  = 1,
	['<']  = 1,
	[' ']  = 1,
	['\t'] = 1,
	['\n'] = 1,
	['\r'] = 1,
};

static ssize_t scan_unquoted_string(const char **pp, char *out_buf)
{
	const char *p;
	ssize_t len = 0;
	bool escape = false;
	for (p = *pp; ; p++) {
		if (is_special[(unsigned char)*p]) {
			if (*p == '\0')
				break;
			if (!escape) {
				if (*p == '\\') {
					escape = true;
					continue;
				} else
					break;
			}
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
	if (len < 0)
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
	tok->next = NULL;

	/* return the token and the pointer to the next unparsed character */
	*pp = p;
	return tok;
}

static void free_tok_list(struct token *tok)
{
	struct token *next;
	while (tok) {
		next = tok->next;
		free(tok->tok_data);
		free(tok);
		tok = next;
	}
}


struct redirections {
	const char *stdin_filename;
	const char *stdout_filename;
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
	if (!(tok->type & TOK_CLASS_STRING)) {
		mysh_error("expected string as first token of command");
		return -1;
	}
	*nargs_ret = 0;
	do {
		tok = tok->next;
		++*nargs_ret;
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
		if (*filename_p) {
			mysh_error("found multiple redirections for same stream");
			return -1;
		}
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

/* Executed by the child process after a fork().  The child now must set up
 * redirections of stdin and stdout (if any) and execute the new program. */
static void start_child(const struct token * const command_toks,
			const struct redirections * const redirs,
			const unsigned cmd_nargs,
			const unsigned pipeline_cmd_idx,
			const unsigned pipeline_ncommands,
			const int pipe_fds[2],
			const int prev_read_end)
{
	int new_stdout_fd = -1;
	int new_stdin_fd = -1;
	char *argv[cmd_nargs + 1];
	const struct token *tok;
	unsigned i;

	if (redirs->stdin_filename != NULL) {
		new_stdin_fd = open(redirs->stdin_filename, O_RDONLY);
		if (new_stdin_fd < 0) {
			mysh_error_with_errno("can't open %s for reading",
					      redirs->stdin_filename);
			exit(-1);
		}
	}
	if (redirs->stdout_filename != NULL) {
		new_stdout_fd = open(redirs->stdout_filename,
				     O_WRONLY | O_CREAT | O_TRUNC, 0666);
		if (new_stdout_fd < 0) {
			mysh_error_with_errno("can't open %s for writing",
					      redirs->stdout_filename);
			exit(-1);
		}
	}

	if (pipeline_cmd_idx != 0) {
		/* Not the first command in the pipeline:
		 * assign read end of pipe to stdin, or close it if it's not
		 * being used */
		if (new_stdin_fd < 0)
			new_stdin_fd = prev_read_end;
		else
			close(prev_read_end);
	}

	if (pipeline_cmd_idx != pipeline_ncommands - 1) {
		/* Not the last command in the pipeline: close read end of pipe
		 * we are writing to, then assign write end of pipe to stdout,
		 * or close it if it's not being used */
		close(pipe_fds[0]);
		if (new_stdout_fd < 0)
			new_stdout_fd = pipe_fds[1];
		else
			close(pipe_fds[1]);
	}
	if (new_stdin_fd >= 0) {
		MYSH_DEBUG("dup %d to stdin\n", new_stdin_fd);
		if (dup2(new_stdin_fd, STDIN_FILENO) < 0) {
			mysh_error_with_errno("Failed to duplicate stdin "
					      "file descriptor");
			exit(-1);
		}
		close(new_stdin_fd);
	}
	if (new_stdout_fd >= 0) {
		MYSH_DEBUG("dup %d to stdout\n", new_stdout_fd);
		if (dup2(new_stdout_fd, STDOUT_FILENO) < 0) {
			mysh_error_with_errno("Failed to duplicate stdout "
					      "file descriptor");
			exit(-1);
		}
		close(new_stdout_fd);
	}

	tok = command_toks;
	for (i = 0; i < cmd_nargs; i++, tok = tok->next)
		argv[i] = tok->tok_data;
	argv[i] = NULL;
	execvp(argv[0], argv);
	mysh_error_with_errno("Failed to execute %s", argv[0]);
	exit(-1);
}

struct builtin {
	const char *name;
};

static const struct builtin builtins[] = {
	{"pwd"},
	{"cd"},
	{"setenv"},
	{"getenv"},
	{"exit"},
};

#define NUM_BUILTINS ARRAY_SIZE(builtins)

#define for_builtin(b) \
		for (b = builtins; b != builtins + NUM_BUILTINS; b++)

static bool execute_builtin(const struct token *command_toks,
			    const struct redirections *redirs,
			    const unsigned command_nargs,
			    int *status_ret)
{
	const struct builtin *b;
	const char *name = command_toks->tok_data;
	int orig_stdout;
	int orig_stdin;
	int new_stdout;
	int new_stdin;
	int status = -1;

	for_builtin(b)
		if (strcmp(b->name, name) == 0)
			goto found_builtin;
	/* not a builtin command */
	return false;
found_builtin:
	if (redirs->stdout_filename) {
		orig_stdout = dup(STDOUT_FILENO);
		if (orig_stdout < 0) {
			mysh_error_with_errno("can't duplicate stdin file descriptor");
			goto out;
		}
		new_stdout = open(redirs->stdout_filename
	}
out:
	*status_ret = status;
	return true;
}

static int execute_pipeline(const struct token * const *pipe_commands,
			    unsigned ncommands)
{
	unsigned i;
	unsigned cmd_idx;
	int ret;
	struct redirections redirs[ncommands];
	int pipe_fds[2];
	int prev_read_end;
	unsigned command_nargs[ncommands];
	pid_t child_pids[ncommands];
	bool async;

#ifdef DEBUG
	printf("executing pipeline containing %u commands\n", ncommands);
	for (i = 0; i < ncommands; i++) {
		const struct token *tok;
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
	async = false;
	for (i = 0; i < ncommands; i++) {
		ret = verify_command(pipe_commands[i],
				     (i == ncommands - 1),
				     &async, 
				     &command_nargs[i],
				     &redirs[i]);
		if (ret)
			return ret;
	}

	/* If the pipeline only has one command and is not being executed
	 * asynchronously, try interpreting the command as a builtin. */
	if (ncommands == 1 || !async) {
		if (execute_builtin(pipe_commands[0], &redirs[0],
				    &command_nargs[0], &ret))
		    return ret;
		/* not a builtin */
	}

	/* Execute the commands */
	prev_read_end = pipe_fds[0] = pipe_fds[1] = -1;
	for (cmd_idx = 0; cmd_idx < ncommands; cmd_idx++) {

		/* Close any pipes we created that are no longer needed; also
		 * save the read end of the previous pipe (if any) in the
		 * prev_read_end variable.  */
		if (prev_read_end >= 0)
			close(prev_read_end);
		prev_read_end = pipe_fds[0];
		pipe_fds[0] = -1;
		if (pipe_fds[1] >= 0) {
			close(pipe_fds[1]);
			pipe_fds[1] = -1;
		}

		/* Unless this is the last command, create a new pair of pipes */
		if (cmd_idx != ncommands - 1) {
			if (pipe(pipe_fds)) {
				mysh_error_with_errno("can't create pipes");
				goto out_close_pipes;
			}
			MYSH_DEBUG("Created pipe\n");
		}

		/* Fork the process */
		ret = fork();
		if (ret < 0) {
			/* fork() error */
			mysh_error_with_errno("can't fork child process");
			goto out_close_pipes;
		} else if (ret == 0) {
			/* Child: set up file descriptors and execute new process */
			start_child(pipe_commands[cmd_idx], &redirs[cmd_idx],
				    command_nargs[cmd_idx], cmd_idx, ncommands,
				    pipe_fds, prev_read_end);
		} else {
			/* Parent: save child pid in an array */
			child_pids[cmd_idx] = ret;
		}
	}
	ret = 0;
out_close_pipes:
	if (pipe_fds[0] >= 0)
		close(pipe_fds[0]);
	if (pipe_fds[1] >= 0)
		close(pipe_fds[1]);
	if (prev_read_end >= 0)
		close(prev_read_end);
	if (ret == 0 && !async) {
		for (i = 0; i < cmd_idx; i++) {
			int status;
			MYSH_DEBUG("Wait for pid %d\n", child_pids[i]);
			/*if (wait(&status) == -1) {*/
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
	}
	return ret;
}

/* Execute a line of input that has been parsed into tokens.
 * Also is responsible for freeing the tokens. */
static int execute_tok_list(struct token *tok_list)
{
	struct token *tok, *prev, *next;
	unsigned ncommands;
	unsigned cmd_idx;
	unsigned i;
	bool cmd_boundary;
	int ret;

	tok = tok_list;
	if (tok->type == TOK_EOL) { /* empty line */
		free(tok);
		return 0;
	}

	/* split the tokens into individual lists (commands), around the '|'
	 * signs. */
	ncommands = 0;
	do {
		if (tok->type & TOK_CLASS_CMD_BOUNDARY)
			ncommands++;
		tok = tok->next;
	} while (tok);

	struct token *commands[ncommands];

	cmd_idx = 0;
	cmd_boundary = true;
	tok = tok_list;
	do {
		next = tok->next;
		if (tok->type & TOK_CLASS_CMD_BOUNDARY) {
			free(tok);
			if (cmd_boundary) {
				mysh_error("empty command in pipeline");
				free_tok_list(next);
				ret = -1;
				goto out;
			} else {
				prev->next = NULL;
				cmd_boundary = true;
			}
		} else if (cmd_boundary) {
			/* begin token list for next command */
			commands[cmd_idx++] = tok;
			cmd_boundary = false;
		}
		prev = tok;
		tok = next;
	} while (tok);
	ret = execute_pipeline((const struct token**)commands, cmd_idx);
out:
	for (i = 0; i < cmd_idx; i++)
		free_tok_list(commands[i]);
	return ret;
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
		if (!tok) { /* parse error */
			free_tok_list(tok_list);
			return -1;
		}
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
		in = fopen(argv[0], "rb");
		if (!in) {
			mysh_error("can't open %s: %s", argv[0], strerror(errno));
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
			   (argc == 0 ? "stdin" : argv[0]), strerror(errno));
		status = 1;
	}
	fclose(in);
	free(line);
	return status;
}

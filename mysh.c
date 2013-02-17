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

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))
#define ZERO_ARRAY(A) memset(A, 0, sizeof(A))

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

struct orig_fds {
	int orig_stdin;
	int orig_stdout;
};

static int undo_redirections(const struct orig_fds *orig)
{
	int ret = 0;
	if (orig->orig_stdin >= 0)
		if (dup2(orig->orig_stdin, STDIN_FILENO) < 0)
			ret = -1;
	if (orig->orig_stdout >= 0)
		if (dup2(orig->orig_stdout, STDOUT_FILENO) < 0)
			ret = -1;
	return ret;
}

/* Apply the redirections in the token list @redirs.  If @orig is non-NULL, save
 * the original file descriptors in there.  Return %true on success, %false on
 * failure. */
static int do_redirections(const struct token *redirs, struct orig_fds *orig)
{
	while (redirs && (redirs->type & TOK_CLASS_REDIRECTION)) {
		int open_flags;
		int dest_fd;
		int *orig_fd_p = NULL;
		int ret;
		int fd;
		const char *filename;

		if (redirs->type == TOK_STDIN_REDIRECTION) {
			open_flags = O_RDONLY;
			dest_fd = STDIN_FILENO;
			if (orig)
				orig_fd_p = &orig->orig_stdin;
		} else {
			open_flags = O_WRONLY | O_TRUNC | O_CREAT;
			dest_fd = STDOUT_FILENO;
			if (orig)
				orig_fd_p = &orig->orig_stdout;
		}

		if (orig_fd_p != NULL && *orig_fd_p < 0) {
			*orig_fd_p = dup(dest_fd);
			if (*orig_fd_p < 0) {
				mysh_error_with_errno("Failed to duplicate "
						      "file descriptor %d", dest_fd);
				goto out_undo_redirections;
			}
		}

		redirs = redirs->next;
		filename = redirs->tok_data;
		redirs = redirs->next;
		fd = open(filename, open_flags, 0666);
		if (fd < 0) {
			mysh_error_with_errno("can't open %s", filename);
			goto out_undo_redirections;
		}
		ret = dup2(fd, dest_fd);
		close(fd);
		if (ret < 0) {
			mysh_error_with_errno("can't perform redirection to or from %s",
					      filename);
			goto out_undo_redirections;
		}
	}
	return 0;
out_undo_redirections:
	if (orig)
		(void)undo_redirections(orig);
	return -1;
}

/* command -> string args redirections
 * args -> e | args string
 * redirections -> stdin_redirection stdout_redirection
 * stdin_redirection -> '<' STRING | e
 * stdout_redirection -> '<' STRING | e */
static int verify_command(const struct token *tok,
			  const bool is_last,
			  bool *async_ret,
			  unsigned *nargs_ret,
			  const struct token **redirs_ret)
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
		if (!*redirs_ret)
			*redirs_ret = tok;
		if (!tok->next || !(tok->next->type & TOK_CLASS_STRING)) {
			mysh_error("expected filename after redirection operator");
			return -1;
		}
		tok = tok->next;
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
			const struct token * const redirs,
			const unsigned cmd_nargs,
			const unsigned pipeline_cmd_idx,
			const unsigned pipeline_ncommands,
			const int pipe_fds[2],
			const int prev_read_end)
{
	char *argv[cmd_nargs + 1];
	const struct token *tok;
	unsigned i;

	/* Set up stdin and stdout for this component of the pipeline */

	if (pipeline_cmd_idx != pipeline_ncommands - 1) {
		/* Not the last command in the pipeline; close the read end of
		 * pipe we are writing to, then assign the write end of the pipe
		 * to stdout */
		close(pipe_fds[0]);
		if (dup2(pipe_fds[1], STDOUT_FILENO) < 0) {
			mysh_error_with_errno("Failed to set up stdout "
					      "for pipeline");
			goto fail;
		}
	}

	if (pipeline_cmd_idx != 0) {
		/* Not the first command in the pipeline; assign the read end of
		 * the previous pipe to stdin. */
		if (dup2(prev_read_end, STDIN_FILENO) < 0) {
			mysh_error_with_errno("Failed to set up stdin "
					      "for pipeline");
			goto fail;
		}
	}

	/* Apply other redirections */
	if (do_redirections(redirs, NULL) != 0)
		goto fail;

	/* Set up argv */
	tok = command_toks;
	for (i = 0; i < cmd_nargs; i++, tok = tok->next)
		argv[i] = tok->tok_data;
	argv[i] = NULL;

	/* Execute the new program */
	execvp(argv[0], argv);

	/* Control only reaches here if execvp() failed */
	mysh_error_with_errno("Failed to execute %s", argv[0]);
fail:
	exit(-1);
}

static int builtin_pwd(int argc, const char **argv)
{
	char *buf;
	int ret = -1;

	buf = getcwd(NULL, 0);
	if (!buf) {
		mysh_error_with_errno("pwd: can't get current working directory");
		goto out;
	}
	if (puts(buf) == EOF)
		mysh_error_with_errno("pwd: write error");
	else
		ret = 0;
	free(buf);
out:
	return ret;
}

static int builtin_cd(int argc, const char **argv)
{
	int ret;
	const char *dest_dir;

	if (argc < 2) {
		dest_dir = getenv("HOME");
		if (!dest_dir) {
			mysh_error("cd: HOME not set");
			ret = 1;
			goto out;
		}
	} else {
		dest_dir = argv[1];
	}
	if (chdir(dest_dir) != 0) {
		mysh_error_with_errno("cd: %s", dest_dir);
		ret = 1;
	} else {
		ret = 0;
	}
out:
	return ret;
}

struct builtin {
	const char *name;
	int (*func)(int argc, const char **argv);
};

static const struct builtin builtins[] = {
	{"pwd", builtin_pwd},
	{"cd", builtin_cd},
	{"setenv", NULL},
	{"getenv", NULL},
	{"exit", NULL},
};

#define NUM_BUILTINS ARRAY_SIZE(builtins)

static int execute_builtin(const struct builtin *builtin,
			   const struct token *command_toks,
			   const struct token *redirs,
			   unsigned cmd_nargs)
{
	struct orig_fds orig = {-1, -1};
	const char *argv[cmd_nargs + 1];
	const struct token *tok;
	unsigned i;
	int status;
	int ret;

	/* Do redirections for the builtin */
	status = do_redirections(redirs, &orig);
	if (status)
		return status;

	/* Prepare argv for the builtin */
	tok = command_toks;
	for (i = 0; i < cmd_nargs; i++, tok = tok->next)
		argv[i] = tok->tok_data;
	argv[i] = NULL;
	/* Call the builtin function */
	builtin->func(cmd_nargs, argv);

	/* Undo redirections for the builtin */
	ret = undo_redirections(&orig);
	if (ret) {
		if (status == 0)
			status = ret;
		mysh_error_with_errno("Failed to restore redirections");
	}
	return status;
}

static bool maybe_execute_builtin(const struct token *command_toks,
				  const struct token *redirs,
				  unsigned cmd_nargs,
				  int *status_ret)
{
	const char *name = command_toks->tok_data;
	size_t i;

	for (i = 0; i < NUM_BUILTINS; i++) {
		if (strcmp(builtins[i].name, name) == 0 && builtins[i].func) {
			/* The command matched a builtin.  Execute it. */
			*status_ret = execute_builtin(&builtins[i],
						      command_toks,
						      redirs, cmd_nargs);
			return true;
		}
	}
	/* Not a builtin command */
	return false;
}

static int execute_pipeline(const struct token * const *pipe_commands,
			    unsigned ncommands)
{
	unsigned i;
	unsigned cmd_idx;
	int ret;
	struct token *redirs[ncommands];
	int pipe_fds[2];
	int prev_read_end;
	unsigned command_nargs[ncommands];
	pid_t child_pids[ncommands];
	bool async;

	ZERO_ARRAY(redirs);
	async = false;
	for (i = 0; i < ncommands; i++) {
		ret = verify_command(pipe_commands[i],
				     (i == ncommands - 1),
				     &async, 
				     &command_nargs[i],
				     (const struct token**)&redirs[i]);
		if (ret)
			return ret;
	}

	/* If the pipeline only has one command and is not being executed
	 * asynchronously, try interpreting the command as a builtin. */
	if (ncommands == 1 || !async) {
		if (maybe_execute_builtin(pipe_commands[0], redirs[0],
					  command_nargs[0], &ret))
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
		}

		/* Fork the process */
		ret = fork();
		if (ret < 0) {
			/* fork() error */
			mysh_error_with_errno("can't fork child process");
			goto out_close_pipes;
		} else if (ret == 0) {
			/* Child: set up file descriptors and execute new process */
			start_child(pipe_commands[cmd_idx], redirs[cmd_idx],
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

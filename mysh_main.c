/*
 * mysh_main.c
 *
 * A simple shell program.
 *
 * This shell can execute commands in the following ways:
 *   - with no command line arguments to the shell, in which cases commands are
 *   read from standard input
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

#include "mysh.h"
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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
	 * asynchronously, try interpreting the command as a builtin.  Note:
	 * this means that with the current code, builtins cannot be used as
	 * parts of a multi-component pipeline. */
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
 * allocation failure, exits the shell with status 1.  Otherwise, the return
 * value is the exit status of the last command in the pipeline executed, or 0
 * if there were no commands in the pipeline (for example, just a comment). */
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

static void set_up_signal_handlers()
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) != 0)
		mysh_error_with_errno("Failed to set up signal handlers");
}

int main(int argc, char **argv)
{
	int c;
	FILE *in;
	char *line;
	size_t n;
	int status;

	set_up_signal_handlers();

	while ((c = getopt(argc, argv, "c:")) != -1) {
		if (c == 'c') {
			status = execute_line(optarg);
		} else {
			mysh_error("invalid option");
			status = 2;
		}
		goto out;
	}
	argc -= optind;
	argv += optind;
	if (argc) {
		in = fopen(argv[0], "rb");
		if (!in) {
			mysh_error_with_errno("can't open %s", argv[0]);
			status = 1;
			goto out;
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
		mysh_error("error reading from %s",
			   (argc == 0 ? "stdin" : argv[0]));
		status = 1;
	}
	fclose(in);
	free(line);
out:
	return status;
}

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
 *   - Control statements such as 'if', 'for', and 'case' are not supported.
 *   - Functions are not supported.
 *   - Command substitution is not supported.
 *   - Arithmetic expansion is not supported.
 *   - Startup files are not supported.
 *   - Job control is not supported (other than the ability to start a pipeline
 *     in the backgroup)
 */

#include "mysh.h"
#include "list.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>


/* globals */
int mysh_last_exit_status;
int mysh_filename_expansion_disabled;
int mysh_exit_on_error;
int mysh_write_input_to_stderr;
int mysh_noexecute;

/* Executed by the child process after a fork().  The child now must set up
 * redirections of stdin and stdout (if any) and execute the new program. */
static void
start_child(const struct list_head * const cmd_args,
	    const struct list_head * const redirs,
	    const struct list_head * const var_assignments,
	    const unsigned cmd_nargs,
	    const unsigned pipeline_cmd_idx,
	    const unsigned pipeline_ncommands,
	    const int pipe_fds[2],
	    const int prev_read_end)
{
	char *argv[cmd_nargs + 1];
	struct string *s;
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
	i = 0;
	list_for_each_entry(s, cmd_args, list)
		argv[i++] = s->chars;
	argv[i] = NULL;

	/* Set any environmental variables for this command */
	list_for_each_entry(s, var_assignments, list) {
		if (putenv(s->chars)) {
			mysh_error_with_errno("Failed to set environmental "
					      "variable %s", s->chars);
			goto fail;
		}
	}

	/* Execute the new program */
	execvp(argv[0], argv);

	/* Control only reaches here if execvp() failed */
	if (errno == ENOENT)
		mysh_error("%s: command not found", argv[0]);
	else
		mysh_error_with_errno("Failed to execute %s", argv[0]);
fail:
	exit(-1);
}


static int process_var_assignments(const struct list_head *assignments)
{
	struct string *s;
	list_for_each_entry(s, assignments, list)
		make_param_assignment(s->chars);
	return 0;
}

static void free_redir_list(struct list_head *redir_list)
{
	struct redirection *redir, *tmp;
	list_for_each_entry_safe(redir, tmp, redir_list, list) {
		if (redir->is_file)
			free(redir->src_filename);
		free(redir);
	}
}

/* Executes a pipeline.  This includes the trivial pipeline consisting of only 1
 * comment.
 *
 * @command_tokens:  An array that gives the lists of tokens for each command.
 * @ncommands:  Number of commands in the pipeline.
 *
 * Return value is the exit status of the last pipeline component on success, or
 * -1 if there was a problem with the execution of the pipeline itself.
 */
static int execute_pipeline(struct list_head command_tokens[],
			    unsigned ncommands)
{
	unsigned i;
	int ret;

	bool async;
	struct list_head redir_lists[ncommands];
	struct list_head cmd_arg_lists[ncommands];
	struct list_head var_assignment_lists[ncommands];
	unsigned cmd_nargs[ncommands];
	unsigned num_redirs[ncommands];

	unsigned cmd_idx;
	int pipe_fds[2];
	int prev_read_end;
	pid_t child_pids[ncommands];

	mysh_assert(ncommands != 0);
	async = false;
	i = 0;
	do {
		INIT_LIST_HEAD(&cmd_arg_lists[i]);
		INIT_LIST_HEAD(&redir_lists[i]);
		INIT_LIST_HEAD(&var_assignment_lists[i]);
	} while (++i != ncommands);
	i = 0;
	do {
		ret = parse_tok_list(&command_tokens[i],
				     (i == ncommands - 1) ? &async : NULL,
				     &cmd_arg_lists[i],
				     &var_assignment_lists[i],
				     &redir_lists[i],
				     &cmd_nargs[i],
				     &num_redirs[i]);
		if (ret)
			goto out_free_lists;
	} while (++i != ncommands);

	if (mysh_noexecute)
		goto out_free_lists;

	/* If the pipeline only has one command and is not being executed
	 * asynchronously, try interpreting the command as a builtin.  Note:
	 * this means that with the current code, builtins cannot be used as
	 * parts of a multi-component pipeline. */
	if (ncommands == 1 || !async) {
		if (maybe_execute_builtin(&cmd_arg_lists[0], &redir_lists[0],
					  cmd_nargs[0], &ret))
			goto out_free_lists;
		/* not a builtin */

		/* if there are no arguments, just process leading variable
		 * assignments */
		if (cmd_nargs[0] == 0) {
			ret = process_var_assignments(&var_assignment_lists[0]);
			goto out_free_lists;
		}
	}

	i = 0;
	do {
		if (cmd_nargs[i] == 0) {
			mysh_error("Expected command name");
			ret = -1;
			goto out_free_lists;
		}
	} while (++i != ncommands);

	/* Execute the commands */
	prev_read_end = pipe_fds[0] = pipe_fds[1] = -1;
	cmd_idx = 0;
	do {
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
			start_child(&cmd_arg_lists[cmd_idx],
				    &redir_lists[cmd_idx],
				    &var_assignment_lists[cmd_idx],
				    cmd_nargs[cmd_idx], cmd_idx, ncommands,
				    pipe_fds, prev_read_end);
		} else {
			/* Parent: save child pid in an array */
			child_pids[cmd_idx] = ret;
		}
	} while (++cmd_idx != ncommands);
	ret = 0;
out_close_pipes:
	if (pipe_fds[0] >= 0)
		close(pipe_fds[0]);
	if (pipe_fds[1] >= 0)
		close(pipe_fds[1]);
	if (prev_read_end >= 0)
		close(prev_read_end);
	if (ret == 0 && !async) {
		i = 0;
		do {
			int status;
			if (waitpid(child_pids[i], &status, 0) == -1) {
				if (ret == 0)
					ret = -1;
				mysh_error_with_errno("Failed to wait for child with "
						      "pid %d to terminate", child_pids[i]);
			} else if (ret == 0) {
				if (WIFEXITED(status))
					ret = WEXITSTATUS(status);
				else
					ret = -1;
			}
		} while (++i != ncommands);
	}
out_free_lists:
	i = 0;
	do {
		free_string_list(&cmd_arg_lists[i]);
		free_string_list(&var_assignment_lists[i]);
		free_redir_list(&redir_lists[i]);
	} while (++i != ncommands);
	return ret;
}

/* Execute a line of input that has been parsed into tokens.
 * Also is responsible for freeing the tokens. */
static int execute_tok_list(struct list_head *tok_list)
{
	struct token *tok, *tmp;
	unsigned ncommands;
	unsigned i;
	int ret;
	struct list_head *cur_list;

	/* Count the number of commands in the pipeline */
	ncommands = 0;
	list_for_each_entry(tok, tok_list, list)
		if (tok->type & TOK_CLASS_CMD_BOUNDARY)
			ncommands++;

	struct list_head command_tokens[ncommands];

	for (i = 0; i < ncommands; i++)
		INIT_LIST_HEAD(&command_tokens[i]);

	/* Return 0 if the pipeline is empty (e.g. a line of only whitespace, or
	 * only a comment) */
	if (list_is_singular(tok_list)) {
		ret = 0;
		goto out;
	}

	/* Split the tokens into individual lists (commands), around the '|'
	 * signs. */
	cur_list = &command_tokens[0];
	list_for_each_entry_safe(tok, tmp, tok_list, list) {
		if (tok->type & TOK_CLASS_CMD_BOUNDARY) {
			if (list_empty(cur_list)) {
				mysh_error("empty command in pipeline");
				ret = -1;
				goto out;
			}
			cur_list++;
		} else {
			list_move_tail(&tok->list, cur_list);
		}
	}
	/* Execute the pipeline */
	ret = execute_pipeline(command_tokens, ncommands);
out:
	free_tok_list(tok_list);
	for (i = 0; i < ncommands; i++)
		free_tok_list(&command_tokens[i]);
	return ret;
}

static void set_up_signal_handlers()
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	if (sigaction(SIGINT, &act, NULL) != 0)
		mysh_error_with_errno("Failed to set up signal handlers");
}

#define DEFAULT_INPUT_BUFSIZE 4096

/*
 * Execute input to the shell.
 *
 * @cur_tok_list:  A list containing any previously parsed tokens for the
 *		   current shell statement.
 * 
 * @input:         Pointer to the shell input, not necessarily null-terminated.
 *
 * @bytes_remaining_p:
 *                 Number of bytes of input that are remaining.
 *
 * This function returns when any of the following is true:
 *    - There is no input remaining and there are no residual tokens.  In this
 *    case, the return value is the exit status of the last executed shell
 *    statement.
 *    - There is not enough input remaining to lex a full token, and the code is
 *    in the middle of lexing a shell statement.  In this case, the return value
 *    is LEX_NOT_ENOUGH_INPUT, and *bytes_remaining_p is set to the number of
 *    bytes remaining in the input that have not yet been lexed.
 *    - A shell command was executed and it had nonzero exit status, and the
 *    'set -e' option is active.  In this case, the return value is this exit
 *    status.
 *    - There were problems breaking the input into tokens.  In this case, the
 *    return value is LEX_ERROR.
 */
static int execute_shell_input(struct list_head *cur_tok_list,
			       const char *input,
			       size_t *bytes_remaining_p)
{
	int ret = 0;
	size_t bytes_remaining = *bytes_remaining_p;
	while (bytes_remaining) {
		struct token *tok;
		do {
			size_t bytes_lexed;

			ret = lex_next_token(input, bytes_remaining_p, &tok);
			if (ret)
				return ret;
			bytes_lexed = bytes_remaining - *bytes_remaining_p;
			if (mysh_write_input_to_stderr)
				fwrite(input, 1, bytes_lexed, stderr);
			input += bytes_lexed;
			bytes_remaining -= bytes_lexed;
			list_add_tail(&tok->list, cur_tok_list);
		} while (tok->type != TOK_END_OF_SHELL_STATEMENT);
		ret = execute_tok_list(cur_tok_list);
		if (ret && mysh_exit_on_error)
			return ret;
	}
	return ret;
}

/* A wrapper around execute_shell_input() that requires the input to be 0 or
 * more full shell statements. */
int execute_full_shell_input(const char *input, size_t len)
{
	int ret;
	LIST_HEAD(tok_list);

	/* hack: overwrite null terminator with a newline so that the end of
	 * input is seen as the end of a shell statement */
	((char*)input)[len++] = '\n';
	ret = execute_shell_input(&tok_list, input, &len);
	switch (ret) {
	case LEX_ERROR:
		mysh_last_exit_status = -1;
		break;
	case LEX_NOT_ENOUGH_INPUT:
		mysh_error("unexpected end of input");
		mysh_last_exit_status = -1;
		break;
	default:
		mysh_last_exit_status = ret;
		break;
	}
	return mysh_last_exit_status;
}

int main(int argc, char **argv)
{
	int c;
	int in_fd;
	int ret;
	bool from_stdin = false;
	bool interactive = false;
	char *input_buf;
	size_t input_data_begin;
	size_t input_data_end;
	size_t input_buf_len;

	LIST_HEAD(cur_tok_list);

	set_up_signal_handlers();
	init_param_map();

	while ((c = getopt(argc, argv, "c:is")) != -1) {
		switch (c) {
		case 'c':
			/* execute string provided on the command line */
			set_positional_params(argc - optind, argv[optind - 1], &argv[optind]);
			execute_full_shell_input(optarg, strlen(optarg));
			goto out;
		case 's':
			/* read from stdin */
			from_stdin = true;
			break;
		case 'i':
			interactive = true;
			break;
		default:
			mysh_error("invalid option");
			mysh_last_exit_status = 2;
			goto out;
		}
	}
	argc -= optind;
	argv += optind;

	(void)set_pwd();

	if (argc && !from_stdin) {
		in_fd = open(argv[0], O_RDONLY);
		if (in_fd < 0) {
			mysh_error_with_errno("can't open %s", argv[0]);
			mysh_last_exit_status = -1;
			goto out;
		}
		set_positional_params(argc - 1, argv[0], argv + 1);
	} else {
		set_positional_params(argc, argv[-1], argv);
		in_fd = STDIN_FILENO;
	}
	if (isatty(in_fd))
		interactive = true;
	mysh_last_exit_status = 0;
	input_buf_len = DEFAULT_INPUT_BUFSIZE;
	input_buf = xmalloc(input_buf_len);
	input_data_begin = 0;
	input_data_end = 0;
	for (;;) {
		ssize_t bytes_read;
		size_t bytes_remaining;
		size_t bytes_to_read;

		/* Print command prompt */
		if (interactive) {
			printf("%s $ ", lookup_shell_param("PWD"));
			fflush(stdout);
		}

	read_again_check_buffer:
		/* Check whether less than half the distance to the end of the
		 * buffer is remaining */
		if (input_buf_len - input_data_end < input_buf_len / 2) {
			if (input_data_begin > input_buf_len / 10) {
				/* Move data to beginning of buffer to make more
				 * room */
				bytes_remaining = input_data_end - input_data_begin;
				memmove(input_buf, &input_buf[input_data_begin],
					bytes_remaining);
				input_data_begin = 0;
				input_data_end = bytes_remaining;
			} else if (input_data_end == input_buf_len) {
				/* Buffer is full or almost full */
				input_buf_len *= 2;
				input_buf = xrealloc(input_buf, input_buf_len);
			}
		}

	read_again:
		bytes_to_read = input_buf_len - input_data_end;
		/* Read data into the buffer */
		bytes_read = read(in_fd, &input_buf[input_data_end], bytes_to_read);
		if (bytes_read == 0) {
			/* EOF */
			if (input_data_end - input_data_begin != 0) {
				mysh_error("unexpected end of input");
				mysh_last_exit_status = -1;
			}
			goto out_break_read_loop;
		} else if (bytes_read < 0) {
			/* Read error */
			if (errno == EINTR)
				goto read_again;
			mysh_error_with_errno("error reading input");
			mysh_last_exit_status = -1;
			goto out_break_read_loop;
		} else {
			/* Successful read */

			input_data_end += bytes_read;
			bytes_remaining = input_data_end - input_data_begin;

			/* Execute as many commands as possible */
			ret = execute_shell_input(&cur_tok_list,
						  &input_buf[input_data_begin],
						  &bytes_remaining);
			input_data_begin = input_data_end - bytes_remaining;
			switch (ret) {
			case LEX_ERROR:
				mysh_last_exit_status = -1;
				goto out_break_read_loop;
			case LEX_NOT_ENOUGH_INPUT:
				goto read_again_check_buffer;
			default:
				mysh_last_exit_status = ret;
				if (mysh_last_exit_status != 0 && mysh_exit_on_error)
					goto out_break_read_loop;
				break;
			}
		}
	}
out_break_read_loop:
	close(in_fd);
	free(input_buf);
out:
	destroy_positional_params();
	destroy_param_map();
	return mysh_last_exit_status;
}

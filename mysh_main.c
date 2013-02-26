/*
 * mysh_main.c
 *
 * main loop for the shell.
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

#ifdef WITH_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

/* globals */
int mysh_last_exit_status;
int mysh_filename_expansion_disabled;
int mysh_exit_on_error;
int mysh_write_input_to_stderr;
int mysh_noexecute;
int mysh_last_background_pid;

struct background_pipeline {
	struct list_head list;
	unsigned num;
	unsigned npids;
	pid_t last_pid;
	pid_t pids[0];
};

static LIST_HEAD(background_pipelines);

static unsigned get_next_job_number()
{
	unsigned n = 1;
	const struct background_pipeline *p;
	list_for_each_entry(p, &background_pipelines, list)
		if (n <= p->num)
			n = p->num + 1;
	return n;
}

static int add_background_pipeline(const pid_t child_pids[], unsigned npids)
{
	struct background_pipeline *p;

	mysh_assert(npids != 0);
	p = xmalloc(sizeof(*p) + npids * sizeof(pid_t));

	p->num = get_next_job_number();
	p->npids = npids;
	p->last_pid = mysh_last_background_pid = child_pids[npids - 1];
	memcpy(p->pids, child_pids, npids * sizeof(pid_t));
	list_add_tail(&p->list, &background_pipelines);

	printf("[%u] %d\n", p->num, p->last_pid);
	return 0;
}


static bool sigint_occurred;

static void sigint_handler(int sig)
{
	sigint_occurred = true;
#ifdef WITH_READLINE
	/* This is somewhat of a hack to make libreadline discard the current
	 * line of input. */
	rl_end = 0;
#endif
}

static void onetime_sigint_handler(int sig);

static void install_handler(int sig, void (*handler)(int))
{
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = handler;
	sigaddset(&act.sa_mask, sig);
	sigaction(sig, &act, NULL);
}

static void set_up_sigint_handler()
{
	sigint_occurred = false;
	install_handler(SIGINT, sigint_handler);
}

static void set_up_onetime_sigint_handler()
{
	sigint_occurred = false;
	install_handler(SIGINT, onetime_sigint_handler);
}

static void remove_sigint_handler()
{
	install_handler(SIGINT, SIG_IGN);
}

static void onetime_sigint_handler(int sig)
{
	sigint_occurred = true;
	remove_sigint_handler();
}

static void interrupt_children(const pid_t child_pids[], unsigned npids)
{
	unsigned i = 0;
	do {
		if (kill(child_pids[i], SIGINT)) {
			mysh_error_with_errno("failed to interrupt child "
					      "process (pid %d)",
					      child_pids[i]);
		}
	} while (++i != npids);
}

/* Wait for child processes to terminate.  If SIGINT received, pass it onto all
 * remaining children, then continue waiting for them. */
static int wait_for_children(const pid_t child_pids[], unsigned npids)
{
	int ret;
	unsigned i = 0;
	int status;
	set_up_onetime_sigint_handler();
	do {
	again:
		if (waitpid(child_pids[i], &status, 0) == -1) {
			if (errno == EINTR && sigint_occurred) {
				interrupt_children(&child_pids[i], npids - i);
				goto again;
			} else {
				ret = -1;
				mysh_error_with_errno("failed to wait for child "
						      "process (pid %d) to terminate ",
						      child_pids[i]);
			}
		} else {
			if (WIFEXITED(status))
				ret = WEXITSTATUS(status);
			else
				ret = -1;
		}
	} while (++i != npids);
	if (!sigint_occurred)
		remove_sigint_handler();
	return ret;
}

static void check_for_finished_background_pipelines()
{
	struct background_pipeline *p, *tmp;

	list_for_each_entry_safe(p, tmp, &background_pipelines, list) {
		unsigned rem_pids = p->npids;
		unsigned i = 0;
		do {
			if (p->pids[i] < 0) {
				rem_pids--;
			} else {
				int status;
				int ret;
				ret = waitpid(p->pids[i], &status, WNOHANG);
				if (ret == -1) {
					mysh_error_with_errno("wait error");
				} else if (ret != 0) {
					rem_pids--;
					p->pids[i] = -1;
				}
			}
		} while (++i != p->npids);
		if (rem_pids == 0) {
			printf("[%u]+ Done                  %d\n", p->num, p->last_pid);
			list_del(&p->list);
			free(p);
		}
	}
}


/* Executed by the child process after a fork().  The child now must set up
 * redirections (if any) and execute the new program. */
static void __attribute__((noreturn))
start_child(const struct list_head *cmd_args,
	    const struct list_head *redirs,
	    const struct list_head *var_assignments,
	    unsigned cmd_nargs,
	    unsigned pipeline_cmd_idx,
	    unsigned pipeline_ncommands,
	    const int pipe_fds[2],
	    int prev_read_end)
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
	mysh_assert(i == cmd_nargs);

	/* Set any environmental variables for this command */
	list_for_each_entry(s, var_assignments, list) {
		if (putenv(s->chars)) {
			mysh_error_with_errno("Failed to set environmental "
					      "variable %s", s->chars);
			goto fail;
		}
	}

	/* Use the default SIGINT handler (the shell may be using a different
	 * one) */
	install_handler(SIGINT, SIG_DFL);

	/* Execute the new program.  execvp() automatically searches $PATH.
	 * Note: this shell does not attempt to save time by remembering the
	 * locations of executable programs on the $PATH. */
	execvp(argv[0], argv);

	/* Only reached if execvp() failed */
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
		list_del(&redir->list);
		if (redir->is_file)
			free(redir->src_filename);
		free(redir);
	}
}

/* Executes a pipeline.  This includes a trivial pipeline consisting of only 1
 * comment.
 *
 * @command_tokens:  An array that gives the lists of tokens for each command in
 *                   the pipeline.
 * @ncommands:  Number of commands in the pipeline.
 *
 * The return value is the exit status of the last pipeline component on
 * success, or -1 if there was a problem with the execution of the pipeline
 * itself.
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

	int pipe_fds[2];
	int prev_read_end;
	pid_t child_pids[ncommands];

	mysh_assert(ncommands > 0);
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
	 * asynchronously, try interpreting the command as a sequence of
	 * variable assignments or as a shell builtin.  Note: this means that
	 * with the current code, builtins cannot be used as parts of a
	 * multi-component pipeline. */
	if (ncommands == 1 && !async) {
		if (cmd_nargs[0] == 0) {
			/* No arguments: just process leading variable
			 * assignments. */
			ret = process_var_assignments(&var_assignment_lists[0]);
			goto out_free_lists;
		} else if (maybe_execute_builtin(&cmd_arg_lists[0],
						 &redir_lists[0],
						 cmd_nargs[0], &ret))
			goto out_free_lists;
		/* Not a builtin */
	}

	/* Verify that there is a command to execute for each component of the
	 * pipeline (e.g. there isn't a component that is only redirections) */
	i = 0;
	do {
		if (cmd_nargs[i] == 0) {
			mysh_error("Expected command name");
			ret = -1;
			goto out_free_lists;
		}
	} while (++i != ncommands);

	/* Execute the commands in the pipeline.  This essentially is done by
	 * fork() followed by execvp() for each command.  Redirections are
	 * handled by the forked child processes before calling execvp().  Pipes
	 * are created with pipe() before the fork.  Note that each component of
	 * the pipeline other than the first and last is involved with two
	 * different pipes: one to read from, and one to write to.  The
	 * @prev_read_end variable is used to save the read end of a pipe for
	 * the next pipeline component. */
	prev_read_end = pipe_fds[0] = pipe_fds[1] = -1;
	i = 0;
	do {
		/* Unless this is the last command, create a new pair of pipes */
		if (i != ncommands - 1) {
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
			if (async) {
				errno = 0;
				setsid();
				dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);
				if (errno) {
					mysh_error_with_errno("problem daemonizing "
							      "background process");
				}
			}
			/* Child: set up redirections and execute new process */
			start_child(&cmd_arg_lists[i],
				    &redir_lists[i],
				    &var_assignment_lists[i],
				    cmd_nargs[i], i, ncommands,
				    pipe_fds, prev_read_end);
			/* Not reached */
			mysh_assert(0);
		}

		/* Parent: save child pid in an array */
		child_pids[i] = ret;

		/* Close any pipes we created that are no longer needed; also
		 * save the read end of the pipe (if any) in the prev_read_end
		 * variable.  */
		if (prev_read_end >= 0)
			close(prev_read_end);
		prev_read_end = pipe_fds[0];
		pipe_fds[0] = -1;
		if (pipe_fds[1] >= 0) {
			close(pipe_fds[1]);
			pipe_fds[1] = -1;
		}
	} while (++i != ncommands);
	ret = 0;
out_close_pipes:
	if (pipe_fds[0] >= 0)
		close(pipe_fds[0]);
	if (pipe_fds[1] >= 0)
		close(pipe_fds[1]);
	if (prev_read_end >= 0)
		close(prev_read_end);
	/* If no error has occurred and the pipeline is not being executed
	 * asynchronously, wait for the commands to terminate.  'ret' is set to
	 * the exit status of the last command in the pipeline.
	 *
	 * If the pipeline is to be asynchronous, don't wait for any children;
	 * just add an entry to the list of background pipelines. */
	if (ret == 0) {
		if (async)
			ret = add_background_pipeline(child_pids, ncommands);
		else
			ret = wait_for_children(child_pids, ncommands);
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

	mysh_assert(!list_empty(tok_list) &&
		    (list_entry(tok_list->prev, struct token, list)->type ==
		    TOK_END_OF_SHELL_STATEMENT));
	BUILD_BUG_ON((TOK_CLASS_CMD_BOUNDARY & TOK_END_OF_SHELL_STATEMENT) == 0);

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

	/* Split the tokens into individual lists (pipeline components), around
	 * the '|' signs. */
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

/*
 * Execute input to the shell.
 *
 * @cur_tok_list:  A list containing any previously parsed tokens for the
 *		   current shell statement.
 *
 * @input:         Pointer to the shell input, not necessarily null-terminated.
 *
 * @bytes_remaining_p:
 *                 Pointer to number of bytes of input that are remaining.
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

#define DEFAULT_INPUT_BUFSIZE 4096

/* Execute shell input from the file descriptor @in_fd until end-of-file.
 * Closes the file descriptor when done.
 *
 * @interactive specifies whether the shell prompt should be written after each
 * line or not.
 *
 * Return value is exit status of last shell statement executed, or -1 on error
 * (including read errors and parse errors).  This is the same as
 * mysh_last_exit_status.
 *
 * The loop in this function is complicated and probably should be refactored;
 * however the code is written to handle multiple similar but not identical
 * cases:
 *   - non-interactive shells
 *   - interactive shells without readline support
 *   - interactive shells with readline support
 *
 * The code also is careful not to place any arbitrary limits on the length of
 * the input and to allow a shell statement to span multiple lines in the
 * interactive and interactive modes.
 */
int read_loop(int in_fd, bool interactive)
{
	char *input_buf;
	size_t input_data_begin;
	size_t input_data_end;
	size_t input_buf_len;
	int ret;
	struct list_head cur_tok_list;

	input_buf_len = DEFAULT_INPUT_BUFSIZE;
	input_buf = xmalloc(input_buf_len);
	input_data_begin = 0;
	input_data_end = 0;
	INIT_LIST_HEAD(&cur_tok_list);
	for (;;) {
		ssize_t bytes_read;
		size_t bytes_remaining;
		size_t bytes_to_read;

		/* Check for background pipelines that have terminated */
		check_for_finished_background_pipelines();

		if (interactive) {
		#ifdef WITH_READLINE
			/* Interactive shell, linked with libreadline */
			const char *prompt;
			char *p;

			/* Call readline() to get the next line of input,
			 * allowing it to be interrupted. */
			if (list_empty(&cur_tok_list))
				prompt = "$ "; /* Beginning of shell statement */
			else
				prompt = "> "; /* Continue a shell statement */
			set_up_sigint_handler();
			p = readline(prompt);
			remove_sigint_handler();

			if (sigint_occurred) {
				/* SIGINT received; discard the line of input
				 * along with all previous lines that are part
				 * of the same shell statement. */
				sigint_occurred = false;
				input_data_begin = 0;
				input_data_end = 0;
				free_tok_list(&cur_tok_list);
				puts("^C");
				free(p);
				continue;
			} else {
				/* No SIGINT received.  Add the line to the
				 * readline history if it's non-empty; then
				 * transfer it to the input buffer for parsing.
				 * */
				if (!p)
					goto out_break_read_loop;
				if (*p)
					add_history(p);
				bytes_read = strlen(p) + 1;
				if (bytes_read > input_buf_len - input_data_end) {
					/* Out of space; resize the buffer */
					input_buf_len *= 2;
					if (bytes_read > input_buf_len - input_data_end)
						input_buf_len += bytes_read -
							(input_buf_len - input_data_end);
					input_buf = xrealloc(input_buf, input_buf_len);
				}
				memcpy(&input_buf[input_data_end], p, bytes_read);
				input_buf[input_data_end + bytes_read - 1] = '\n';
				free(p);
				goto skip_raw_read;
			}
		#else
			/* Interactive shell, not linked with libreadline */

			/* Print the prompt ourselves when not relying on
			 * readline, then fall through to the code below that
			 * checks the buffer size, then does a raw read(). */
			putc('$', stdout);
			putc(' ', stdout);
			fflush(stdout);
		#endif
		}

	read_again_check_buffer:
		/* Check whether less than half the distance to the end of the
		 * buffer is remaining.  This part is executed in noninteractive
		 * shells as well as interactive shells without readline
		 * support. */
		if (input_buf_len - input_data_end < input_buf_len / 2) {
			if (input_data_begin > input_buf_len / 10) {
				/* Move data to beginning of buffer to make more
				 * room */
				bytes_remaining = input_data_end - input_data_begin;
				memmove(input_buf, &input_buf[input_data_begin],
					bytes_remaining);
				input_data_begin = 0;
				input_data_end = bytes_remaining;
			} else if (input_data_end == input_buf_len
			#ifdef WITH_READLINE
				   && !interactive
			#endif
				   )
			{
				/* Buffer is full or almost full */
				input_buf_len *= 2;
				input_buf = xrealloc(input_buf, input_buf_len);
			}
		}

	read_again:
		/* Read data into the buffer with read(), allowing the read() to
		 * be interrupted.  This part is executed in noninteractive
		 * shells as well as interactive shells without readline
		 * support. */
	#ifndef WITH_READLINE
		if (interactive)
			set_up_sigint_handler();
	#endif
		bytes_to_read = input_buf_len - input_data_end;
		bytes_read = read(in_fd, &input_buf[input_data_end], bytes_to_read);
	#ifndef WITH_READLINE
		if (interactive)
			remove_sigint_handler();
	#endif
#ifdef WITH_READLINE
	skip_raw_read:
#endif
		if (bytes_read == 0) {
			/* EOF */
			if (input_data_end - input_data_begin != 0) {
				mysh_error("unexpected end of input");
				mysh_last_exit_status = -1;
			}
			goto out_break_read_loop;
		} else if (bytes_read < 0) {
			/* Read error */
			if (errno == EINTR) {
			#ifndef WITH_READLINE
				if (interactive) {
					/* SIGINT received; discard the line of
					 * input along with all previous lines
					 * that are part of the same shell
					 * statement. */
					input_data_begin = 0;
					input_data_end = 0;
					free_tok_list(&cur_tok_list);
					putchar('\n');
					fflush(stdout);
					continue;
				}
			#endif
				goto read_again;
			}
			mysh_error_with_errno("error reading input");
			mysh_last_exit_status = -1;
			goto out_break_read_loop;
		} else {
			/* Successful read */

			input_data_end += bytes_read;
			bytes_remaining = input_data_end - input_data_begin;

			/* Execute as many shell statements as possible */
			ret = execute_shell_input(&cur_tok_list,
						  &input_buf[input_data_begin],
						  &bytes_remaining);
			input_data_begin = input_data_end - bytes_remaining;
			switch (ret) {
			case LEX_ERROR:
				/* The input was invalid.  Break the loop. */
				mysh_last_exit_status = -1;
				goto out_break_read_loop;
			case LEX_NOT_ENOUGH_INPUT:
				/* The current input ends in the middle of a
				 * shell statement.  Jump back to the
				 * appropriate place to handle more input. */
			#ifdef WITH_READLINE
				if (interactive)
					continue;
			#endif
				goto read_again_check_buffer;
			default:
				/* The input ended on a shell statement boundary
				 * and was executed, but the exit status was not
				 * necessarily 0, and there may have been other
				 * errors.  mysh_exit_on_error indicates whether
				 * the 'set -e' shell option is set, and it
				 * requires exiting the shell early when a
				 * command is unsuccessful. */
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
	return mysh_last_exit_status;
}

/* Source a shell script. */
int do_source(const char *filename, unsigned nargs, const char * const *args)
{
	int in_fd;
	char **pos_params_save;
	unsigned num_pos_params_save;
	int ret;

	in_fd = open(filename, O_RDONLY);
	if (in_fd < 0) {
		mysh_error_with_errno("can't open %s", filename);
		return 1;
	}

	pos_params_save = positional_parameters;
	num_pos_params_save = num_positional_parameters;
	positional_parameters = NULL;
	set_positional_params(nargs, filename, (const char **)args);
	ret = read_loop(in_fd, false);
	destroy_positional_params();
	positional_parameters = pos_params_save;
	num_positional_parameters = num_pos_params_save;
	return ret;
}

static void source_myshrc()
{
	/* source $HOME/.myshrc */
	char *home = getenv("HOME");
	if (home) {
		size_t len = strlen(home);
		char filename[len + sizeof("/.myshrc")];
		stpcpy(filename, home);
		strcat(filename, "/.myshrc");
		do_source(filename, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	int c;
	int in_fd;
	bool from_stdin = false;
	bool interactive = false;

	remove_sigint_handler();
	init_param_map();

#ifdef WITH_READLINE
	/* getc() will return EOF on interrupt, instead of retrying like the
	 * default rl_getc().  This makes readline() return when an interrupt
	 * occurs, which allows the shell to handle SIGINT better.  Similarly,
	 * rl_catch_signals is set to 0 to prevent readline from catching the
	 * SIGINT signal before the shell does.  This is not the only solution:
	 * another would be to have readline handle SIGINT, then pass it onto
	 * the shell, which then does a longjmp() back to the main loop.  I
	 * didn't do it this way because using longjmp() correctly is very
	 * tricky. */
	rl_getc_function = getc;
	rl_catch_signals = 0;
#endif

	while ((c = getopt(argc, argv, "c:is")) != -1) {
		switch (c) {
		case 'c':
			/* execute string provided on the command line */
			set_positional_params(argc - optind, argv[optind - 1],
					      (const char **)&argv[optind]);
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

	source_myshrc();
	(void)set_pwd();

	if (argc && !from_stdin) {
		in_fd = open(argv[0], O_RDONLY);
		if (in_fd < 0) {
			mysh_error_with_errno("can't open %s", argv[0]);
			mysh_last_exit_status = -1;
			goto out;
		}
		set_positional_params(argc - 1, argv[0], (const char **)(argv + 1));
	} else {
		set_positional_params(argc, argv[-1], (const char **)argv);
		in_fd = STDIN_FILENO;
	}
	if (isatty(in_fd))
		interactive = true;

	read_loop(in_fd, interactive);
out:
	destroy_positional_params();
	destroy_param_map();
	return mysh_last_exit_status;
}

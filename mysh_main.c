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
#include "list.h"
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <ctype.h>
#include <glob.h>
#include <unistd.h>


/* globals */
int last_exit_status;


/* Executed by the child process after a fork().  The child now must set up
 * redirections of stdin and stdout (if any) and execute the new program. */
static void
start_child(const struct list_head * const cmd_args,
	    const struct list_head * const redirs,
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

	/* Execute the new program */
	execvp(argv[0], argv);

	/* Control only reaches here if execvp() failed */
	mysh_error_with_errno("Failed to execute %s", argv[0]);
fail:
	exit(-1);
}



static void
split_string_around_whitespace(struct string *s, struct list_head *out_list)
{
	const char *whitespace_chars = " \r\t\n";
	const char *strstart;
	const char *strend;

	if (!strpbrk(s->chars, whitespace_chars)) {
		/* No whitespace in string. */
		if (s->len != 0)
			list_add_tail(&s->list, out_list);
		return;
	}

	strstart = s->chars;
	while (1) {
		while (isspace(*strstart))
			strstart++;

		if (*strstart == '\0')
			return;

		strend = strpbrk(strstart, whitespace_chars);
		append_string(strstart, strend - strstart, out_list);
		strstart = strend + 1;
	}
}

static void
string_do_filename_expansion(struct string *s, struct list_head *out_list)
{
	int ret;
	glob_t glob_buf;

	ret = glob(s->chars,
		   GLOB_NOESCAPE | GLOB_TILDE | GLOB_NOCHECK | GLOB_BRACE,
		   NULL, &glob_buf);
	if (ret) {
		mysh_error_with_errno("glob()");
		list_add_tail(&s->list, out_list);
	} else {
		size_t i;

		free_string(s);
		for (i = 0; i < glob_buf.gl_pathc; i++) {
			append_string(glob_buf.gl_pathv[i], 
				      strlen(glob_buf.gl_pathv[i]),
				      out_list);
		}
		globfree(&glob_buf);
	}
}

static void
do_filename_expansion(struct list_head *string_list)
{
	struct string *s, *tmp;
	LIST_HEAD(new_list);
	list_for_each_entry_safe(s, tmp, string_list, list)
		string_do_filename_expansion(s, &new_list);
	INIT_LIST_HEAD(string_list);
	list_splice_tail(&new_list, string_list);
}

static void
expand_string(struct token *tok, struct list_head *out_list)
{
	struct string *s = xmalloc(sizeof(struct string));
	s->chars = tok->tok_data;
	s->len = strlen(tok->tok_data);
	tok->tok_data = NULL;
	if (tok->type & (TOK_UNQUOTED_STRING | TOK_DOUBLE_QUOTED_STRING))
		s = do_param_expansion(s);

	INIT_LIST_HEAD(out_list);
	if (tok->type & TOK_UNQUOTED_STRING)
		split_string_around_whitespace(s, out_list);
	else
		list_add_tail(&s->list, out_list);

	if (tok->type & TOK_UNQUOTED_STRING)
		do_filename_expansion(out_list);
}

static int
parse_tok_list(struct token *tok,
	       const bool is_last,
	       bool *async_ret,
	       struct list_head *cmd_args,
	       unsigned *cmd_nargs_ret,
	       unsigned *nleading_var_assignments_ret,
	       struct list_head *redirs)
{

	int ret;
	LIST_HEAD(string_list);
	LIST_HEAD(redir_string_list);
	unsigned nleading_var_assignments = 0;
	bool leading = true;
	while (tok->type & TOK_CLASS_STRING) {
		if (leading
		    && (tok->type & TOK_UNQUOTED_STRING)
		    && strchr(tok->tok_data, '='))
		{
			++nleading_var_assignments;
		} else {
			leading = false;
			LIST_HEAD(tmp_list);
			expand_string(tok, &tmp_list);
			list_splice_tail(&tmp_list, &string_list);
		}
		tok = tok->next;
		if (!tok) {
			ret = 0;
			break;
		}
	}
	ret = 0;
	INIT_LIST_HEAD(cmd_args);
	INIT_LIST_HEAD(redirs);
	list_splice_tail(&string_list, cmd_args);
	*cmd_nargs_ret = list_size(cmd_args);
	*nleading_var_assignments_ret = nleading_var_assignments;
	goto out;
#if 0
	bool is_first_redirection = true;
	while (1) {
		struct token *next = tok->next;
		const char *redir_source;
		const char *redir_dest;

		int ntokens_consumed;
		int redir_type;

		switch (tok->type) {
#if 0
		case TOK_GREATER_THAN:
			if (!next) {
				mysh_error("Unexpected end of statement after '>'");
				ret = -1;
				goto out_free_string_list;
			}
			switch (next->type) {
			case TOK_AMPERSAND:
				/* >& */
				if (tok->preceded_by_whitespace) {
				} else {
					redir_source = NULL;
				}
				break;
			case TOK_GREATER_THAN:
				/* >> */
				break;
			}
			break;
#endif
		case TOK_LESS_THAN:
			/* redirecting input */
			break;
		case TOK_UNQUOTED_STRING:
		case TOK_DOUBLE_QUOTED_STRING:
		case TOK_SINGLE_QUOTED_STRING:
			if (!list_empty(&redir_string_list))
				expand_string(tok, &redir_string_list);
			break;
		default:
			mysh_error(
			goto out_free_string_list;
		}
		is_first_redirection = false;

	}
#endif
out_free_string_lists:
	free_string_list(&redir_string_list);
	free_string_list(&string_list);
out:
	return ret;

#if 0
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
#endif
}

static int process_var_assignments(const struct token *assignments,
				   unsigned num_assignments)
{
	const struct token *tok = assignments;
	while (num_assignments--) {
		make_param_assignment(tok->tok_data);
		tok = tok->next;
	}
	return 0;
}

static int execute_pipeline(struct token **pipe_commands,
			    unsigned ncommands)
{
	unsigned i;
	int ret;

	bool async;
	struct list_head redir_lists[ncommands];
	struct list_head cmd_arg_lists[ncommands];
	unsigned cmd_nargs[ncommands];
	unsigned nleading_var_assignments[ncommands];

	unsigned cmd_idx;
	int pipe_fds[2];
	int prev_read_end;
	pid_t child_pids[ncommands];

	async = false;
	for (i = 0; i < ncommands; i++) {
		INIT_LIST_HEAD(&cmd_arg_lists[i]);
		INIT_LIST_HEAD(&redir_lists[i]);
	}
	for (i = 0; i < ncommands; i++) {
		ret = parse_tok_list(pipe_commands[i],
				     (i == ncommands - 1),
				     &async, 
				     &cmd_arg_lists[i],
				     &cmd_nargs[i],
				     &nleading_var_assignments[i],
				     &redir_lists[i]);
		if (ret)
			goto out_free_lists;
	}

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
			ret = process_var_assignments(pipe_commands[0],
						      nleading_var_assignments[0]);
			goto out_free_lists;
		}
	}

	for (cmd_idx = 0; cmd_idx < ncommands; cmd_idx++) {
		if (cmd_nargs[cmd_idx] == 0) {
			mysh_error("Expected command name");
			ret = -1;
			goto out_free_lists;
		}
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
			start_child(&cmd_arg_lists[cmd_idx], &redir_lists[cmd_idx],
				    cmd_nargs[cmd_idx], cmd_idx, ncommands,
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
out_free_lists:
	for (i = 0; i < ncommands; i++)
		free_string_list(&cmd_arg_lists[i]);
	/* XXX redirs */
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
	ret = execute_pipeline(commands, cmd_idx);
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
		tok = lex_next_token(&line);
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
	bool from_stdin = false;

	set_up_signal_handlers();
	init_param_map();

	while ((c = getopt(argc, argv, "c:s")) != -1) {
		switch (c) {
		case 'c':
			/* execute string provided on the command line */
			init_positional_params(argc - optind, argv[0], &argv[optind]);
			last_exit_status = execute_line(optarg);
			goto out;
		case 's':
			/* read from stdin */
			from_stdin = true;
			break;
		default:
			mysh_error("invalid option");
			last_exit_status = 2;
			goto out;
		}
	}
	argc -= optind;
	argv += optind;

	(void)set_pwd();

	if (argc && !from_stdin) {
		in = fopen(argv[0], "rb");
		if (!in) {
			mysh_error_with_errno("can't open %s", argv[0]);
			last_exit_status = -1;
			goto out;
		}
		init_positional_params(argc - 1, argv[-1], argv + 1);
	} else {
		init_positional_params(argc, argv[-1], argv);
		in = stdin;
	}

	last_exit_status = 0;
	line = NULL;
	while (1) {
		if (in == stdin)
			fprintf(stdout, "%s $ ", lookup_shell_param("PWD"));
		if (getline(&line, &n, in) == -1)
			break;
		last_exit_status = execute_line(line);
	}

	if (ferror(in)) {
		mysh_error_with_errno("error reading input");
		last_exit_status = -1;
	}
	fclose(in);
	free(line);
out:
	destroy_positional_params();
	destroy_param_map();
	return last_exit_status;
}

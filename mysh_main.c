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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <glob.h>
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
	mysh_error_with_errno("Failed to execute %s", argv[0]);
fail:
	exit(-1);
}



/*
 * Split a unquoted string around whitespace produced by parameter
 * expansion.
 *
 * @s:               The string to split. It will be freed or transferred
 *                   to @out_list.
 *
 * @out_list:        An empty list into which the split strings will be written.
 *                   If the string is empty or is entirely whitespace produced
 *                   by parameter expansion, then the resulting list will remain
 *                   empty.  Otherwise, the string will have one or more strings
 *                   written to it, and they will have the same flags as the
 *                   original string except for the following two exceptions:
 *                     (1) The strings will have STRING_FLAG_WORD_SPLIT set,
 *                         unless the list contains only the original string @s
 *                         (i.e. if word splitting was a no-op).
 *                     (2) All strings except the first will have
 *                         STRING_FLAG_PRECEDING_WHITESPACE set.  The first will
 *                         have STRING_FLAG_PRECEDING_WHITESPACE set if and only
 *                         if @leading_whitespace is set to %true.
 *
 * @param_char_map:  A map from character position to booleans
 *                   that indicate whether the character was produced by
 *                   parameter expansion (1) or not (0).
 *
 * @leading_whitespace:
 *                   Set to %true if the string has leading whitespace that was
 *                   produced by parameter expansion; set to %false otherwise.
 *
 * @trailing_whitespace:
 *                   Set to %true if the string has trailing whitespace that was
 *                   produced by parameter expansion; set to %false otherwise.
 */
static void
split_string_around_whitespace(struct string *s, struct list_head *out_list,
			       const unsigned char *param_char_map,
			       bool *leading_whitespace, bool *trailing_whitespace)
{
	const char *chars;
	struct string *s2;
	size_t i;

	chars = s->chars;
	i = 0;
	*leading_whitespace = false;
	for (;;) {
		/* skip leading whitespace produced by parameter expansion  */
		size_t j = i;
		while (isspace(chars[i]) && param_char_map[i] != 0) {
			if (i == 0)
				*leading_whitespace = true;
			i++;
		}

		if (chars[i] == '\0') {
			/* end of string: set trailing_whitespace if there was
			 * at least 1 parameter-expanded whitespace character at
			 * the end of the string.  Also, free @s before
			 * returning, since it's no longer needed. */
			*trailing_whitespace = (i != j);
			free_string(s);
			return;
		}
		/* j is set the index of the next character that is not a
		 * parameter-expanded whitespace character */
		j = i;

		/* skip non-whitespace and whitespace not produced by parameter
		 * expansion */
		while (chars[i] != '\0' && (!isspace(chars[i]) || !param_char_map[i]))
			i++;

		if (j == 0 && i == s->len) {
			/* Add entire string and return. */
			*trailing_whitespace = false;
			list_add_tail(&s->list, out_list);
			return;
		} else {
			/* Create a new substring and append it to the list of
			 * split strings.
			 *
			 * STRING_FLAG_WORD_SPLIT is set on every new substring.
			 * STRING_FLAG_PRECEDING_WHITESPACE is set on all
			 * substrings except the first if it occurs at the very
			 * beginning of the original string. */

			s2 = new_string_with_data(&chars[j], i - j);
			s2->flags = s->flags | STRING_FLAG_WORD_SPLIT;
			if (i != 0)
				s2->flags |= STRING_FLAG_PRECEDING_WHITESPACE;
			list_add_tail(&s2->list, out_list);
		}
	}
}

/* Performs filename expansion on a string using the glob() function.  For
 * example, mysh_*.c could return [mysh_main.c, mysh_parm.c, ... etc.].  The ?
 * character to indicate any character and bracketed character ranges are also
 * allowed.
 *
 * If the string does not match any files as a glob, it is returned literally.
 *
 * @s:        The string to expand.  It will either be freed or transferred to
 *            @out_list.
 *
 * @out_list: A list to which the resulting strings will be appended.  It will
 *            not necessarily be empty.
 *
 * Returns 0 on success, or -1 on a read error in glob().
 */
static int
string_do_filename_expansion(struct string *s, struct list_head *out_list)
{
	int ret;
	glob_t glob_buf;

	ret = glob(s->chars,
		   GLOB_NOESCAPE | GLOB_TILDE | GLOB_BRACE,
		   NULL, &glob_buf);
	if (ret) {
		switch (ret) {
		case GLOB_NOMATCH:
			/* If the glob does not match, use the literal string. */
			list_add_tail(&s->list, out_list);
			break;
		case GLOB_NOSPACE:
			/* Be consistent with xmalloc() and just abort the shell
			 * if memory has been exhausted */
			mysh_error_with_errno("out of memory");
			exit(1);
		default:
			/* Other error, such as a read error. */
			mysh_error_with_errno("glob()");
			return -1;
		}
	} else {
		size_t i;
		int flags;
		struct string *s2;

		/* glob completed successfully and produced one or more strings.
		 * Free the original string, and add the new strings to
		 * @out_list. */
 		flags = s->flags;
		free_string(s);
		for (i = 0; i < glob_buf.gl_pathc; i++) {
			s2 = new_string_with_data(glob_buf.gl_pathv[i],
						  strlen(glob_buf.gl_pathv[i]));
			s2->flags = flags | STRING_FLAG_FILENAME_EXPANDED;
			list_add_tail(&s2->list, out_list);
		}
		globfree(&glob_buf);
	}
	return 0;
}

/* Performs filename expansion on a list of strings.  The list of strings is
 * replaced with the list of expanded strings.  0 is returned on success; -1 is
 * returned on read error in glob(). */
static int
do_filename_expansion(struct list_head *string_list)
{
	struct string *s, *tmp;
	int ret = 0;

	LIST_HEAD(new_list);
	list_for_each_entry_safe(s, tmp, string_list, list)
		ret |= string_do_filename_expansion(s, &new_list);
	INIT_LIST_HEAD(string_list);
	if (ret)
		free_string_list(&new_list);
	else
		list_splice_tail(&new_list, string_list);
	return ret;
}

/* Do parameter expansion and word splitting */
static int
expand_params_and_word_split(struct token *tok,
			     bool have_next_token,
			     struct list_head *out_list)
{
	struct string *s;
	bool leading_whitespace;
	unsigned char *param_char_map;

	mysh_assert(tok->type & TOK_CLASS_STRING);
	mysh_assert(list_empty(out_list));

 	s = xmalloc(sizeof(struct string));
	s->chars = tok->tok_data;
	s->len = strlen(tok->tok_data);
	s->flags = 0;
	switch (tok->type) {
	case TOK_UNQUOTED_STRING:
		s->flags |= STRING_FLAG_UNQUOTED;
		break;
	case TOK_DOUBLE_QUOTED_STRING:
		s->flags |= STRING_FLAG_DOUBLE_QUOTED;
		break;
	case TOK_SINGLE_QUOTED_STRING:
		s->flags |= STRING_FLAG_SINGLE_QUOTED;
		break;
	default:
		break;
	}
	tok->tok_data = NULL;

	/* Do parameter expansion on unquoted strings and on double-quoted
	 * strings */
	if (tok->type & (TOK_UNQUOTED_STRING | TOK_DOUBLE_QUOTED_STRING))
		s = do_param_expansion(s, &param_char_map);

	/* Do word splitting on unquoted strings that had parameter expansion
	 * performed */
	if ((tok->type & TOK_UNQUOTED_STRING) && (s->flags & STRING_FLAG_PARAM_EXPANDED)) {
		bool trailing_whitespace;
		split_string_around_whitespace(s, out_list, param_char_map,
					       &leading_whitespace,
					       &trailing_whitespace);
		/* If there was trailing whitespace as a result of word
		 * splitting, force @preceded_by_whitespace to true on the next
		 * token (if there is one) */
		if (have_next_token && trailing_whitespace)
			list_entry(tok->list.next, struct token, list)->preceded_by_whitespace = true;
	} else {
		list_add_tail(&s->list, out_list);
		leading_whitespace = false;
	}

	/* If at least one string was produced as a result of word splitting and
	 * either the original token was preceded by whitespace or there was
	 * additional preceding whitespace produced by parameter expansion, set
	 * STRING_FLAG_PRECEDING_WHITESPACE on the first string. */
	if ((tok->preceded_by_whitespace || leading_whitespace) &&
	    !list_empty(out_list))
	{
		list_entry(out_list->next, struct string, list)->flags |=
			STRING_FLAG_PRECEDING_WHITESPACE;
	}
	return 0;
}

/* This function performs what I'm calling the "gluing" together of strings.
 * For example, if you type
 *
 *   $ echo "a"'b'
 *
 * at the shell, the double-quoted string "a" will be glued together with the
 * single-quoted string 'b' because they are not separated by any whitespace.
 *
 * This transformation occurs after parameter expansion and word splitting, but
 * before filename expansion.  So, for example, "a"'b'* would be equivalent to
 * ab*, and ${a}b would be equivalent to "a" "cb" if the shell variable $a is
 * set to "a c".
 *
 * The input is a list @string_list that gives a list of strings passed to the
 * shell.  Each string is glued to any adjacent, succeeding strings that have
 * the flag STRING_FLAG_PRECEDING_WHITESPACE set, which indicates that they
 * should be glued to the preceding string.  The resulting list of "glued"
 * strings replaces the input list.
 *
 * This function also has a special responsibility where it looks for "glued"
 * strings that are constructed from an unquoted string that did not have any
 * parameter expansions that matches the regular expression
 * [A-Za-z_][A-Za-z_0-9]*=.*, followed by zero or more unquoted or quoted
 * strings.  So, for example, 
 *   $ a="b"
 *   $ a=b
 *   $ a="b"'c'
 *   $ a=           # this is legal; it unsets the variable a
 * The glued strings of this form are interpreted as variable assignments, so
 * the STRING_FLAG_VAR_ASSIGNMENT flag is set on these glued strings.
 * */
static int
glue_strings(struct list_head *string_list)
{
	struct string *s, *tmp;
	LIST_HEAD(new_list);
	while (!list_empty(string_list)) {
		struct list_head *first = string_list->next;
		int flags;
		/* Glue one string */
		LIST_HEAD(glue_list);
		list_move_tail(first, &glue_list);
		list_for_each_entry_safe(s, tmp, string_list, list) {
			if (s->flags & STRING_FLAG_PRECEDING_WHITESPACE)
				break;
			else
				list_move_tail(&s->list, &glue_list);
		}
		s = list_entry(first, struct string, list);
		if ((s->flags & STRING_FLAG_UNQUOTED) &&
		    !(s->flags & STRING_FLAG_PARAM_EXPANDED) &&
		    string_matches_param_assignment(s))
		{
			flags = STRING_FLAG_VAR_ASSIGNMENT;
		} else
			flags = 0;
		s = join_strings(&glue_list);
		s->flags = flags;
		list_add_tail(&s->list, &new_list);
	}
	/* Replace @string_list with the list of glued strings */
	list_splice_tail(&new_list, string_list);
	return 0;
}

static void transfer_var_assignments(struct list_head *string_list,
				     struct list_head *var_assignments)
{
	struct string *s, *tmp;
	list_for_each_entry_safe(s, tmp, string_list, list) {
		if (s->flags & STRING_FLAG_VAR_ASSIGNMENT)
			list_move_tail(&s->list, var_assignments);
		else
			break;
	}
}

static int
parse_tok_list(struct list_head *toks,
	       const bool is_last,
	       bool *async_ret,
	       struct list_head *cmd_args,
	       struct list_head *var_assignments,
	       struct list_head *redirs,
	       unsigned *cmd_nargs_ret,
	       unsigned *num_redirs_ret)
{
	struct token *tok;
	int ret;

	mysh_assert(list_empty(var_assignments));
	mysh_assert(list_empty(cmd_args));
	mysh_assert(list_empty(redirs));
	LIST_HEAD(string_list);
	LIST_HEAD(redir_string_list);
	list_for_each_entry(tok, toks, list) {
		if (!(tok->type & TOK_CLASS_STRING))
			break;
		LIST_HEAD(tmp_list);
		ret = expand_params_and_word_split(tok, (tok->list.next != toks), &tmp_list);
		if (ret)
			goto out_free_string_lists;
		list_splice_tail(&tmp_list, &string_list);
	}

	ret = glue_strings(&string_list);
	if (ret)
		goto out_free_string_lists;
	if (!mysh_filename_expansion_disabled) {
		ret = do_filename_expansion(&string_list);
		if (ret)
			goto out_free_string_lists;
	}
	transfer_var_assignments(&string_list, var_assignments);
	list_splice_tail(&string_list, cmd_args);
	*cmd_nargs_ret = list_size(cmd_args);
	*num_redirs_ret = 0;
	ret = 0;
	goto out;
#if 0
	bool is_first_redirection = true;
	for (;;) {
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

static int process_var_assignments(const struct list_head *assignments)
{
	struct string *s;
	list_for_each_entry(s, assignments, list)
		make_param_assignment(s->chars);
	return 0;
}

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
				     (i == ncommands - 1),
				     &async,
				     &cmd_arg_lists[i],
				     &var_assignment_lists[i],
				     &redir_lists[i],
				     &cmd_nargs[i],
				     &num_redirs[i]);
		if (ret)
			goto out_free_lists;
	} while (++i != ncommands);

	if (mysh_noexecute)
		return ret;

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
	for (i = 0; i < ncommands; i++) {
		free_string_list(&cmd_arg_lists[i]);
		free_string_list(&var_assignment_lists[i]);
		free_string_list(&redir_lists[i]);
	}
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

	/* split the tokens into individual lists (commands), around the '|'
	 * signs. */
	ncommands = 0;
	list_for_each_entry(tok, tok_list, list)
		if (tok->type & TOK_CLASS_CMD_BOUNDARY)
			ncommands++;

	struct list_head command_tokens[ncommands];

	for (i = 0; i < ncommands; i++)
		INIT_LIST_HEAD(&command_tokens[i]);

	if (list_is_singular(tok_list)) {
		ret = 0;
		goto out;
	}

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
			input_buf = optarg;
			input_buf_len = strlen(optarg) + 1;
			input_buf[input_buf_len - 1] = '\n';
			ret = execute_shell_input(&cur_tok_list, input_buf, &input_buf_len);
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

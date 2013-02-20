/*
 * mysh_parse.c
 */

#include "mysh.h"
#include <ctype.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

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
		if (glob_buf.gl_pathc > 1 || strcmp(glob_buf.gl_pathv[0], s->chars) != 0)
			flags |= STRING_FLAG_FILENAME_EXPANDED;
		free_string(s);
		for (i = 0; i < glob_buf.gl_pathc; i++) {
			s2 = new_string_with_data(glob_buf.gl_pathv[i],
						  strlen(glob_buf.gl_pathv[i]));
			s2->flags = flags;
			list_add_tail(&s2->list, out_list);
		}
		globfree(&glob_buf);
	}
	return 0;
}

/* Performs filename expansion on a list of strings.  The list of strings is
 * replaced with the list of expanded strings.  0 is returned on success; -1 is
 * returned on read error in glob(). */
static int do_filename_expansion(struct list_head *string_list)
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

/* Do parameter expansion and word splitting.  */
static int expand_params_and_word_split(struct token *tok,
					struct token *next,
					struct list_head *out_list)
{
	struct string *s;
	bool leading_whitespace;
	unsigned char *param_char_map = NULL;

	mysh_assert(tok->type & TOK_CLASS_STRING);
	mysh_assert(list_empty(out_list));

 	s = xmalloc(sizeof(struct string));
	s->chars = tok->tok_data;
	s->len = strlen(tok->tok_data);
	s->flags = 0;
	tok->tok_data = NULL;
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
		if (next && trailing_whitespace)
			next->preceded_by_whitespace = true;
	} else {
		list_add_tail(&s->list, out_list);
		leading_whitespace = false;
	}
	free(param_char_map);
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
static int glue_strings(struct list_head *string_list)
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

static struct token *next_token_nodel(struct list_head *toks)
{
	struct token *tok;

	if (list_empty(toks))
		tok = NULL;
	else
		tok = list_entry(toks->next, struct token, list);
	return tok;
}

static struct token *next_token(struct list_head *toks)
{
	struct token *tok = next_token_nodel(toks);
	if (tok)
		list_del(&tok->list);
	return tok;
}

struct redir_spec {
	unsigned requires_right_string_is_fd : 1;
	unsigned accepts_whitespace_before_right_string : 1;
	unsigned right_fd_is_input : 1;

	int open_flags;
	int default_left_fd;
};

enum redir_spec_number {
	REDIRECT_OUTPUT_NUM = 0,
	APPEND_OUTPUT_NUM,
	DUP_OUTPUT_FD_NUM,
	REDIRECT_INPUT_NUM,
	DUP_INPUT_FD_NUM,
};

/*
 * [N=STDOUT_FILENO]>FILENAME:
 * dup2(open(FILENAME, O_WRONLY | O_TRUNC | O_CREAT), N);
 * FILENAME may be preceded by whitespace and cannot expand to more than one string.
 *
 * [N=STDOUT_FILENO]>>FILENAME:
 * dup2(open(FILENAME, O_WRONLY | O_APPEND | O_CREAT), N);
 * FILENAME may be preceded by whitespace and cannot expand to more than one string.
 *
 * &>>FILENAME:
 * dup2(open(FILENAME, O_WRONLY | O_APPEND | O_CREAT), STDOUT_FILENO);
 * dup2(STDOUT_FILENO, STDERR_FILENO);
 * FILENAME may be preceded by whitespace and cannot expand to more than one string.
 * Equivalent to >>FILENAME 2>&1
 *
 * &>FILENAME:
 * dup2(open(FILENOME, O_WRONLY | O_TRUNC | O_CREAT), STDOUT_FILENO);
 * dup2(STDOUT_FILENO, STDERR_FILENO);
 * FILENAME may be preceded by whitespace and cannot expand to more than one string.
 * Equivalent to >FILENAME 2>&1
 *
 * [N=STDOUT_FILENO]>&M
 * dup2(M, N)
 *
 * [N=STDIN_FILENO]<FILENAME:
 * dup2(open(FILENAME, O_RDONLY), N);
 * FILENAME may be preceded by whitespace and cannot expand to more than one string.
 *
 * [N=STDIN_FILENO]<&M
 * dup2(M, N)
 * M may not be preceded by whitespace and cannot expand to more than one string.
 *
 */
static const struct redir_spec redir_specs[] = {
	/* [N=STDOUT_FILENO]>FILENAME */
	[REDIRECT_OUTPUT_NUM] = {
		.requires_right_string_is_fd = 0,
		.accepts_whitespace_before_right_string = 1,
		.open_flags = O_WRONLY | O_TRUNC | O_CREAT,
		.default_left_fd = STDOUT_FILENO,
	},
	/* [N=STDIN_FILENO]<FILENAME */
	[REDIRECT_INPUT_NUM] = {
		.requires_right_string_is_fd = 0,
		.accepts_whitespace_before_right_string = 1,
		.open_flags = O_RDONLY,
		.default_left_fd = STDIN_FILENO,
	},
	/* [N=STDOUT_FILENO]>>FILENAME */
	[APPEND_OUTPUT_NUM] = {
		.requires_right_string_is_fd = 0,
		.accepts_whitespace_before_right_string = 1,
		.open_flags = O_WRONLY | O_APPEND | O_CREAT,
		.default_left_fd = STDOUT_FILENO,
	},
	/* [N=STDOUT_FILENO]>&M */
	[DUP_OUTPUT_FD_NUM] = {
		.requires_right_string_is_fd = 1,
		.right_fd_is_input = 0,
		.accepts_whitespace_before_right_string = 0,
		.open_flags = -1,
		.default_left_fd = STDOUT_FILENO,
	},
	/* [N=STDIN_FILENO]<&M */
	[DUP_INPUT_FD_NUM] = {
		.requires_right_string_is_fd = 1,
		.right_fd_is_input = 1,
		.accepts_whitespace_before_right_string = 0,
		.open_flags = -1,
		.default_left_fd = STDIN_FILENO,
	},
};

static int expand_single_string(struct token *tok, struct token *next,
				struct string **string_ret)
{
	int ret;
	LIST_HEAD(string_list);
	ret = expand_params_and_word_split(tok, next, &string_list);
	if (ret)
		goto out_free_string_list;
	ret = glue_strings(&string_list);
	if (ret)
		goto out_free_string_list;
	if (!mysh_filename_expansion_disabled) {
		ret = do_filename_expansion(&string_list);
		if (ret)
			goto out_free_string_list;
	}
	if (list_empty(&string_list))
		*string_ret = NULL;
	else if (list_is_singular(&string_list))
		*string_ret = list_entry(string_list.next, struct string, list);
	else {
		ret = -1;
		goto out_free_string_list;
	}
out:
	return ret;
out_free_string_list:
	free_string_list(&string_list);
	goto out;
}

static int add_redirection(const struct redir_spec *spec,
			   struct string *left_adjacent_string,
			   struct token *next,
			   struct token *next_next,
			   struct list_head *redirs)
{
	struct redirection *redir = xmalloc(sizeof(struct redirection));
	int ret = 0;
	struct string *right_string;

	redir->dest_fd = spec->default_left_fd;
	if (left_adjacent_string &&
	    !(left_adjacent_string->flags & (STRING_FLAG_FILENAME_EXPANDED |
					     STRING_FLAG_PARAM_EXPANDED)))
	{
		char *tmp;
		int left_fd = strtol(left_adjacent_string->chars, &tmp, 10);
		if (left_fd >= 0 && tmp != left_adjacent_string->chars && !*tmp) {
			redir->dest_fd = left_fd;
			clear_string(left_adjacent_string);
		}
	}

	if (!next ||
	    (!spec->accepts_whitespace_before_right_string &&
	     next->preceded_by_whitespace)
	    || (ret = expand_single_string(next, next_next, &right_string)) || !right_string)
	{
		mysh_error("expected single %s after redirection operator",
			   spec->requires_right_string_is_fd ? "file descriptor" : "filename");
		if (ret == 0)
			ret = -1;
		goto out;
	}

	if (spec->requires_right_string_is_fd) {
		char *tmp;
		int right_fd = strtol(right_string->chars, &tmp, 10);
		if (right_fd >= 0 && tmp != right_string->chars && !*tmp)
			redir->src_fd = right_fd;
		else {
			mysh_error("expected valid file descriptor "
				   "after redirection operator");
			ret = -1;
			goto out_free_string;
		}
		redir->is_file = false;
	} else {
		redir->src_filename = right_string->chars; // XXX
		right_string->chars = NULL;
		right_string->len = 0;
		redir->open_flags = spec->open_flags;
		redir->is_file = true;
	}
out_free_string:
	free_string(right_string);
out:
	if (ret == 0)
		list_add_tail(&redir->list, redirs);
	else
		free(redir);
	return ret;
}

static void add_stderr_to_stdout_redirection(struct list_head *redirs)
{
	struct redirection *redir;

	redir = xmalloc(sizeof(*redir));
	redir->is_file = false;
	redir->src_fd = 1;
	redir->dest_fd = 2;
	list_add_tail(&redir->list, redirs);
}

static int parse_next_redirection(struct list_head *toks,
				  struct string *prev_string,
				  struct list_head *redirs,
				  bool *async_ret)
{
	struct token *tok, *tok2, *tok3, *tok4;
	int ret = 0;

	tok = next_token(toks);
	if (tok->preceded_by_whitespace)
		prev_string = NULL;
	tok2 = tok3 = tok4 = NULL;
	switch (tok->type) {
	case TOK_GREATER_THAN:
		/* > */
		tok2 = next_token(toks);
		if (!tok2)
			goto out_syntax_error;
		if (tok2->type & TOK_GREATER_THAN && !tok2->preceded_by_whitespace) {
			tok3 = next_token(toks);
			if (tok3 && tok3->type & TOK_CLASS_STRING) {
				/* [N]>>WORD (output redirection, append) */
				ret = add_redirection(&redir_specs[APPEND_OUTPUT_NUM],
						      prev_string, tok3,
						      next_token_nodel(toks),
						      redirs);
				break;
			}
		} else if (tok2->type & TOK_CLASS_STRING) {
			/* [N]>WORD  (output redirection) */
			ret = add_redirection(&redir_specs[REDIRECT_OUTPUT_NUM],
					      prev_string, tok2,
					      next_token_nodel(toks),
					      redirs);
			break;
		} else if (tok2->type & TOK_AMPERSAND &&
			   !tok2->preceded_by_whitespace)
		{
			/* [N]>&WORD (duplicate output file descriptor) */
			tok3 = next_token(toks);
			if (tok3 && tok3->type & TOK_CLASS_STRING) {
				ret = add_redirection(&redir_specs[DUP_OUTPUT_FD_NUM],
						      prev_string, tok3,
						      next_token_nodel(toks),
						      redirs);
				break;
			}
		}
		goto out_syntax_error;
	case TOK_LESS_THAN:
		/* < */
		tok2 = next_token(toks);
		if (!tok2)
			goto out_syntax_error;
		if (tok2->type & TOK_CLASS_STRING) {
			/* [N]<WORD */
			ret = add_redirection(&redir_specs[REDIRECT_INPUT_NUM],
					      prev_string, tok2,
					      next_token_nodel(toks),
					      redirs);
			break;
		} else if (tok2->type & TOK_LESS_THAN && !tok2->preceded_by_whitespace) {
			/* << */
			tok3 = next_token(toks);
			if (!tok3)
				goto out_syntax_error;
			if (tok3->type & TOK_LESS_THAN && !tok3->preceded_by_whitespace) {
				tok4 = next_token(toks);
				if (tok4->type & TOK_CLASS_STRING) {
					/* <<<WORD (here string) */
					mysh_error("here strings not implemented");
					goto out_error;
				}
			} else if (tok3->type & TOK_CLASS_STRING) {
				/* <<WORD (here document) */
				mysh_error("here documents not implemented");
				goto out_error;
			}
		} else if (tok2->type & TOK_AMPERSAND && !tok2->preceded_by_whitespace) {
			tok3 = next_token(toks);
			/* [N]<&WORD  (duplicate input file descriptor) */
			if (tok3 && tok3->type & TOK_CLASS_STRING) {
				ret = add_redirection(&redir_specs[DUP_INPUT_FD_NUM],
						      prev_string, tok3,
						      next_token_nodel(toks),
						      redirs);
				break;
			}
		}
		goto out_syntax_error;
	case TOK_AMPERSAND:
		tok2 = next_token(toks);
		if (!tok2 && async_ret) {
			/* & */
			*async_ret = true;
			break;
		} else if (tok2 && tok2->type & TOK_GREATER_THAN) {
			/* &> */
			tok3 = next_token(toks);
			if (!tok3)
				goto out_syntax_error;
			if (tok3->type & TOK_CLASS_STRING) {
				/* &>WORD */
				/* Rewrite as
				 * >WORD 2>&1 */
				ret = add_redirection(&redir_specs[REDIRECT_OUTPUT_NUM],
						      NULL, tok3,
						      next_token_nodel(toks), redirs);
				if (ret)
					break;
				add_stderr_to_stdout_redirection(redirs);
				break;
			} else if (tok3->type & TOK_GREATER_THAN) {
				/* &>> */
				tok4 = next_token(toks);
				if (tok4 && tok4->type & TOK_CLASS_STRING) {
					/* &>>WORD */
					/* Rewrite as
					 * >>WORD 2>&1 */
					ret = add_redirection(&redir_specs[APPEND_OUTPUT_NUM],
							      NULL, tok4,
							      next_token_nodel(toks), redirs);
					if (ret)
						break;
					add_stderr_to_stdout_redirection(redirs);
					break;
				}

			}
		}
	default:
		goto out_syntax_error;
	}
out:
	free_token(tok);
	free_token(tok2);
	free_token(tok3);
	free_token(tok4);
	return ret;
out_error:
	ret = -1;
	goto out;
out_syntax_error:
	mysh_error("syntax error while parsing redirections");
	goto out_error;
}

static int parse_redirections(struct list_head *toks,
			      struct list_head *cmd_args,
			      struct list_head *redirs,
			      bool *async_ret)
{
	struct string *prev_string;
	int ret = 0;

	/* Set prev_string by following a string from the cmd_args list. */
	bool prev_string_is_borrowed = true;
	if (!list_empty(cmd_args))
		prev_string = list_entry(cmd_args->prev, struct string, list);
	else
		prev_string = NULL;

	/* While there are additional tokens remaining, try parsing the next
	 * redirection. */
	while (!list_empty(toks)) {
		ret = parse_next_redirection(toks, prev_string, redirs,
					     async_ret);
		if (ret) /* Parse error */
			break;

		if (prev_string) {
			char *chars = prev_string->chars;

			/* Redirection consumed borrowed string.  Delete it from
			 * the cmd_args list. */
			if (chars == NULL && prev_string_is_borrowed)
				list_del(&prev_string->list);

			/* If the redirection consumed the previous string, or
			 * it was not borrowed,free it */
			if (chars == NULL || !prev_string_is_borrowed)
				free_string(prev_string);

			/* If the previous string was not borrowed and it was
			 * not consumed by the redirection, it's a syntax error. */
			if (chars != NULL && !prev_string_is_borrowed) {
				mysh_error("unexpected string token");
				return -1;
			}
			prev_string = NULL;
		}

		/* If the next token is a string, try to set prev_string from
		 * it. */
		while (!list_empty(toks)) { /* while loop to take into account
					       strings that expand to nothing */
			struct token *tok = list_entry(toks->next, struct token, list);
			if (tok->type & TOK_CLASS_STRING) {
				struct token *next;
				if (tok->list.next == toks)
					next = NULL;
				else
					next = list_entry(tok->list.next, struct token, list);
				ret = expand_single_string(tok, next, &prev_string);
				if (ret)
					return ret;
				list_del(&tok->list);
				if (prev_string) {
					prev_string_is_borrowed = false;
					break;
				}
			} else {
				break;
			}
		}
	}
	return ret;

}

/* Given a list of tokens that make up a component of a pipeline, parse the
 * tokens into the command arguments, the variable assignments (if any), and the
 * redirections (if any).  In the process, do parameter expansion, word
 * splitting, word gluing, and filename globbing. */
int parse_tok_list(struct list_head *toks,
		   bool *async_ret,
		   struct list_head *cmd_args,
		   struct list_head *var_assignments,
		   struct list_head *redirs,
		   unsigned *cmd_nargs_ret,
		   unsigned *num_redirs_ret)
{
	struct token *tok, *tmp, *next;
	int ret;

	mysh_assert(list_empty(var_assignments));
	mysh_assert(list_empty(cmd_args));
	mysh_assert(list_empty(redirs));
	LIST_HEAD(string_list);
	list_for_each_entry_safe(tok, tmp, toks, list) {
		if (!(tok->type & TOK_CLASS_STRING))
			break;
		LIST_HEAD(tmp_list);
		if (tok->list.next == toks)
			next = NULL;
		else
			next = list_entry(tok->list.next, struct token, list);
		ret = expand_params_and_word_split(tok, next, &tmp_list);
		if (ret)
			goto out_free_string_list;
		list_splice_tail(&tmp_list, &string_list);
		list_del(&tok->list);
		free(tok->tok_data);
		free(tok);
	}

	ret = glue_strings(&string_list);
	if (ret)
		goto out_free_string_list;
	if (!mysh_filename_expansion_disabled) {
		ret = do_filename_expansion(&string_list);
		if (ret)
			goto out_free_string_list;
	}
	transfer_var_assignments(&string_list, var_assignments);
	ret = parse_redirections(toks, &string_list, redirs, async_ret);
	if (ret)
		goto out_free_string_list;
	list_splice_tail(&string_list, cmd_args);
	*cmd_nargs_ret = list_size(cmd_args);
	*num_redirs_ret = list_size(redirs);
	ret = 0;
	goto out;
out_free_string_list:
	free_string_list(&string_list);
out:
	return ret;
}

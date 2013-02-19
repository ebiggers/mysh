/*
 * mysh_parse.c
 */

#include "mysh.h"
#include <ctype.h>
#include <glob.h>
#include <stdlib.h>
#include <string.h>

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

/* Given a list of tokens that make up a component of a pipeline, parse the
 * tokens into the command arguments, the variable assignments (if any), and the
 * redirections (if any).  In the process, do parameter expansion, word
 * splitting, word gluing, and filename globbing. */
int parse_tok_list(struct list_head *toks,
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

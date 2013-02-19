/*
 * mysh_lex.c
 *
 * Code for lexical analyzer to parse a line of shell input into tokens
 * (represented by `struct token's)
 */

#include "mysh.h"
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

void free_tok_list(struct list_head *tok_list)
{
	struct token *tok, *tmp;
	list_for_each_entry_safe(tok, tmp, tok_list, list) {
		list_del(&tok->list);
		free(tok->tok_data);
		free(tok);
	}
}

/* Single quotes preserve the literal value of every character in the string. */
static ssize_t scan_single_quoted_string(const char *p,
					 size_t *bytes_remaining_p, char *out_buf)
{
	const char *term_quote;
	ssize_t len;

 	term_quote = memchr(p, '\'', *bytes_remaining_p);
	if (!term_quote)
		return LEX_NOT_ENOUGH_INPUT;

	len = term_quote - p;
	if (memchr(p, '\0', len)) {
		mysh_error("illegal null byte in single-quoted string");
		return LEX_ERROR;
	}
	if (out_buf)
		memcpy(out_buf, p, len);
	*bytes_remaining_p -= (len + 1);
	return len;
}

static ssize_t scan_double_quoted_string(const char *p,
					 size_t *bytes_remaining_p, char *out_buf)
{
	bool escape = false;
	ssize_t len = 0;
	size_t bytes_remaining = *bytes_remaining_p;
	char c;

	for (;; p++, bytes_remaining--) {
		if (!bytes_remaining)
			return LEX_NOT_ENOUGH_INPUT;
		c = *p;
		if (c == '\0') {
			mysh_error("illegal null byte in double-quoted string");
			return LEX_ERROR;
		} else if (c == '\\' && !escape) {
			/* backslash: try to escape the next character */
			escape = true;
		} else if (c == '"' && !escape) {
			/* found terminating double-quote */
			--bytes_remaining;
			break;
		} else {
			if (escape && !(shell_char_type(c) & SHELL_DOUBLE_QUOTE_SPECIAL)) {
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
	*bytes_remaining_p = bytes_remaining;
	return len;
}

static const unsigned char is_special[256] = {
	['\0'] = 1,
	['\\'] = 1,
	['\''] = 1,
	['"']  = 1,
	['&']  = 1,
	['#']  = 1,
	[';']  = 1,
	['|']  = 1,
	['>']  = 1,
	['<']  = 1,
	[' ']  = 1,
	['\t'] = 1,
	['\n'] = 1,
	['\r'] = 1,
};

static ssize_t scan_unquoted_string(const char *p,
				    size_t *bytes_remaining_p, char *out_buf)
{
	const char *orig_p = p;
	ssize_t len = 0;
	bool escape = false;
	size_t bytes_remaining = *bytes_remaining_p;
	for (;; p++, bytes_remaining--) {
		if (!bytes_remaining)
			return LEX_NOT_ENOUGH_INPUT;
		if (is_special[(unsigned char)*p]) {
			if (*p == '\0') {
				mysh_error("illegal null byte in unquoted string");
				return LEX_ERROR;
			}
			if (!escape) {
				if (*p == '\\') {
					escape = true;
					continue;
					/* special case to not start a comment
					 * at the # of $# */
				} else if (!(*p == '#' && p != orig_p && *(p - 1) == '$'))
					break;
			}
		}
		if (out_buf)
			*out_buf++ = *p;
		len++;
		escape = false;
	}
	*bytes_remaining_p = bytes_remaining;
	return len;
}

typedef ssize_t (*scan_string_t)(const char *, size_t *, char *);

/* Parse a string (single-quoted, double-quoted, or unquoted, depending on the
 * @scan_string function).  */
static int lex_string(const char *p, scan_string_t scan_string,
		      size_t *bytes_remaining_p, char **string_ret)
{
	ssize_t len;
	char *buf;
	size_t bytes_remaining = *bytes_remaining_p;
	
	/* get string length */
	len = scan_string(p, &bytes_remaining, NULL);
	if (len < 0)
		return len; /* parse error or not enough input */
	buf = xmalloc(len + 1);
	/* get the string */
	scan_string(p, bytes_remaining_p, buf);
	buf[len] = '\0';
	*string_ret = buf;
	return 0;
}

/*
 * Get the next token from the shell input.  See 'enum token_type' for the
 * possible token types.
 *
 * @p:                  Pointer to the input to lex.
 *
 * @bytes_remaining_p:  Pointer to the number of bytes of input that
 *                      are remaining.  On success, this value is updated
 *                      to subtract the bytes that were consumed by the new
 *                      token.
 *
 * @tok_ret:            On success, a pointer to the new token is written into
 *                      this location.
 *
 * Returns: 0 on success; or LEX_NOT_ENOUGH_INPUT if a full token cannot be parsed
 * with the remaining input; or LEX_ERROR if the input is invaled.
 */
int lex_next_token(const char *p, size_t *bytes_remaining_p,
		   struct token **tok_ret)
{
	struct token *tok;
	enum token_type type;
	char *tok_data;
	bool found_whitespace = false;
	size_t bytes_remaining = *bytes_remaining_p;
	int ret;

	/* ignore whitespace between tokens */
	while (shell_char_type(*p) & SHELL_LEX_WHITESPACE) {
		found_whitespace = true;
		p++;
		if (--bytes_remaining == 0)
			return LEX_NOT_ENOUGH_INPUT;
	}

	/* Choose the token type based on the next character, then parse the
	 * token. */
	tok_data = NULL;
	switch (*p) {
	case '&':
		type = TOK_AMPERSAND;
		--bytes_remaining;
		break;
	case '|':
		type = TOK_PIPE;
		--bytes_remaining;
		break;
	case '<':
		type = TOK_GREATER_THAN;
		--bytes_remaining;
		break;
	case '>':
		type = TOK_LESS_THAN;
		--bytes_remaining;
		break;
	case '#': /* everything after '#' character is a comment */
		{
			--bytes_remaining;
			const char *newline = memchr(p + 1, '\n', bytes_remaining);
			if (!newline)
				return LEX_NOT_ENOUGH_INPUT;
			bytes_remaining -= newline - p;
		}
		type = TOK_END_OF_SHELL_STATEMENT;
		break;
	case '\r':
	case '\n':
	case ';':
		type = TOK_END_OF_SHELL_STATEMENT;
		--bytes_remaining;
		break;
	case '\'':
		type = TOK_SINGLE_QUOTED_STRING;
		--bytes_remaining;
		ret = lex_string(p + 1, scan_single_quoted_string, &bytes_remaining, &tok_data);
		if (ret < 0)
			return ret;
		break;
	case '"':
		type = TOK_DOUBLE_QUOTED_STRING;
		--bytes_remaining;
		ret = lex_string(p + 1, scan_double_quoted_string, &bytes_remaining, &tok_data);
		if (ret < 0)
			return ret;
		break;
	default:
		/* anything that didn't match one of the special characters is
		 * treated as the beginning of an unquoted string */
		type = TOK_UNQUOTED_STRING;
		ret = lex_string(p, scan_unquoted_string, &bytes_remaining, &tok_data);
		if (ret < 0)
			return ret;
		break;
	}
	/* Allocate and initialize the token */
	tok = xmalloc(sizeof(struct token));
	tok->preceded_by_whitespace = found_whitespace;
	tok->type = type;
	/* tok_data defaults to NULL if not explicitly set for a string token */
	tok->tok_data = tok_data;
	/* Return the token and set the bytes remaining in the input according
	 * to how much was consumed */
	*bytes_remaining_p = bytes_remaining;
	*tok_ret = tok;
	return 0;
}

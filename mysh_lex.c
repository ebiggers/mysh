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

/* Single quotes preserve the literal value of every character in the string. */
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
static char *lex_string(const char **pp, scan_string_t scan_string)
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
struct token *lex_next_token(const char **pp)
{
	const char *p = *pp;
	struct token *tok;
	enum token_type type;
	char *tok_data;
	bool found_whitespace = false;

	/* ignore whitespace between tokens */
	while (isspace(*p)) {
		found_whitespace = true;
		p++;
	}

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
		if (!(tok_data = lex_string(&p, scan_single_quoted_string)))
			return NULL; /* parse error */
		break;
	case '"':
		type = TOK_DOUBLE_QUOTED_STRING;
		p++;
		if (!(tok_data = lex_string(&p, scan_double_quoted_string)))
			return NULL; /* parse error */
		break;
	case '|':
		type = TOK_PIPE;
		p++;
		break;
	case '<':
		type = TOK_GREATER_THAN;
		p++;
		break;
	case '>':
		type = TOK_LESS_THAN;
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
		if (!(tok_data = lex_string(&p, scan_unquoted_string)))
			return NULL; /* parse error */
		break;
	}
	/* allocate and initialize the token */
	tok = xmalloc(sizeof(struct token));
	tok->preceded_by_whitespace = found_whitespace;
	tok->type = type;
	/* tok_data defaults to NULL if not explicitly set for a string token */
	tok->tok_data = tok_data;
	tok->next = NULL;

	/* return the token and the pointer to the next unparsed character */
	*pp = p;
	return tok;
}

void free_tok_list(struct token *tok)
{
	struct token *next;
	while (tok) {
		next = tok->next;
		free(tok->tok_data);
		free(tok);
		tok = next;
	}
}


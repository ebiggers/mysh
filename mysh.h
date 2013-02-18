#ifndef _MYSH_H
#define _MYSH_H

#include <stddef.h>
#include <stdbool.h>

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))
#define ZERO_ARRAY(A) memset(A, 0, sizeof(A))

enum token_type {
	TOK_UNQUOTED_STRING      = 0x1,
	TOK_SINGLE_QUOTED_STRING = 0x2,
	TOK_DOUBLE_QUOTED_STRING = 0x4,
	TOK_PIPE                 = 0x8,
	TOK_GREATER_THAN         = 0x10,
	TOK_LESS_THAN            = 0x20,
	TOK_AMPERSAND            = 0x40,
	TOK_EOL                  = 0x80,
};


#define TOK_CLASS_STRING \
		(TOK_UNQUOTED_STRING | TOK_SINGLE_QUOTED_STRING | TOK_DOUBLE_QUOTED_STRING)

#define TOK_CLASS_REDIRECTION \
		(TOK_GREATER_THAN | TOK_LESS_THAN)

#define TOK_CLASS_CMD_BOUNDARY \
		(TOK_PIPE | TOK_EOL)

struct token {
	bool preceded_by_whitespace;
	enum token_type type;
	char *tok_data;
	struct token *next;
};

/* mysh_builtin.c */
extern bool maybe_execute_builtin(const struct token *command_toks,
				  const struct token *redirs,
				  unsigned cmd_nargs,
				  int *status_ret);

/* mysh_main.c */
extern char **positional_parameters;
extern unsigned int num_positional_parameters;

/* mysh_parse.c */
extern void free_tok_list(struct token *tok);
extern struct token *lex_next_token(const char **pp);

/* mysh_redir.c */
struct orig_fds {
	int orig_stdin;
	int orig_stdout;
};

extern int undo_redirections(const struct orig_fds *orig);
extern int do_redirections(const struct token *redirs, struct orig_fds *orig);

/* mysh_util.c */
extern void mysh_error(const char *fmt, ...);
extern void mysh_error_with_errno(const char *fmt, ...);
extern void *xmalloc(size_t len);
extern void *xstrdup(const char *s);


#endif /* _MYSH_H */

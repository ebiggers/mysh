#ifndef _MYSH_H
#define _MYSH_H

#include <stddef.h>
#include <stdbool.h>
#include "list.h"

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

enum redirection_type {
	REDIR_TYPE_FD_TO_FD,
	REDIR_TYPE_FILE_TO_FD,
	REDIR_TYPE_FD_TO_FILE_OVERWRITE,
	REDIR_TYPE_FD_TO_FILE_APPEND,
};

struct redirection {
	enum redirection_type type;
	union {
		int from_fd;
		const char *from_filename;
	};
	union {
		int to_fd;
		const char *to_filename;
	};
	struct list_head list;
};

struct string {
	char *chars;
	size_t len;
	struct list_head list;
};

/* mysh_builtin.c */
extern bool maybe_execute_builtin(const struct list_head *command_toks,
				  const struct list_head *redirs,
				  unsigned cmd_nargs,
				  int *status_ret);

/* mysh_main.c */
extern int last_exit_status;

/* mysh_param.c */
extern struct string *do_param_expansion(struct string *s);
extern const char *lookup_param(const char *name, size_t len);
extern void init_positional_params(int argc, char **argv);
extern void init_param_map();
extern void destroy_positional_params();
extern void destroy_param_map();

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
extern int do_redirections(const struct list_head *redirs, struct orig_fds *orig);

/* mysh_util.c */
extern void mysh_error(const char *fmt, ...);
extern void mysh_error_with_errno(const char *fmt, ...);
extern void *xmalloc(size_t len);
extern char *xstrdup(const char *s);
extern void *zmalloc(size_t len);
extern struct string * join_strings(struct list_head *strings);
extern void append_param(const char *name, size_t len, struct list_head *out_list);
extern void append_string(const char *chars, size_t len, struct list_head *out_list);
extern struct string *new_string(size_t len);
extern struct string *new_string_with_data(const char *chars, size_t len);
extern void free_string(struct string *s);
extern void free_string_list(struct list_head *string_list);


#endif /* _MYSH_H */

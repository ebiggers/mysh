#ifndef _MYSH_H
#define _MYSH_H

#include <stddef.h>
#include <stdbool.h>
#include <assert.h>
#include "list.h"

#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))
#define ZERO_ARRAY(A) memset(A, 0, sizeof(A))

#define mysh_assert assert

enum token_type {
	TOK_UNQUOTED_STRING        = 0x1,
	TOK_SINGLE_QUOTED_STRING   = 0x2,
	TOK_DOUBLE_QUOTED_STRING   = 0x4,
	TOK_PIPE                   = 0x8,
	TOK_GREATER_THAN           = 0x10,
	TOK_LESS_THAN              = 0x20,
	TOK_AMPERSAND              = 0x40,
	TOK_END_OF_SHELL_STATEMENT = 0x80,
};

enum lex_status {
	LEX_SUCCESS          = 0,
	LEX_ERROR            = -1000, /* don't conflict with exit statuses */
	LEX_NOT_ENOUGH_INPUT = -2000, /* don't conflict with exit statuses */
};

#define TOK_CLASS_STRING \
		(TOK_UNQUOTED_STRING | TOK_SINGLE_QUOTED_STRING | TOK_DOUBLE_QUOTED_STRING)

#define TOK_CLASS_REDIRECTION \
		(TOK_GREATER_THAN | TOK_LESS_THAN)

#define TOK_CLASS_CMD_BOUNDARY \
		(TOK_PIPE | TOK_END_OF_SHELL_STATEMENT)

struct token {
	bool preceded_by_whitespace;
	enum token_type type;
	char *tok_data;
	struct list_head list;
};


struct redirection {
	bool is_file;
	union {
		int src_fd;
		struct {
			char *src_filename;
			int open_flags;
		};
	};
	int dest_fd;
	struct list_head list;
};

struct string {
	char *chars;
	size_t len;
	int flags;
	struct list_head list;
};

enum string_flags {
	STRING_FLAG_UNQUOTED                = 0x1,
	STRING_FLAG_DOUBLE_QUOTED           = 0x2,
	STRING_FLAG_SINGLE_QUOTED           = 0x4,
	STRING_FLAG_PARAM_EXPANDED          = 0x8,
	STRING_FLAG_PRECEDING_WHITESPACE    = 0x10,
	STRING_FLAG_WORD_SPLIT              = 0x20,
	STRING_FLAG_FILENAME_EXPANDED       = 0x40,
	STRING_FLAG_WAS_PARAM               = 0x100,
	STRING_FLAG_VAR_ASSIGNMENT          = 0x200,
	STRING_FLAG_IN_REDIRECTIONS         = 0x400,
};

/* mysh_builtin.c */
extern int set_pwd();
extern bool maybe_execute_builtin(const struct list_head *command_toks,
				  const struct list_head *redirs,
				  unsigned cmd_nargs,
				  int *status_ret);

/* mysh_lex.c */
extern void free_tok_list(struct list_head *tok_list);
extern void free_token(struct token *tok);
extern int lex_next_token(const char *p, size_t *bytes_remaining_p,
			  struct token **tok_ret);

/* mysh_main.c */
extern int mysh_last_exit_status;
extern int mysh_filename_expansion_disabled;
extern int mysh_exit_on_error;
extern int mysh_write_input_to_stderr;
extern int mysh_noexecute;

extern int read_loop(int in_fd, bool interactive);
extern int execute_full_shell_input(const char *input, size_t len);

/* mysh_param.c */
extern struct string *
do_param_expansion(struct string *s, unsigned char **param_char_map);

extern const char *lookup_param(const char *name, size_t len);
extern void set_positional_params(int num_params, const char *param0,
				  const char **params);
extern void init_param_map();
extern const char *lookup_shell_param(const char *name);
extern const char *lookup_shell_param_len(const char *name, size_t len);
extern void insert_shell_param(const char *name, const char *value);
extern int export_variable(const char *name);
extern void insert_shell_param_len(const char *name, size_t len,
				   const char *value);
extern void make_param_assignment(const char *assignment);
extern bool string_matches_param_assignment(const struct string *s);
extern void destroy_positional_params();
extern void destroy_param_map();
extern int print_all_shell_variables();

extern char *all_positional_params;
extern char **positional_parameters;
extern unsigned int num_positional_parameters;

enum shell_char_type_flags {
	SHELL_PARAM_ALPHA_CHAR      = 0x1,
	SHELL_PARAM_NUMERIC_CHAR    = 0x2,
	SHELL_PARAM_UNDERSCORE_CHAR = 0x4,
	SHELL_PARAM_SPECIAL_CHAR    = 0x8,
	SHELL_LEX_WHITESPACE        = 0x10,
	SHELL_DOUBLE_QUOTE_SPECIAL  = 0x20,
	SHELL_UNQUOTED_SPECIAL      = 0x40,
};

#define SHELL_NORMAL_PARAM_FIRST_CHAR \
	(SHELL_PARAM_ALPHA_CHAR | SHELL_PARAM_UNDERSCORE_CHAR)

#define SHELL_NORMAL_PARAM_CHAR \
	(SHELL_NORMAL_PARAM_FIRST_CHAR | SHELL_PARAM_NUMERIC_CHAR)

extern const unsigned char _shell_char_tab[256];
static inline int
shell_char_type(char c)
{
	return (int)_shell_char_tab[(unsigned char)c];
}

/* mysh_parse.c */
extern int parse_tok_list(struct list_head *toks,
			  bool *async_ret,
			  struct list_head *cmd_args,
			  struct list_head *var_assignments,
			  struct list_head *redirs,
			  unsigned *cmd_nargs_ret,
			  unsigned *num_redirs_ret);

/* mysh_redir.c */
struct orig_fds {
	int fds[3];
};

extern int undo_redirections(const struct orig_fds *orig);
extern int do_redirections(const struct list_head *redirs, struct orig_fds *orig);

/* mysh_util.c */
extern void mysh_error(const char *fmt, ...);
extern void mysh_error_with_errno(const char *fmt, ...);
extern void *xmalloc(size_t size);
extern void *xzalloc(size_t size);
extern void *xrealloc(void *ptr, size_t size);
extern char *xstrdup(const char *s);
extern struct string * join_strings(struct list_head *strings);
extern struct string *new_string(size_t len);
extern struct string *new_string_with_data(const char *chars, size_t len);
extern void free_string(struct string *s);
extern void free_string_list(struct list_head *string_list);
extern void clear_string(struct string *s);


#endif /* _MYSH_H */

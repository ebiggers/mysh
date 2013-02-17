#include "mysh.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int builtin_pwd(int argc, const char **argv)
{
	char *buf;
	int ret = -1;

	buf = getcwd(NULL, 0);
	if (!buf) {
		mysh_error_with_errno("pwd: can't get current working directory");
		goto out;
	}
	if (puts(buf) == EOF)
		mysh_error_with_errno("pwd: write error");
	else
		ret = 0;
	free(buf);
out:
	return ret;
}

static int builtin_cd(int argc, const char **argv)
{
	int ret;
	const char *dest_dir;

	if (argc < 2) {
		dest_dir = getenv("HOME");
		if (!dest_dir) {
			mysh_error("cd: HOME not set");
			ret = 1;
			goto out;
		}
	} else {
		dest_dir = argv[1];
	}
	if (chdir(dest_dir) != 0) {
		mysh_error_with_errno("cd: %s", dest_dir);
		ret = 1;
	} else {
		ret = 0;
	}
out:
	return ret;
}

struct builtin {
	const char *name;
	int (*func)(int argc, const char **argv);
};

static const struct builtin builtins[] = {
	{"pwd", builtin_pwd},
	{"cd", builtin_cd},
	{"setenv", NULL},
	{"getenv", NULL},
	{"exit", NULL},
};

#define NUM_BUILTINS ARRAY_SIZE(builtins)

static int execute_builtin(const struct builtin *builtin,
			   const struct token *command_toks,
			   const struct token *redirs,
			   unsigned cmd_nargs)
{
	struct orig_fds orig = {-1, -1};
	const char *argv[cmd_nargs + 1];
	const struct token *tok;
	unsigned i;
	int status;
	int ret;

	/* Do redirections for the builtin */
	status = do_redirections(redirs, &orig);
	if (status)
		return status;

	/* Prepare argv for the builtin */
	tok = command_toks;
	for (i = 0; i < cmd_nargs; i++, tok = tok->next)
		argv[i] = tok->tok_data;
	argv[i] = NULL;
	/* Call the builtin function */
	builtin->func(cmd_nargs, argv);

	/* Undo redirections for the builtin */
	ret = undo_redirections(&orig);
	if (ret) {
		if (status == 0)
			status = ret;
		mysh_error_with_errno("Failed to restore redirections");
	}
	return status;
}

bool maybe_execute_builtin(const struct token *command_toks,
			   const struct token *redirs,
			   unsigned cmd_nargs, int *status_ret)
{
	const char *name = command_toks->tok_data;
	size_t i;

	for (i = 0; i < NUM_BUILTINS; i++) {
		if (strcmp(builtins[i].name, name) == 0 && builtins[i].func) {
			/* The command matched a builtin.  Execute it. */
			*status_ret = execute_builtin(&builtins[i],
						      command_toks,
						      redirs, cmd_nargs);
			return true;
		}
	}
	/* Not a builtin command */
	return false;
}

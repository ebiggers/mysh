/*
 * mysh_builtin.c
 *
 * Handle shell builtin commands such as 'cd'
 */

#include "mysh.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const char **environ;

/* Print the working directory */
static int builtin_pwd(unsigned argc, const char **argv)
{
	char *buf;
	int ret = 1;

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

/* Change the working directory */
static int builtin_cd(unsigned argc, const char **argv)
{
	int ret = 1;
	const char *dest_dir;

	if (argc) {
		dest_dir = argv[0];
	} else {
		dest_dir = getenv("HOME");
		if (!dest_dir) {
			mysh_error("cd: HOME not set");
			goto out;
		}
	}
	if (chdir(dest_dir) != 0)
		mysh_error_with_errno("cd: %s", dest_dir);
	else
		ret = 0;
out:
	return ret;
}

/* Set the value of an environmental variable */
static int builtin_setenv(unsigned argc, const char **argv)
{
	int ret;
	if (argc < 2) {
		mysh_error("usage: setenv VARIABLE VALUE");
		ret = 2;
		goto out;
	}
	if (setenv(argv[0], argv[1], 1) != 0) {
		mysh_error_with_errno("setenv %s", argv[0]);
		ret = 1;
	} else {
		ret = 0;
	}
out:
	return ret;
}

/* Print the value of an environmental variable */
static int builtin_getenv(unsigned argc, const char **argv)
{
	int ret = 0;
	if (argc) {
		const char *value = getenv(argv[0]);
		if (value) {
			if (puts(value) == EOF) {
				mysh_error_with_errno("getenv: write error");
				ret = 1;
			}
		} else
			ret = 2;
	} else {
		const char **env_p;
		for (env_p = environ; *env_p; env_p++) {
			if (puts(*env_p) == EOF) {
				mysh_error_with_errno("getenv: write error");
				ret = 1;
				break;
			}
		}
	}
	return ret;
}

static int builtin_shift(unsigned argc, const char **argv)
{
	unsigned amount;
	unsigned i;
	if (argc) {
		int iamount = atoi(argv[0]);
		if (iamount < 0) {
			mysh_error("shift: shift count cannot be negative");
			return 1;
		}
		amount = iamount;
		if (amount > num_positional_parameters) {
			mysh_error("shift: shift count greater than "
				   "number of positional parameters");
			return 1;
		}
	} else {
		if (num_positional_parameters == 0)
			return 0;
		amount = 1;
	}

	for (i = 1; i <= amount; i++)
		free(positional_parameters[i]);
	for (; i <= num_positional_parameters; i++)
		positional_parameters[i - amount] = positional_parameters[i];
	num_positional_parameters -= amount;
	return 0;
}

/* Exit the shell */
static int builtin_exit(unsigned argc, const char **argv)
{
	exit((argc) ? atoi(argv[0]) : 0);
}

/* Dummy command */
static int builtin_dummy(unsigned argc, const char **argv)
{
	return 0;
}


struct builtin {
	/* Name of the command through which the builtin will be called */
	const char *name;

	/* Function to execute the builtin command.  Note: for these functions,
	 * argv is not NULL-terminated, and argv[0] is the first argument rather
	 * than the builtin name. */
	int (*func)(unsigned argc, const char **argv);
};

/* Table of builtins recognized by the shell */
static const struct builtin builtins[] = {
	{"pwd",    builtin_pwd},
	{"cd",     builtin_cd},
	{"setenv", builtin_setenv},
	{"getenv", builtin_getenv},
	{"shift",  builtin_shift},
	{"exit",   builtin_exit},
	{":",      builtin_dummy},
};

#define NUM_BUILTINS ARRAY_SIZE(builtins)

/* Execute a builtin command.
 *
 * @builtin:       Pointer to a structure describing which builtin command to
 *                 execute.
 *
 * @command_toks:  List of tokens for the arguments to the builtin, not
 *                 including the name of the builtin itself.
 *
 * @redirs:        List of tokens for the builtin's redirections.
 *
 * @cmd_nargs:     Number of arguments that the builtin was passed, not
 *                 including the name of the builtin itself.
 *
 * Return value:   The return value of the builtin command function, or -1 if
 *                 there are problems doing or undoing redirections.
 */
static int execute_builtin(const struct builtin *builtin,
			   const struct list_head *cmd_args,
			   const struct list_head *redirs,
			   unsigned cmd_nargs)
{
	struct orig_fds orig = {-1, -1};
	const char *argv[cmd_nargs];
	struct string *s;
	unsigned i;
	int status;
	int ret;

	/* Do redirections for the builtin */
	status = do_redirections(redirs, &orig);
	if (status)
		return status;

	/* Prepare argv for the builtin */
	for (i = 0, s = list_entry(cmd_args->next, struct string, list);
	     i < cmd_nargs;
	     i++, s = list_entry(s->list.next, struct string, list))
	{
		argv[i] = s->chars;
	}
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

/* Execute a builtin command if the command matches a shell builtin.
 *
 * @command_toks:  List of tokens for the command.
 *
 * @redirs:        List of tokens for the command's redirections.
 *
 * @cmd_nargs:     Number of arguments that the command was passed, including
 *                 the first string that gives the name of the program or
 *                 builtin.
 *
 * @status_ret:    If a builtin is executed, its exit status is written
 *                 to this location.
 *
 * Return value:   %true if a builtin was executed; %false if the command
 *                 did not match a shell builtin.
 */
bool maybe_execute_builtin(const struct list_head *command_toks,
			   const struct list_head *redirs,
			   unsigned cmd_nargs, int *status_ret)
{
	const char *name;
	size_t i;

	if (list_empty(command_toks))
		return false;
	name = list_entry(command_toks->next, struct string, list)->chars;
	for (i = 0; i < NUM_BUILTINS; i++) {
		if (strcmp(builtins[i].name, name) == 0) {
			/* The command matched a builtin.  Execute it. */
			*status_ret = execute_builtin(&builtins[i],
						      command_toks->next,
						      redirs, cmd_nargs - 1);
			return true;
		}
	}
	/* Not a builtin command */
	return false;
}

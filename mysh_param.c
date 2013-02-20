/*
 * mysh_param.c
 *
 * Handle shell parameters / variables
 */

#include "mysh.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

char *all_positional_params;
char **positional_parameters;
unsigned int num_positional_parameters;

#define NUM_SHELL_PARAM_VALID_CHARS 63

struct param_trie_node {
	struct param_trie_node *children[NUM_SHELL_PARAM_VALID_CHARS];
	struct param_trie_node *parent;
	struct param_trie_node **parent_child_ptr;
	char *value;
	unsigned long num_children;
};

static struct param_trie_node param_trie_root;

static struct param_trie_node *
new_trie_node()
{
	return xzalloc(sizeof(struct param_trie_node));
}


extern char **environ;

static char trie_slot_tab[256];
static char trie_slot_to_char_tab[NUM_SHELL_PARAM_VALID_CHARS];

static const unsigned char trie_slot_ranges[][2] = {
	{'a', 'z'},
	{'A', 'Z'},
	{'0', '9'},
	{'_', '_'},
};

/* Initialize a table to map from the %NUM_SHELL_PARAM_VALID_CHARS allowed shell
 * variable characters to a numbering [0, %NUM_SHELL_PARAM_VALID_CHARS - 1]. */
static void init_trie_slot_tab()
{
	unsigned i, n;
	for (i = 0; i < 256; i++)
		trie_slot_tab[i] = -1;
	n = 0;
	for (i = 0; i < ARRAY_SIZE(trie_slot_ranges); i++) {
		unsigned char range_begin = trie_slot_ranges[i][0];
		unsigned char range_end = trie_slot_ranges[i][1];
		unsigned char c;
		for (c = range_begin; c <= range_end; c++) {
			trie_slot_tab[c] = n;
			trie_slot_to_char_tab[n] = c;
			n++;
		}
	}
	mysh_assert(n == NUM_SHELL_PARAM_VALID_CHARS);
}

static int trie_get_slot(char c)
{
	mysh_assert(trie_slot_tab['z'] != 0);
	return (int)trie_slot_tab[(unsigned char)c];
}


/* Set or unset a shell variable.
 *
 * @node:  Root of the trie of shell variables.
 * @name:  Name of the variable to insert.
 * @len:   Length of the name of the variable to insert.
 * @value: null-terminated value of the variable, or NULL to unset the variable.
 */
static void insert_param(struct param_trie_node *node,
			 const char *name, size_t len, char *value)
{
	while (len--) {
		int slot = trie_get_slot(*name++);
		if (slot < 0)
			return;
		if (!node->children[slot]) {
			node->children[slot] = new_trie_node();
			node->children[slot]->parent = node;
			node->children[slot]->parent_child_ptr = &node->children[slot];
			node->num_children++;
		}
		node = node->children[slot];
	}
	free(node->value);
	node->value = value;

	/* If we unset a parameter by inserting NULL, walk up the free and free
	 * any nodes that aren't needed anymore. */
	while (node->value == NULL && node->num_children == 0) {
		struct param_trie_node **parent_child_ptr = node->parent_child_ptr;
		struct param_trie_node *parent = node->parent;
		if (parent) {
			free(node);
			*parent_child_ptr = NULL;
			parent->num_children--;
		} else {
			break;
		}
		node = parent;
	}
}

void insert_shell_param_len(const char *name, size_t len, const char *value)
{
	insert_param(&param_trie_root, name, len, xstrdup(value));
}

void insert_shell_param(const char *name, const char *value)
{
	insert_param(&param_trie_root, name, strlen(name), xstrdup(value));
}

void make_param_assignment(const char *assignment)
{
	const char *equals = strchr(assignment, '=');
	mysh_assert(equals != NULL);
	insert_shell_param_len(assignment, equals - assignment, equals + 1);
}

/* Export a shell variable into the environment.
 *
 * @name: The name of the shell variable to insert (null-terminated)
 */
int export_variable(const char *name)
{
	const char *value = lookup_shell_param(name);
	int ret;
	if (value)
		ret = setenv(name, value, 1);
	else
		ret = unsetenv(name);
	if (ret)
		mysh_error_with_errno("export_variable()");
	return ret;
}

/* Loads the environment into shell variables */
void init_param_map()
{
	char **env_p;
	const char *name;

	init_trie_slot_tab();
	for (env_p = environ; (name = *env_p) != NULL; env_p++) {
		const char *equals;
		const char *value;
		size_t len;

		equals = strchr(name, '=');
		if (equals) {
			value = equals + 1;
			len = equals - name;
			insert_param(&param_trie_root, name, len, xstrdup(value));
		}
	}
}

static void free_param_trie(struct param_trie_node *node)
{
	size_t i;
	for (i = 0; i < ARRAY_SIZE(node->children); i++) {
		if (node->children[i]) {
			free_param_trie(node->children[i]);
			free(node->children[i]->value);
			free(node->children[i]);
		}
	}
	memset(node, 0, sizeof(node));

}

/* Unsets all shell variables, thereby freeing the memory allocated to store
 * shell variables. */
void destroy_param_map()
{
	free_param_trie(&param_trie_root);
}

bool string_matches_param_assignment(const struct string *s)
{
	size_t i;
	if (!(shell_char_type(s->chars[0]) & SHELL_NORMAL_PARAM_FIRST_CHAR))
		return false;
	for (i = 1; i < s->len; i++)
		if (!(shell_char_type(s->chars[i]) & SHELL_NORMAL_PARAM_CHAR))
			return (s->chars[i] == '=');
	return false;
}


/* Looks up a shell variable that is not a positional parameter or special
 * variable.  Note that this finds environmental variables as well, provided
 * that they have been inserted as shell variables with init_param_map().
 *
 * @name:  The name of the variable to look up.
 * @len:   The length of the name of the variable.
 *
 * Returns the value of the variable if it's set; otherwise, NULL.  */
const char *
lookup_shell_param_len(const char *name, size_t len)
{
	struct param_trie_node *node = &param_trie_root;
	while (len--) {
		int slot = trie_get_slot(*name++);
		if (slot < 0)
			return NULL;
		node = node->children[slot];
		if (!node)
			return NULL;
	}
	return node->value;
}

const char *
lookup_shell_param(const char *name)
{
	return lookup_shell_param_len(name, strlen(name));
}

static char *get_all_positional_params()
{
	size_t total_len = 1;
	unsigned i;
	char *p;

	if (all_positional_params)
		free(all_positional_params);
	for (i = 1; i <= num_positional_parameters; i++)
		total_len += strlen(positional_parameters[i]);
	total_len += num_positional_parameters;
	all_positional_params = p = xmalloc(total_len);
	*p = '\0';
	for (i = 1; i <= num_positional_parameters; i++) {
		p = stpcpy(p, positional_parameters[i]);
		if (i != num_positional_parameters)
			p = stpcpy(p, " ");
	}
	return all_positional_params;
}
/* Looks up a shell variable that may be a regular variable, a positional
 * parameter, or a special variable. */
const char *
lookup_param(const char *name, size_t len)
{
	static char buf[20];
	unsigned char char_type = shell_char_type(*name);
	if (char_type & SHELL_PARAM_NUMERIC_CHAR) {
		/* Positional parameter */
		unsigned n = 0;
		do {
			n *= 10;
			n += *name - '0';
		} while (--len);
		if (n > num_positional_parameters)
			return NULL;
		else
			return positional_parameters[n];
	} else if (char_type & SHELL_PARAM_SPECIAL_CHAR) {
		/* Special variable */
		switch (*name) {
		case '$':
			/* $$: Process ID */
			sprintf(buf, "%d", getpid());
			return buf;
		case '?':
			/* $?: Exit status of last command */
			sprintf(buf, "%d", mysh_last_exit_status);
			return buf;
		case '#':
			/* $#: Number of positional parameters */
			sprintf(buf, "%u", num_positional_parameters);
			return buf;
		case '*':
		case '@': /* Note: $@ does not yet behave correctly (it's treated the same as $*) */
			/* All positional parameters */
			return get_all_positional_params();
		}
	} else {
		/* Regular variable; look it up in the trie. */
		return lookup_shell_param_len(name, len);
	}
	return NULL;
}

static int node_print_variable(struct param_trie_node *node)
{
	size_t len;
	size_t i;
	struct param_trie_node *p;
	int ret;

	p = node;
	len = 0;
	while (p != &param_trie_root) {
		p = p->parent;
		len++;
	}
	char name[len + 1];
	name[len] = '\0';

	p = node;
	i = len - 1;
	do {
		name[i] = trie_slot_to_char_tab[p->parent_child_ptr - p->parent->children];
		p = p->parent;
	} while (i-- != 0);
	ret = printf("%s='%s'\n", name, node->value);
	if (ret >= 0)
		ret = 0;
	else
		mysh_error_with_errno("set: write error");
	return ret;
}

static int do_print_all_shell_variables(struct param_trie_node *node)
{
	size_t i;
	int ret = 0;
	if (node->value) {
		ret = node_print_variable(node);
		if (ret)
			goto out;
	}
	for (i = 0; i < ARRAY_SIZE(node->children); i++) {
		if (node->children[i]) {
			ret = do_print_all_shell_variables(node->children[i]);
			if (ret)
				goto out;
		}
	}
out:
	return ret;
}

int print_all_shell_variables()
{
	return do_print_all_shell_variables(&param_trie_root);
}

static void
append_string(const char *chars, size_t len, struct list_head *out_list)
{
	struct string *s = new_string_with_data(chars, len);
	list_add_tail(&s->list, out_list);
}


static void
append_param(const char *name, size_t len, struct list_head *out_list)
{
	const char *value = lookup_param(name, len);
	if (value) {
		struct string *s = new_string_with_data(value, strlen(value));
		list_add_tail(&s->list, out_list);
		s->flags |= STRING_FLAG_WAS_PARAM;
	}
}


/*
 * Perform parameter expansion on a string by replacing sequences beginning with
 * a '$' character with the corresponding expansion, or "" if the corresponding
 * parameter is empty or unset.
 *
 * @s:  The string to expand.  It may be empty, but it may not be NULL.
 *
 * @param_char_map:  A pointer to an unsigned char * in which will be written a
 *                   pointer to a map from character indices to boolean values
 *                   indicating whether the corresponding character was produced
 *                   by parameter expansion (1) or was present in the original
 *                   string (0).  If parameter expansion was not performed or
 *                   the string expanded to length 0, NULL will be written into
 *                   the location instead.
 *
 * The return value is the expanded string.  The caller is responsible for its
 * memory; the caller is no longer responsible for the memory for @s, which is
 * freed if it's not returned as the resulting string (due to no parameter
 * expansion occurring).  The expanded string will have the flag
 * STRING_FLAG_PARAM_EXPANDED set, in addition to any flags that were set on @s.
 */
struct string *
do_param_expansion(struct string *s, unsigned char **param_char_map)
{
	const char *var_begin;
	const char *dollar_sign;
	const char *var_end;
	unsigned char mask;
	unsigned char char_type;
	struct string *tmp;
	size_t len;
	struct list_head string_list;

	var_end = s->chars;
	dollar_sign = strchr(var_end, '$');
	if (!dollar_sign || *(dollar_sign + 1) == '\0') { 
		/* No parameter expansion to be done.
		 * Return the original string. */
		*param_char_map = NULL; 
		return s;
	}

	/* As a result of doing the expansions, we will produce a list of
	 * strings in the list @string_list, each of which will correspond to
	 * either literal characters or to characters that were produced as a
	 * result of a parameter expansion.  These strings are later joined
	 * together to produce the returned, expanded string. */
	INIT_LIST_HEAD(&string_list);
	do {
		/* Append the literal characters (if any) from after the end of
		 * the previous variable (or the beginning of the string) up
		 * until the dollar sign. */
		if (dollar_sign != var_end)
			append_string(var_end, dollar_sign - var_end, &string_list);

		/* Parse the parameter name.  There are several cases; for
		 * example, the parameter may be specified as ${foo} rather than
		 * $foo.  Parameters beginning with a number are positional
		 * parameters, so they are parsed up until the first non-digit
		 * or closing '}'.  Any invalid sequences, such as the missing
		 * closing '}', are just output literally. */
		var_begin = dollar_sign + 1;
		var_end = var_begin;
		if (*var_end == '{')
			var_end++;
		char_type = shell_char_type(*var_end);
		if (char_type & (SHELL_NORMAL_PARAM_CHAR |
				 SHELL_PARAM_SPECIAL_CHAR))
		{
			if (char_type & SHELL_PARAM_NUMERIC_CHAR) {
				/* positional parameter */
				mask = SHELL_PARAM_NUMERIC_CHAR;
			} else if (char_type & SHELL_PARAM_SPECIAL_CHAR) {
				/* special parameter */
				mask = 0;
			} else {
				/* regular parameter */
				mask = SHELL_NORMAL_PARAM_CHAR;
			}
			do {
				var_end++;
			} while (shell_char_type(*var_end) & mask);
			if (*var_end == '}') {
				if (*var_begin == '{') {
					var_begin++;
					var_end++;
				}
			} else {
				if (*var_begin == '{') {
					/* missing closing brace */
					var_end = var_begin;
				}
			}
			/* The parameter name (or special character, or
			 * positional parameter) begins at var_begin and
			 * continues for (var_end - var_begin characters).  Look
			 * it up and append it to the string list. */
			if (var_end - var_begin != 0)
				append_param(var_begin, var_end - var_begin,
					     &string_list);
		}
	} while ((dollar_sign = strchr(var_end, '$')) && *(dollar_sign + 1) != '\0');

	/* Append any remaining literal characters */
	if (*var_end)
		append_string(var_end, strlen(var_end), &string_list);

	/* Sum the total length of the expanded string */
	len = 0;
	list_for_each_entry(tmp, &string_list, list)
		len += tmp->len;
	if (len == 0) {
		/* The expansions produced the empty string.  Return the
		 * original string.  */
		free_string_list(&string_list);
		s->len = 0;
		s->chars[0] = '\0';
		*param_char_map = NULL;
	} else {
		/* The expansions produced one or more strings, which now need
		 * to be joined.  The original string that was passed in must be
		 * freed. */
		int flags;
		size_t pos;

		flags = s->flags;
		free_string(s);
		*param_char_map = xzalloc(len);
		pos = 0;
		list_for_each_entry(tmp, &string_list, list) {
			if (tmp->flags & STRING_FLAG_WAS_PARAM) {
				size_t i;
				for (i = 0; i < tmp->len; i++)
					(*param_char_map)[pos + i] = 1;
			}
			pos += tmp->len;

		}
		s = join_strings(&string_list);
		s->flags = flags;
	}
	s->flags |= STRING_FLAG_PARAM_EXPANDED;
	return s;
}

/* Set the positional parameters of the shell.
 *
 * @num_params:  Number of positional parameters, not counting $0.
 *               Equivalent to the $# shell variable.
 * @param0:      String to set as the $0 variable.
 * @params:      Array of length @num_params that gives the positional
 *               parameters $1, $2, ... $@num_params. */
void set_positional_params(int num_params, const char *param0,
			   const char **params)
{
	unsigned i;
	destroy_positional_params();
	num_positional_parameters = num_params;
	positional_parameters = xmalloc((num_positional_parameters + 1) * sizeof(char *));
	positional_parameters[0] = xstrdup(param0);
	for (i = 0; i < num_positional_parameters; i++)
		positional_parameters[i + 1] = xstrdup(params[i]);
}

/* Free the memory allocated for positional parameters. */
void destroy_positional_params()
{
	unsigned i;
	if (positional_parameters) {
		for (i = 0; i <= num_positional_parameters; i++)
			free(positional_parameters[i]);
		free(positional_parameters);
		positional_parameters = NULL;
		if (all_positional_params) {
			free(all_positional_params);
			all_positional_params = NULL;
		}
	}
}

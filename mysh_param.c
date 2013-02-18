#include "mysh.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

char **positional_parameters;
unsigned int num_positional_parameters;

struct param_trie_node {
	struct param_trie_node *children[63];
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

int trie_get_slot(char c)
{
	return (int)trie_slot_tab[(unsigned char)c];
}

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
	while (node->value == NULL && node->num_children == 0) {
		struct param_trie_node **parent_child_ptr = node->parent_child_ptr;
		struct param_trie_node *parent = node->parent;
		free(node);
		if (parent) {
			*parent_child_ptr = NULL;
			parent->num_children--;
		} else {
			break;
		}
		node = parent;
	}
}

void insert_shell_param(const char *name, const char *value)
{
	insert_param(&param_trie_root, name, strlen(name), xstrdup(value));
}

static void init_trie_slot_tab()
{
	int i, n;
	for (i = 0; i < 256; i++)
		trie_slot_tab[i] = -1;
	n = 0;
	for (i = 'a'; i <= 'z'; i++)
		trie_slot_tab[i] = n++;
	for (i = 'A'; i <= 'Z'; i++)
		trie_slot_tab[i] = n++;
	for (i = '0'; i <= '9'; i++)
		trie_slot_tab[i] = n++;
	trie_slot_tab['_'] = n++;
}

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

}

void destroy_param_map()
{
	free_param_trie(&param_trie_root);
}

#define SHELL_PARAM_ALPHA_CHAR      0x1
#define SHELL_PARAM_NUMERIC_CHAR    0x2
#define SHELL_PARAM_UNDERSCORE_CHAR 0x4
#define SHELL_PARAM_SPECIAL_CHAR    0x8
#define SHELL_PARAM_BEGIN_BRACE     0x10
#define SHELL_PARAM_END_BRACE       0x20

static const unsigned char shell_param_char_tab[256] = {
	['A' ... 'Z'] = SHELL_PARAM_ALPHA_CHAR,
	['a' ... 'z'] = SHELL_PARAM_ALPHA_CHAR,
	['0' ... '9'] = SHELL_PARAM_NUMERIC_CHAR,
	['_']         = SHELL_PARAM_UNDERSCORE_CHAR,
	['@']         = SHELL_PARAM_SPECIAL_CHAR,
	['*']         = SHELL_PARAM_SPECIAL_CHAR,
	['#']         = SHELL_PARAM_SPECIAL_CHAR,
	['?']         = SHELL_PARAM_SPECIAL_CHAR,
	['-']         = SHELL_PARAM_SPECIAL_CHAR,
	['$']         = SHELL_PARAM_SPECIAL_CHAR,
	['!']         = SHELL_PARAM_SPECIAL_CHAR,
	['{']         = SHELL_PARAM_BEGIN_BRACE,
	['}']         = SHELL_PARAM_END_BRACE,
};

static int
shell_param_char_type(char c)
{
	return shell_param_char_tab[(unsigned char)c];
}

const char *
lookup_shell_param(const char *name, size_t len)
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
lookup_param(const char *name, size_t len)
{
	if (len == 0)
		return NULL;

	static char buf[20];

	unsigned char char_type = shell_param_char_type(*name);
	if (char_type & SHELL_PARAM_NUMERIC_CHAR) {
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
		switch (*name) {
		case '$':
			sprintf(buf, "%d", getpid());
			return buf;
		case '?':
			sprintf(buf, "%d", last_exit_status);
			return buf;
		case '#':
			sprintf(buf, "%u", num_positional_parameters);
			return buf;
		}
	} else {
		return lookup_shell_param(name, len);
	}
	return NULL;
}


struct string *
do_param_expansion(struct string *s)
{
	const char *var_begin;
	const char *dollar_sign;
	const char *var_end;
	unsigned char mask;
	unsigned char char_type;
	LIST_HEAD(string_list);

	var_end = s->chars;
	dollar_sign = strchr(var_end, '$');
	if (!dollar_sign)
		return s;
	do {
		if (dollar_sign != var_end)
			append_string(var_end, dollar_sign - var_end, &string_list);
		var_begin = dollar_sign + 1;
		var_end = var_begin;
		if (*var_end == '{')
			var_end++;
		char_type = shell_param_char_type(*var_end);
		if (char_type & (SHELL_PARAM_ALPHA_CHAR |
				 SHELL_PARAM_NUMERIC_CHAR |
				 SHELL_PARAM_UNDERSCORE_CHAR |
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
				mask = SHELL_PARAM_ALPHA_CHAR | SHELL_PARAM_NUMERIC_CHAR |
				       SHELL_PARAM_UNDERSCORE_CHAR;
			}
			do {
				var_end++;
			} while (shell_param_char_type(*var_end) & mask);
			if (*var_end == '}') {
				if (*var_begin == '{') {
					var_begin++;
					var_end++;
				}
			}
			append_param(var_begin, var_end - var_begin, &string_list);
		}
	} while ((dollar_sign = strchr(var_end, '$')));
	if (*var_end)
		append_string(var_end, strlen(var_end), &string_list);
	if (list_empty(&string_list)) {
		s->len = 0;
		s->chars[0] = '\0';
		return s;
	} else
		return join_strings(&string_list);
}

void init_positional_params(int argc, char **argv)
{
	unsigned i;
	if (argc <= 0)
		num_positional_parameters = 0;
	else
		num_positional_parameters = argc - 1;
	positional_parameters = xmalloc((num_positional_parameters + 1) * sizeof(char *));
	for (i = 0; i <= num_positional_parameters; i++)
		positional_parameters[i] = xstrdup(argv[i]);
}

void destroy_positional_params()
{
	unsigned i;
	for (i = 0; i <= num_positional_parameters; i++)
		free(positional_parameters[i]);
	free(positional_parameters);
}

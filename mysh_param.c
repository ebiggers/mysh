#include "mysh.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define SHELL_PARAM_ALPHA_CHAR      0x1
#define SHELL_PARAM_NUMERIC_CHAR    0x2
#define SHELL_PARAM_UNDERSCORE_CHAR 0x4
#define SHELL_PARAM_SPECIAL_CHAR    0x8
#define SHELL_PARAM_BEGIN_BRACE     0x10
#define SHELL_PARAM_END_BRACE       0x20

char **positional_parameters;
unsigned int num_positional_parameters;

struct param_trie_node {
	struct param_trie_node *children[63];
	char *value;
};

static struct param_trie_node param_trie;

static struct param_trie_node *
new_trie_node()
{
	struct param_trie_node *node;
	node = xmalloc(sizeof(struct param_trie_node));
	memset(node, 0, sizeof(struct param_trie_node));
	return node;
}

void init_param_map()
{
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
	free_param_trie(&param_trie);
}


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

static const char *
lookup_shell_param(const char *name, size_t len)
{
	return NULL;
}

const char *
lookup_param(const char *name, size_t len)
{
	if (len == 0)
		return NULL;

	static char buf[20];

	if (*name & SHELL_PARAM_NUMERIC_CHAR) {
		unsigned n = 0;
		do {
			n *= 10;
			n += *name - '0';
		} while (--len);
		if (n > num_positional_parameters)
			return NULL;
		else
			return positional_parameters[n];
	} else if (*name & SHELL_PARAM_SPECIAL_CHAR) {
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
	return join_strings(&string_list);
}

void init_positional_params(int argc, char **argv)
{
	int i;

	num_positional_parameters = argc - 1;
	positional_parameters = xmalloc(argc * sizeof(char *));
	for (i = 0; i < argc; i++)
		positional_parameters[i] = argv[i];
}

void destroy_positional_params()
{
	unsigned i;
	for (i = 0; i <= num_positional_parameters; i++)
		free(positional_parameters[i]);
	free(positional_parameters);
}

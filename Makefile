CC := clang
CFLAGS := -O0 -Wall -g

#SHELL := $(shell if [ -x ./mysh ]; then echo mysh; else echo sh; fi )

SOURCES := mysh_builtin.c mysh_main.c mysh_parse.c mysh_redir.c mysh_util.c 
HEADERS := mysh.h
mysh:$(SOURCES) $(HEADERS)
	gcc -o $@ $(SOURCES) $(CFLAGS)

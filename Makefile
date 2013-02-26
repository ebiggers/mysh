
WITH_READLINE := $(shell if [ -e /usr/include/readline ]; \
				then echo yes; \
			 else \
				 echo no; \
			 fi )

ifeq ($(WITH_READLINE),yes)
READLINE_CPPFLAGS := -DWITH_READLINE
READLINE_LDLIBS := -lreadline
else
READLINE_CPPFLAGS :=
READLINE_LDLIBS :=
endif

#CFLAGS  := -O0 -Wall -g -pipe
CFLAGS  := -O2 -Wall -DNDEBUG -pipe
CPPFLAGS := $(READLINE_CPPFLAGS)

OBJ     := mysh_builtin.o mysh_lex.o mysh_main.o \
	   mysh_param.o mysh_parse.o mysh_redir.o mysh_util.o
LDLIBS  := $(READLINE_LDLIBS)
HEADERS := mysh.h
EXE     := mysh


$(EXE):$(OBJ)
	$(CC) -o $@ $(CFLAGS) $+ $(LDLIBS)

$(OBJ): %.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(EXE) $(OBJ)

.PHONY: clean

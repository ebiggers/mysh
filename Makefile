CFLAGS  := -O0 -Wall -g -pipe
#CFLAGS  := -O2 -Wall -DNDEBUG -pipe

OBJ     := mysh_builtin.o mysh_lex.o mysh_main.o \
	   mysh_param.o mysh_parse.o mysh_redir.o mysh_util.o
HEADERS := mysh.h
EXE     := mysh

$(EXE):$(OBJ)
	$(CC) -o $@ $(CFLAGS) $+

$(OBJ): mysh.h


clean:
	rm -f $(EXE) $(OBJ)

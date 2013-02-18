CFLAGS  := -O2 -Wall -g
OBJ     := mysh_builtin.o mysh_main.o mysh_parse.o mysh_redir.o mysh_util.o 
HEADERS := mysh.h
EXE     := mysh

$(EXE):$(OBJ)
	gcc -o $@ $(CFLAGS) $+

$(OBJ): mysh.h


clean:
	rm -f $(EXE) $(OBJ)

# Define required macros here
REMOVE = rm
CC = gcc


# Explicit rules, all the commands you can call with make 
# (note: the <tab> in the command line is necessary for make to work) 
# target:  dependency1 dependency2 ...
#       <tab> command

#Called by: make targetname 
#also executed when you just called make. This calls the first target. 
all: target_main target_find target_display target_listdirall target_listdir target_countline target_daemon target_checkdaemon


target_find: ./bin/source/find.c
	$(CC) ./bin/source/find.c -o ./bin/find

target_display: ./bin/source/display.c
	$(CC) ./bin/source/display.c -o ./bin/display 

target_listdirall: ./bin/source/listdir_all.c
	$(CC) ./bin/source/listdir_all.c -o ./bin/listdirall

target_listdir: ./bin/source/listdir.c
	$(CC) ./bin/source/listdir.c -o ./bin/listdir

target_countline: ./bin/source/count_line.c
	$(CC) ./bin/source/count_line.c -o ./bin/countline

target_daemon: ./bin/source/summond.c
	$(CC) ./bin/source/summond.c -o ./bin/summond

target_checkdaemon: ./bin/source/check_daemon.c 
	$(CC) ./bin/source/check_daemon.c -o ./bin/checkdaemon 

target_main: ./bin/source/shell.c
	$(CC) ./bin/source/shell.c -o cseshell

clean:
	$(REMOVE) ./bin/find ./bin/display ./bin/listdirall ./bin/listdir ./bin/countline ./bin/summond ./bin/checkdaemon cseshell





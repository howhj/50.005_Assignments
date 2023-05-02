#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
/* "readdir" etc. are defined here. */
#include <dirent.h>
/* limits.h defines "PATH_MAX". */
#include <limits.h>

#define SHELL_BUFFERSIZE 256
#define SHELL_INPUT_DELIM " \t\r\n\a"
#define SHELL_OPT_DELIM "-"

// Stores how many tokens are given currently
int current_number_tokens;

/*
  List of builtin commands, followed by their corresponding functions.
 */
const char *builtin_commands[] = {
    "cd",    // calls shell_cd
    "help",  // calls shell_help
    "exit",  // calls shell_exit
    "usage", // calls shell_usage
};

int num_builtin_functions()
{
  return sizeof(builtin_commands) / sizeof(char *);
};

/*
The fundamental functions of the shell interface
*/
char *read_line_stdin(void);            // TASK 1
char **tokenize_line_stdin(char *line); // TASK 2
int process_command(char **args);       // TASK 3
void main_loop(void);                   // TASK 4

/*
Functions of the shell interface
*/
int shell_cd(char **args);
int shell_help(char **args);
int shell_exit(char **args);
int shell_usage(char **args);

/*This is array of functions, with argument char***/
int (*builtin_command_func[])(char **) = {
    &shell_cd,   // builtin_command_func[0]
    &shell_help, // builtin_command_func[1]
    &shell_exit, // builtin_command_func[2]
    &shell_usage // builtin_command_func[3]
};

// helper functions
void red();
void yellow();
void reset();
void setup_program_path(char **args);
void print_error_message(char **args);
int exec_sys_prog(char **args);

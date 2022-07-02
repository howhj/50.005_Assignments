#include "system_program.h"

/*
Count the number of lines in a file
*/
int execute(char **args)
{

    int number_of_lines = 0;
    FILE *fp;

    // open file in read mode
    fp = fopen(args[1], "r");

    if (!fp)
    {
        printf("File %s cannot be found.\n", args[1]);
        return 1;
    }

    /** TASK 5  **/
    // ATTENTION: you need to implement this function from scratch and not to utilize other system program to do this
    // 1. Read the file line by line by using getline(&buffer, &size, fp)
    // 2. Loop, as long as getline() does not return -1, keeps reading and increment the count
    // 3. Store the count at number_of_lines
    // DO NOT PRINT ANYTHING TO THE OUTPUT

    /***** BEGIN ANSWER HERE *****/
    size_t buf_size = SHELL_BUFFERSIZE;
    char *line = malloc(sizeof(char) * buf_size);
    
    
    
    while (getline(&line, &buf_size, fp) != -1){
        
        number_of_lines++;
    }


    /*********************/
    fclose(fp); // close file.
    printf("%d \t %s \n", number_of_lines, args[1]);
    return 1;
}

int main(int argc, char **args)
{
    return execute(args);
}
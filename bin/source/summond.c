/*
 * summond.c
 * This example daemonizes a process, writes a few log messages,
 * sleeps 60 seconds and terminates afterwards.
 */

#include "system_program.h"

char output_file_path[PATH_MAX];

/*This function summons a daemon process out of the current process*/
static int create_daemon()
{

    /* TASK 6 */
    // Incantation on creating a daemon with fork() twice

    // 1. Fork() from the parent process
    // 2. Close parent with exit(1)
    // 3. On child process (this is intermediate process), call setsid() so that the child becomes session leader to lose the controlling TTY
    // 4. Ignore SIGCHLD, SIGHUP
    // 5. Fork() again, parent (the intermediate) process terminates
    // 6. Child process (the daemon) set new file permissions using umask(0). Daemon's PPID at this point is 1 (the init)
    // 7. Change working directory to root
    // 8. Close all open file descriptors using sysconf(_SC_OPEN_MAX) and redirect fd 0,1,2 to /dev/null
    // 9. Return to main
    // DO NOT PRINT ANYTHING TO THE OUTPUT
    /***** BEGIN ANSWER HERE *****/
    pid_t pid;
    pid = fork();

    if (pid > 0) {
        exit(1);
    }

    setsid();
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid_t pid2;
    pid2 = fork();

    if (pid2 > 0) {
        exit(1);
    }

    umask(0);
    chdir("/");
    
    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }
    
    /*
    * Attach file descriptors 0, 1, and 2 to /dev/null. */
    int fd0 = open("/dev/null", O_RDWR);
    int fd1 = dup(0);
    int fd2 = dup(0);
    /*********************/

    return 0;
}

static int daemon_work()
{

    int num = 0;
    FILE *fptr;

    // write PID of daemon in the beginning
    fptr = fopen(output_file_path, "a");
    if (fptr == NULL)
    {
        return EXIT_FAILURE;
    }

    fprintf(fptr, "%d with FD %d\n", getpid(), fileno(fptr));
    fclose(fptr);

    while (1)
    {

        fptr = fopen(output_file_path, "a");

        if (fptr == NULL)
        {
            return EXIT_FAILURE;
        }

        fprintf(fptr, "PID %d Daemon writing line %d to the file.  \n", getpid(), num);
        num++;

        fclose(fptr);

        sleep(10);

        if (num == 10)
            break;
    }

    return EXIT_SUCCESS;
}
int main(int argc, char **args)
{
    // Setup path
    if (getcwd(output_file_path, sizeof(output_file_path)) == NULL)
    {
        perror("getcwd() error, exiting now.");
        return 1;
    }
    strcat(output_file_path, "/logfile.txt");

    create_daemon();

    /* Open the log file */
    openlog("summond", LOG_PID, LOG_DAEMON);
    syslog(LOG_NOTICE, "Daemon started.");
    closelog();

    return daemon_work();
}
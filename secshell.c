/*
 * secshell.c — stage 1: basic shell loop
 *
 * fork/exec loop, argument parsing, built-in cd/exit,
 * and SIGINT protection. Starting point before adding
 * any security layer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_CMD_LEN 1024
#define MAX_ARGS    64

static void parse_args(char *cmd, char **args)
{
    int i = 0;
    args[i] = strtok(cmd, " \t\r\n");
    while (args[i] && i < MAX_ARGS - 1)
        args[++i] = strtok(NULL, " \t\r\n");
    args[i] = NULL;
}

static void sigint_handler(int sig)
{
    (void)sig;
    write(STDOUT_FILENO, "\nsecshell> ", 11);
}

int main(void)
{
    char  input[MAX_CMD_LEN];
    char *args[MAX_ARGS];
    pid_t pid;
    int   status;

    struct sigaction sa = { .sa_handler = sigint_handler };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    while (1) {
        printf("secshell> ");
        fflush(stdout);

        if (!fgets(input, sizeof input, stdin))
            break;

        input[strcspn(input, "\n")] = '\0';
        if (input[0] == '\0')
            continue;

        parse_args(input, args);
        if (!args[0])
            continue;

        if (strcmp(args[0], "exit") == 0)
            break;

        if (strcmp(args[0], "cd") == 0) {
            if (!args[1])
                fprintf(stderr, "cd: missing argument\n");
            else if (chdir(args[1]) != 0)
                perror("cd");
            continue;
        }

        pid = fork();
        if (pid < 0) { perror("fork"); continue; }

        if (pid == 0) {
            execvp(args[0], args);
            perror(args[0]);
            exit(EXIT_FAILURE);
        }

        waitpid(pid, &status, 0);
    }

    return 0;
}

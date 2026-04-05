/*
 * secshell.c — stage 2: security policy classification
 *
 * Introduces the idea that not all commands need the same
 * privileges. Classifies commands into four tiers before
 * any kernel enforcement is added.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#define MAX_CMD_LEN 1024
#define MAX_ARGS    64

typedef enum {
    POLICY_UNRESTRICTED,
    POLICY_READONLY,
    POLICY_WRITEONLY,
    POLICY_NETWORK,
    POLICY_DANGEROUS
} SecurityPolicy;

typedef struct {
    const char    *cmd;
    SecurityPolicy policy;
} CommandPolicy;

static const CommandPolicy policy_db[] = {
    { "cat",   POLICY_READONLY  }, { "ls",    POLICY_READONLY  },
    { "grep",  POLICY_READONLY  }, { "head",  POLICY_READONLY  },
    { "tail",  POLICY_READONLY  }, { "less",  POLICY_READONLY  },
    { "more",  POLICY_READONLY  }, { "find",  POLICY_READONLY  },
    { "echo",  POLICY_WRITEONLY }, { "cp",    POLICY_WRITEONLY },
    { "mv",    POLICY_WRITEONLY }, { "touch", POLICY_WRITEONLY },
    { "mkdir", POLICY_WRITEONLY },
    { "curl",  POLICY_NETWORK   }, { "wget",  POLICY_NETWORK   },
    { "ping",  POLICY_NETWORK   }, { "ssh",   POLICY_NETWORK   },
    { "rm",    POLICY_DANGEROUS }, { "chmod", POLICY_DANGEROUS },
    { "chown", POLICY_DANGEROUS }, { "dd",    POLICY_DANGEROUS },
    { "mkfs",  POLICY_DANGEROUS },
    { NULL,    POLICY_UNRESTRICTED }
};

static SecurityPolicy get_policy(const char *cmd)
{
    for (int i = 0; policy_db[i].cmd != NULL; i++)
        if (strcmp(cmd, policy_db[i].cmd) == 0)
            return policy_db[i].policy;
    return POLICY_UNRESTRICTED;
}

/* audit log — append one line per command execution */
static void log_audit(const char *cmd, SecurityPolicy policy,
                      int allowed, const char *reason)
{
    FILE *f = fopen("secshell_audit.log", "a");
    if (!f) return;
    time_t now = time(NULL);
    char  *ts  = ctime(&now);
    ts[strlen(ts) - 1] = '\0';
    fprintf(f, "[%s] CMD=%s POLICY=%d ALLOWED=%d REASON=%s\n",
            ts, cmd, (int)policy, allowed, reason);
    fclose(f);
}

/* nanosecond-precision overhead tracking */
typedef struct { struct timespec start, end; long overhead_ns; } PerfMetrics;

static void perf_start(PerfMetrics *m) { clock_gettime(CLOCK_MONOTONIC, &m->start); }
static void perf_end(PerfMetrics *m)
{
    clock_gettime(CLOCK_MONOTONIC, &m->end);
    m->overhead_ns = (m->end.tv_sec  - m->start.tv_sec)  * 1000000000L
                   + (m->end.tv_nsec - m->start.tv_nsec);
}

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

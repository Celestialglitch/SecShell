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
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <asm/unistd.h>

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

/* ------------------------------------------------------------------ */
/* seccomp-bpf filters                                                  */
/* ------------------------------------------------------------------ */

#define LOAD_SYSCALL_NR \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, \
             (offsetof(struct seccomp_data, nr)))
#define ALLOW_SYSCALL(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define KILL_PROCESS \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
#define ALLOW_ALL \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static void install_filter(struct sock_filter *f, unsigned short len)
{
    struct sock_fprog prog = { .len = len, .filter = f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        { perror("prctl(NO_NEW_PRIVS)"); exit(EXIT_FAILURE); }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
        { perror("prctl(SECCOMP)"); exit(EXIT_FAILURE); }
}

/*
 * READONLY allowlist — tightest policy.
 * Note: write() is allowed so programs can produce output.
 * Classic BPF cannot inspect fd arguments, so we cannot restrict
 * write() to stdout/stderr only. That requires stateful eBPF.
 */
static void install_readonly_filter(void)
{
    struct sock_filter f[] = {
        LOAD_SYSCALL_NR,
        ALLOW_SYSCALL(__NR_read),
        ALLOW_SYSCALL(__NR_write),
        ALLOW_SYSCALL(__NR_open),
        ALLOW_SYSCALL(__NR_openat),
        ALLOW_SYSCALL(__NR_close),
        ALLOW_SYSCALL(__NR_fstat),
        ALLOW_SYSCALL(__NR_newfstatat),
        ALLOW_SYSCALL(__NR_lseek),
        ALLOW_SYSCALL(__NR_mmap),
        ALLOW_SYSCALL(__NR_munmap),
        ALLOW_SYSCALL(__NR_brk),
        ALLOW_SYSCALL(__NR_exit),
        ALLOW_SYSCALL(__NR_exit_group),
        KILL_PROCESS
    };
    install_filter(f, (unsigned short)(sizeof f / sizeof f[0]));
}

/* WRITEONLY — extends READONLY with file-creation syscalls */
static void install_writeonly_filter(void)
{
    struct sock_filter f[] = {
        LOAD_SYSCALL_NR,
        ALLOW_SYSCALL(__NR_read),   ALLOW_SYSCALL(__NR_write),
        ALLOW_SYSCALL(__NR_open),   ALLOW_SYSCALL(__NR_openat),
        ALLOW_SYSCALL(__NR_close),  ALLOW_SYSCALL(__NR_creat),
        ALLOW_SYSCALL(__NR_mkdir),  ALLOW_SYSCALL(__NR_rename),
        ALLOW_SYSCALL(__NR_unlink), ALLOW_SYSCALL(__NR_stat),
        ALLOW_SYSCALL(__NR_fstat),  ALLOW_SYSCALL(__NR_lstat),
        ALLOW_SYSCALL(__NR_newfstatat),
        ALLOW_SYSCALL(__NR_mmap),   ALLOW_SYSCALL(__NR_munmap),
        ALLOW_SYSCALL(__NR_brk),    ALLOW_SYSCALL(__NR_exit),
        ALLOW_SYSCALL(__NR_exit_group),
        KILL_PROCESS
    };
    install_filter(f, (unsigned short)(sizeof f / sizeof f[0]));
}

/*
 * NETWORK — denylist approach.
 * Allows network and file I/O but blocks execve/fork/clone
 * so the process cannot spawn children or replace itself.
 */
static void install_network_filter(void)
{
    struct sock_filter f[] = {
        LOAD_SYSCALL_NR,
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execve, 0, 1), KILL_PROCESS,
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_clone,  0, 1), KILL_PROCESS,
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_fork,   0, 1), KILL_PROCESS,
        ALLOW_ALL
    };
    install_filter(f, (unsigned short)(sizeof f / sizeof f[0]));
}

static void apply_policy(const char *cmd)
{
    SecurityPolicy p = get_policy(cmd);
    switch (p) {
    case POLICY_READONLY:
        printf("[SecShell] policy=READONLY  cmd=%s\n", cmd);
        install_readonly_filter();
        break;
    case POLICY_WRITEONLY:
        printf("[SecShell] policy=WRITEONLY cmd=%s\n", cmd);
        install_writeonly_filter();
        break;
    case POLICY_NETWORK:
        printf("[SecShell] policy=NETWORK   cmd=%s\n", cmd);
        install_network_filter();
        log_audit(cmd, p, 1, "network access permitted");
        break;
    case POLICY_DANGEROUS:
        fprintf(stderr, "[SecShell] WARNING: '%s' is destructive. Type 'yes' to proceed: ", cmd);
        fflush(stderr);
        { char buf[8];
          if (!fgets(buf, sizeof buf, stdin) || strncmp(buf, "yes", 3) != 0) {
              printf("[SecShell] Aborted.\n");
              log_audit(cmd, p, 0, "user denied");
              exit(EXIT_SUCCESS);
          }
        }
        log_audit(cmd, p, 1, "user confirmed");
        break;
    case POLICY_UNRESTRICTED:
        log_audit(cmd, p, 1, "unrestricted");
        break;
    }
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

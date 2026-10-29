/* Historical bypass class 1 (#9): nested exec from a signed program.
 * argv[1] = absolute path of an unsigned payload. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    char *a[] = {argv[1], NULL};
    char *e[] = {NULL};
    execve(argv[1], a, e);
    int e1 = errno;
    syscall(SYS_execveat, AT_FDCWD, argv[1], a, e, 0);
    int e2 = errno;
    /* absolute pathname: dirfd is ignored by the kernel even with AT_EMPTY_PATH */
    syscall(SYS_execveat, 4095, argv[1], a, e, AT_EMPTY_PATH);
    int e3 = errno;
    execl("/bin/sh", "sh", "-c", "echo PWNED:shell", (char *)NULL);
    int e4 = errno;
    pid_t p = fork();
    if (p == 0) {
        execve(argv[1], a, e);
        _exit(errno & 0x7f);
    }
    int st = 0;
    waitpid(p, &st, 0);
    printf("BLOCKED:execve errnos=%d,%d,%d,%d child=%d\n", e1, e2, e3, e4, WEXITSTATUS(st));
    return 0;
}

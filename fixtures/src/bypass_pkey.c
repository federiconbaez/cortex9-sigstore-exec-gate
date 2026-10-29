/* Historical bypass class 2 (#9): make injected bytes executable with
 * pkey_mprotect (plus the mprotect and anonymous RWX mmap siblings). */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
static const unsigned char sc[] = {0xb8, 0x37, 0x13, 0x00, 0x00, 0xc3}; /* mov eax,0x1337; ret */
static int call(void *m) { return ((int (*)(void))m)(); }
int main(void) {
    long pg = 4096;
    int pwned = 0;
    void *m = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 3;
    memcpy(m, sc, sizeof sc);
    long r1 = syscall(SYS_pkey_mprotect, m, pg, PROT_READ | PROT_EXEC, -1);
    int e1 = r1 ? errno : 0;
    if (r1 == 0 && call(m) == 0x1337) { puts("PWNED:pkey_mprotect"); pwned = 1; }
    void *m2 = mmap(NULL, pg, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(m2, sc, sizeof sc);
    int r2 = mprotect(m2, pg, PROT_READ | PROT_EXEC);
    int e2 = r2 ? errno : 0;
    if (r2 == 0 && call(m2) == 0x1337) { puts("PWNED:mprotect"); pwned = 1; }
    void *x = mmap(NULL, pg, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    int e3 = x == MAP_FAILED ? errno : 0;
    if (x != MAP_FAILED) { memcpy(x, sc, sizeof sc); if (call(x) == 0x1337) { puts("PWNED:mmap_rwx"); pwned = 1; } }
    if (!pwned) printf("BLOCKED:wx errnos=%d,%d,%d\n", e1, e2, e3);
    return 0;
}

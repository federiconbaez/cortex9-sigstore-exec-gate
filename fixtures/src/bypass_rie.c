/* Historical bypass class 4 (#9): READ_IMPLIES_EXEC turns PROT_READ|PROT_WRITE
 * anonymous memory into RWX without any PROT_EXEC argument a filter could see.
 * Mode "self": the program sets the persona. Mode "inherited": the invoker did. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
static const unsigned char sc[] = {0xb8, 0x37, 0x13, 0x00, 0x00, 0xc3};
static int is_exec(void *p) {
    FILE *f = fopen("/proc/self/maps", "r");
    char line[512];
    unsigned long lo, hi, a = (unsigned long)p;
    char perms[8];
    int x = 0;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) == 3 && a >= lo && a < hi) x = perms[2] == 'x';
    if (f) fclose(f);
    return x;
}
int main(int argc, char **argv) {
    int inherited = argc > 1 && strcmp(argv[1], "inherited") == 0;
    int e = 0;
    if (!inherited && personality(READ_IMPLIES_EXEC) == -1) e = errno;
    int cur = personality(0xffffffff);
    void *m = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) return 3;
    memcpy(m, sc, sizeof sc);
    if (is_exec(m) && ((int (*)(void))m)() == 0x1337) {
        puts("PWNED:read_implies_exec");
        return 0;
    }
    printf("BLOCKED:rie errno=%d persona=%#x\n", e, cur);
    return 0;
}

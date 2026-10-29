/* Historical bypass class 3 (#9): ia32 `int $0x80` execve (nr 11) from a
 * 64-bit process, which a filter that only checks x86_64 numbers misses.
 * argv[1] = absolute path of an unsigned payload. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    char *buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (buf == MAP_FAILED) return 3;
    strncpy(buf + 64, argv[1], 1024);
    uint32_t *av = (uint32_t *)buf;
    av[0] = (uint32_t)(uintptr_t)(buf + 64);
    av[1] = 0;
    av[2] = 0; /* envp = {NULL} */
    long ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(11L), "b"((long)(uintptr_t)(buf + 64)), "c"((long)(uintptr_t)av), "d"((long)(uintptr_t)(av + 2))
                     : "memory");
    printf("BLOCKED:int80 ret=%ld\n", ret);
    return 0;
}

/* Built with -z execstack: must be refused by the static policy. */
#include <stdio.h>
int main(void) { puts("MARK:EXECSTACK"); return 0; }

/* Benign fixture: prints a marker so the harness can detect execution. */
#include <stdio.h>
#ifndef TAG
#define TAG "00"
#endif
static const char mark[] = "MARK:OK-" TAG;
int main(void) { puts(mark); return 0; }

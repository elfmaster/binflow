#include "binflow.h"


int bypass_anti_ptrace(void)
{
	if (putenv("LD_PRELOAD=./fake_ptrace.so") != 0) {
		perror("putenv");
		return -1;
	}
	return 0;
}


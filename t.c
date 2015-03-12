#include <stdio.h>

static char bp_code[] = {0xcd, 0x80, 0xcc, 0x00};

int main(void)
{
	printf("%lx\n", *(long *)&bp_code[0]);
}


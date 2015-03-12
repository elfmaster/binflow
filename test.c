#include <stdio.h>
#include <string.h>

int f(int a, int b, int c)
{
	printf("%d, %d, %d\n", a, b, c);
}

int main(void)
{
	int j = 0;
	int i;
	char *ptr = strdup("Hello");
	char buf[255];
	strncpy(buf, "hello", 8);
	printf("%s\n", buf);
	printf("%s\n", ptr);
	f(3, 2, 1);
	for (i = 0; i < 3; i++)
		f(1 + i, 2, 3 + i);
}


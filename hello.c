#include <stdio.h>

void f1(int a, int b, int c)
{
	printf("%d %d %d\n", a, b, c);
}
void f2(int a, int b, int c)
{
        printf("%d %d %d\n", a, b, c);
}
 main(void)
{
	f1(1, 2, 3);
	f2(3, 2, 1);
}

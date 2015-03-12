#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>

int check_serial(char *s)
{
	char serial[] = {'L', 'e', 'V', 'i', 'a', 't', 'h', 'a', 'n', '3', '1', '\0'};
	char *p;

	if ((p = strchr(s, '\n')) != NULL)
		*p = '\0';
	
	if (!strcmp(serial, s))
		return 1;
	return 0;
}

int dummy_check(char *s)
{
	printf("Checking serial...\n");
	sleep(2);
	int r = check_serial(s);
	return r;
}

int main(void)
{
	char c;
	char buf[256];
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
		printf("fuck off\n");
		exit(-1);
	}

	for (;;) {
		printf("Enter serial number: ");
		fgets(buf, sizeof(buf), stdin);
		if (dummy_check(buf) == 1) {
			printf("Congratulations, you have a licensed copy of ./traceme\n");
			exit(0);
		}
		continue;
	}
}



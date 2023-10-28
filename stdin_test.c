#include <stdio.h>

int main(void)
{
	printf("Hello, world!, now with write!\n");
	printf(">");

	char buf[256];
	fgets(buf, 256, stdin);
	printf("You wrote: %s\n", buf);

	return 0;
}
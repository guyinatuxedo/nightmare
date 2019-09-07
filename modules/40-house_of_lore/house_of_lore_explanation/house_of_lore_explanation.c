#include <stdio.h>
#include <stdlib.h>
int main(void)
{
	unsigned long *ptr0;

	unsigned long targetVar0[4] = 0;
	unsigned long targetVar1[4] = 0;
	
	ptr0 = malloc(200);

	printf("First we allocated a small bin size chunk at:\t%p\n", ptr0);

	malloc(1000);

	free(ptr0);

	malloc(1200);

	ptr0[1] = (unsigned long)&targetVar;

	printf("%p\n", malloc(200));
	printf("%p\n", malloc(200));
	printf("%p\n", malloc(200));

}
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main(void)	
{
	int i, out;
	time_t var0 = time(NULL);
	srand(var0);

	for (i = 0; i < 50; i++)
	{
		out = rand() % 100;
		printf("%d\n", out);
	}
	
	return 0;
}
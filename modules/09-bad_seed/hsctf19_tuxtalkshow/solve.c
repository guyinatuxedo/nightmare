#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

int main()
{
    int array[6];
    int i, output;
    uint32_t randVal, ans;

    srand(time(0)); 


    i = 0;

    array[0] = 0x79;
    array[1] = 0x12c97f;
    array[2] = 0x135f0f8;
    array[3] = 0x74acbc6;
    array[4] = 0x56c614e;
    array[5] = 0xffffffe2;

    while (i < 6)
    {
    	randVal = rand();
    	array[i] = array[i] - ((randVal % 10) - 1);
    	i += 1;
    }

    i = 0;
    output = 0;

    while (i < 6)
    {
    	output = output + array[i];
    	i += 1;
    }


    printf("%d\n", output);	
}

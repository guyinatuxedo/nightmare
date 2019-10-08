#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

int main()
{
    uint32_t rand_num;
    srand(time(0)); 
    rand_num = rand();
    uint32_t ans;
    printf("%d\n", rand_num);	
}

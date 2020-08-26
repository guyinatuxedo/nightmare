#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    puts("The goal of this is to show how we can edit a freed chunk using a Double Free bug.");
    puts("Editing freed chunks will allow us to overwrite heap metadata, which is crucial to a lot of heap attacks.");
    puts("However a bug to edit the heap metadata is often just one piece of the exploitation process.\n");

    printf("So we start off by allocating three chunks of memory. Let's also write some data to them.\n\n");

    char *ptr0, *ptr1, *ptr2;

    ptr0 = malloc(0x30);
    ptr1 = malloc(0x30);
    ptr2 = malloc(0x30);

    char *data0 = "00000000";
    char *data1 = "11111111";
    char *data2 = "22222222";

    memcpy(ptr0, data0, 0x8);
    memcpy(ptr1, data1, 0x8);   
    memcpy(ptr2, data2, 0x8);

    printf("Chunk0: @ %p\t contains: %s\n", ptr0, ptr0);
    printf("Chunk1: @ %p\t contains: %s\n", ptr1, ptr1);
    printf("Chunk2: @ %p\t contains: %s\n\n", ptr2, ptr2);

    printf("Now is where the bug comes in. We will free the same pointer twice (the first chunk pointed to by ptr0).\n");
    printf("In between the two frees, we will free a different pointer. This is because in several different versions of malloc, there is a double free check \n(however in libc-2.27 it will hit the tcache and this will be fine).\n");
    printf("It will check if the pointer being free is the same as the last chunk freed, and if it is the program will cease execution.\n");
    printf("To bypass this, we can just free something in between the two frees to the same pointer.\n\n");

    free(ptr0);
    free(ptr1);
    free(ptr0);
    
    printf("Next up we will allocate three new chunks of the same size that we freed, and write some data to them. This will give us the three chunks we freed.\n\n");

    char *ptr3, *ptr4, *ptr5;

    ptr3 = malloc(0x30);
    ptr4 = malloc(0x30);
    ptr5 = malloc(0x30);

    memcpy(ptr3, data0, 0x8);
    memcpy(ptr4, data1, 0x8);   
    memcpy(ptr5, data2, 0x8);

    printf("Chunk3: @ %p\t contains: %s\n", ptr3, ptr3);
    printf("Chunk4: @ %p\t contains: %s\n", ptr4, ptr4);
    printf("Chunk5: @ %p\t contains: %s\n\n", ptr5, ptr5);

    printf("So you can see that we allocated the same pointer twice, as a result of freeing the same pointer twice (since malloc will reuse freed chunks of similar sizes for performance boosts).\n");
    printf("Now we can free one of the pointers to either Chunk 3 or 5 (ptr3 or ptr5), and clear out the pointer. We will still have a pointer remaining to the same memory chunk, which will now be freed.\n");
    printf("As a result we can use the double free to edit a freed chunk. Let's see it in action by freeing Chunk3 and setting the pointer equal to 0x0 (which is what's supposed to happen to prevent UAFs).\n\n");


    free(ptr3);
    ptr3 = 0x0;

    printf("Chunk3: @ %p\n", ptr3);
    printf("Chunk5: @ %p\n\n", ptr5);

    printf("So you can see that we have freed ptr3 (Chunk 3) and discarded it's pointer. However we still have a pointer to it. Using that we can edit the freed chunk.\n\n");

    char *data3 = "15935728";
    memcpy(ptr5, data3, 0x8);

    printf("Chunk5: @ %p\t contains: %s\n\n", ptr5, ptr5);

    printf("Just like that, we were able to use a double free to edit a free chunk!\n");

}
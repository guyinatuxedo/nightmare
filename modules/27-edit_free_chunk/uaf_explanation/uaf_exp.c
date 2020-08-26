#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    puts("The goal of this is to show how we can edit a freed chunk using a UAF (Use After Free) bug.");
    puts("Editing freed chunks will allow us to overwrite heap metadata, which is crucial to a lot of attacks.");
    puts("However a bug to edit the heap metadata is often just one piece of the exploitation process.");

    printf("So we start off by allocating a chunk of memory.\n\n");

    char *ptr;
    ptr = malloc(0x30);

    printf("Chunk0: %p\n\n", ptr);

    printf("Let's store some data in it.\n\n");

    char *data0 = "15935728";
    memcpy(ptr, data0, 0x8);

    printf("Chunk 0 @ %p\t contains: %s\n\n", ptr, ptr);

    printf("Now we will free it, but keep the pointer for later.\n\n");

    free(ptr);

    printf("Chunk 0 (ptr) has now been freed. Now here is where the UAF comes in. It's pretty simple. We freed a pointer, but we keep it around so we can use it. Hence the name Use After Free.");
    printf("We will write to the chunk to use it.\n\n");

    char *data1 = "75395128";
    memcpy(ptr, data1, 0x8);

    printf("Chunk 0 @ %p\t contains: %s\n\n", ptr, ptr);

    printf("Just like that, we used a UAF to edit a freed chunk!\n");

}
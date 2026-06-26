# edit free chunk uaf explanation

This module essentially explains what a Use After Free is. It can be used to edit freed chunks, and heap metadata among other things. This can be very useful for other attacks. Checkout the well documented source code or binary to see the explanation.

The code:
```
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
```

The code running:
```
$	./uaf_exp 
The goal of this is to show how we can edit a freed chunk using a UAF (Use After Free) bug.
Editing freed chunks will allow us to overwrite heap metadata, which is crucial to a lot of attacks.
However a bug to edit the heap metadata is often just one piece of the exploitation process.
So we start off by allocating a chunk of memory.

Chunk0: 0x5654ef831670

Let's store some data in it.

Chunk 0 @ 0x5654ef831670	 contains: 15935728

Now we will free it, but keep the pointer for later.

Chunk 0 (ptr) has now been freed. Now here is where the UAF comes in. It's pretty simple. We freed a pointer, but we keep it around so we can use it. Hence the name Use After Free.We will write to the chunk to use it.

Chunk 0 @ 0x5654ef831670	 contains: 75395128

Just like that, we used a UAF to edit a freed chunk!
```
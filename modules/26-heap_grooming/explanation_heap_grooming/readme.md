# Heap Grooming Explanation

This is just a well documented c file which explains what heap grooming is, and shows one example of it. 

The C code:

```
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
	puts("So today we will be discussing heap grooming.");
	puts("The heap has a lot of behavior that is predictable.");
	puts("Heap grooming is when we manipulate the heap in certain ways, so it performs certain actions.");
	puts("That includes mapping additional pages to memory, and how it allocates certain chunks.\n");

	puts("For performance purposes, malloc will reuse recently freed chunks if they fit the size.");
	puts("Let's allocate some chunks!\n");

	unsigned long int *ptr0, *ptr1, *ptr2;

	ptr0 = malloc(0x10); 
	ptr1 = malloc(0x10); 
	ptr2 = malloc(0x10); 

	printf("Our chunks are:\nptr0: %p\nptr1: %p\nptr2: %p\n\n", ptr0, ptr1, ptr2);

	printf("Now let's free them.\n\n");

	free(ptr0);
	free(ptr1);
	free(ptr2);

	printf("Now that they have been freed, we will allocate three chunks of the same size.\n");
	printf("Because of malloc's chunk reusage, we should get the same three chunks we freed back in the reverse order.\n");
	printf("So we should get ptr2 first, then ptr1, and then finally ptr0.\n\n");

	printf("ptr0: %p\n", malloc(0x10));
	printf("ptr1: %p\n", malloc(0x10));
	printf("ptr2: %p\n\n", malloc(0x10));

	printf("You see by allocating and freeing heap chunks (just a little bit of heap grooming), we were able to accurately predict future chunks that will be allocated.\n");
	printf("This is just one small example of how we can use heap grooming to manipulate the heap to perform certain actions.\n");
}
```

When it runs:

```
$	./explanation_heap_grooming 
So today we will be discussing heap grooming.
The heap has a lot of behavior that is predictable.
Heap grooming is when we manipulate the heap in certain ways, so it performs certain actions.
That includes mapping additional pages to memory, and how it allocates certain chunks.

For performance purposes, malloc will reuse recently freed chunks if they fit the size.
Let's allocate some chunks!

Our chunks are:
ptr0: 0x55bd0a0ac670
ptr1: 0x55bd0a0ac690
ptr2: 0x55bd0a0ac6b0

Now let's free them.

Now that they have been freed, we will allocate three chunks of the same size.
Because of malloc's chunk reusage, we should get the same three chunks we freed back in the reverse order.
So we should get ptr2 first, then ptr1, and then finally ptr0.

ptr0: 0x55bd0a0ac6b0
ptr1: 0x55bd0a0ac690
ptr2: 0x55bd0a0ac670

You see by allocating and freeing heap chunks (just a little bit of heap grooming), we were able to accurately predict future chunks that will be allocated.
This is just one small example of how we can use heap grooming to manipulate the heap to perform certain actions.
```
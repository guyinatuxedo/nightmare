# Heap Exploitation

This module is literally just an explanation as to how various parts of the heap works. The heap is an area of memory used for dynamic allocation (meaning that it can allocate an amount of space that isn't known at compile time), usually through the use of things like malloc. The thing is malloc has a lot of functionality behind how it operates in order to efficiently do its job (both in terms of space and run time complexity). This gives us a large attack surface on malloc, how in certain situations we can leverage something such as a single null byte overflow into full blown remote code execution. However in order to carry out these attacks effectively, you will need to understand how certain parts of the heap work (it can get a bit more complicated than overwriting a saved return address of a stack). The purpose of this module is to explain some of those parts. Let's get to work. Let's get to work.

## Libc

The first thing I would like to say is that on linux all of the source code for standard functions like malloc and calloc is located in the libc. Across different libc versions the code for various functions change, including the code for malloc. That means that different libc's mallocs operate in different ways. For instance the same binary running with two different libc versions, can see different behavior in the heap. You'll see this come up a lot. When you are working on a heap challenge, make sure you are using the right libc file (assuming the heap challenge is libc dependent). You might need to use something like `LD_PRELOAD` to do this (which you can see how I tackle this in exploit).

## Malloc Chunk

When we call malloc, it returns a pointer to a chunk. Let's take a look at the memory allocation of the chunk for this code:

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(void)
{
    char *ptr;

    ptr = malloc(0x10);

    strcpy(ptr, "panda");
}
```

We can see the memory of the heap chunk here:

```
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555514b <main+22>        mov    rax, QWORD PTR [rbp-0x8]
   0x55555555514f <main+26>        mov    DWORD PTR [rax], 0x646e6170
   0x555555555155 <main+32>        mov    WORD PTR [rax+0x4], 0x61
 → 0x55555555515b <main+38>        nop    
   0x55555555515c <main+39>        leave  
   0x55555555515d <main+40>        ret    
   0x55555555515e                  xchg   ax, ax
   0x555555555160 <__libc_csu_init+0> push   r15
   0x555555555162 <__libc_csu_init+2> mov    r15, rdx
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "try", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555515b → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern panda
[+] Searching 'panda' in memory
[+] In '[heap]'(0x555555559000-0x55555557a000), permission=rw-
  0x555555559260 - 0x555555559265  →   "panda"
gef➤  x/4g 0x555555559250
0x555555559250:    0x0    0x21
0x555555559260:    0x61646e6170    0x0
```

So we can see here is our heap chunk. Every heap chunk has something called a heap header (I often call it heap metadata). On `x64` systems it's the previous `0x10` bytes from the start of the heap chunk, and on `x86` systems it's the previous `0x8` bytes. It contains two separate values, the previous chunk size, and the chunk size.

```
0x0:    0x00     - Previous Chunk Size
0x8:    0x21     - Chunk Size
0x10:     "pada"     - Content of chunk
```

The previous chunk size (if it is set, which it isn't in this case) designates the size of a previous chunk in the heap layout that has been freed. The heap size in this case is `0x21`, which differs from the size we requested. That's because the size we pass to malloc, is just the minimum amount of space we want to be able to store data in. Because of the heap header, `0x10` extra bytes is added on `x64` systems (extra `0x8` bytes is added on `x86`) systems. Also in some instances it will round a number up, so it can deal with it better with things like binning. For instance if you hand malloc a size of `0x7f`, it will return a size of `0x91`. It will round up the size `0x7f` to `0x80` so it can deal with it better. There is an extra `0x10` bytes for the heap header. Also the `0x1` from both the `0x91` and `0x21` come from the previous in use bit, which just signifies if the previous chunk is in use, and not freed.

Also the first three bits of the malloc size are flags which specify different things (part of the reason for rounding). If the bit is set, it means that whatever the flag specifies is true (and vice versa):

```
0x1:     Previous in Use     - Specifies that the chunk before it in memory is in use
0x2:    Is MMAPPED               - Specifies that the chunk was obtained with mmap()
0x4:     Non Main Arena         - Specifies that the chunk was obtained from outside of the main arena
```

We will talk about what some of this means later on.

## Binning

So when malloc frees a chunk, it will typically insert it into one of the bin lists (assuming it can't do something like consolidate it with the top chunk). Then with a later allocation, it will check the bins to see if there are any freed chunks that it could allocate to serve the request. The purpose of this is so it can reuse previous freed chunks, for performance improvements.

#### Fast Bins

The fast bin consists of 7 linked lists, which are typically referred to by their `idx`. On `x64` the sizes range from `0x20` - `0x80` by default. Each idx (which is an index to the fastbins specifying a linked list of the fast bin) is separated by size. So a chunk of size `0x20-0x2f` would fit into `idx` `0`, a chunk of size `0x30-0x3f` would fit into `idx` `1`, and so on and so forth.

```
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602030, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x602050, size=0x30, flags=PREV_INUSE)
Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602080, size=0x40, flags=PREV_INUSE)
Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x6020c0, size=0x50, flags=PREV_INUSE)
Fastbins[idx=4, size=0x50]  ←  Chunk(addr=0x602110, size=0x60, flags=PREV_INUSE)
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x602170, size=0x70, flags=PREV_INUSE)
Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x6021e0, size=0x80, flags=PREV_INUSE)
```

Not the actual structure of a fastbin is a linked list, where it points to the next chunk in the list (granted it points to the heap header of the next chunk):

```
gef➤  x/g 0x602010
0x602010: 0x602020
gef➤  x/4g 0x602020
0x602020: 0x0 0x21
0x602030: 0x0 0x0
```

Now the fast bin is called that, because allocating from the fast bin is typically one of the faster memory allocation methods malloc uses. Also chunks are inserted into the fast bin head first. This means that the fast bin is LIFO, meaning that the last chunk to go into a fast bin list is the first one out.

#### tcache

The tcache is sort of like the Fast Bins, however it has it's differences.

The tcache is a new type of binning mechanism introduced in libc version `2.26` (before that, you won't see the tcache). The tcache is specific to each thread, so each thread has its own tcache. The purpose of this is to speed up performance since malloc won't have to lock the bin in order to edit it. Also in versions of libc that have a tcache, the tcache is the first place that it will look to either allocate chunks from or place freed chunks (since it's faster).

An actual tcache list is stored like a Fast Bin where it is a linked list. Also like the Fast Bin, it is LIFO. However a tcache list can only hold `7` chunks at a time. If a chunk is freed that meets the size requirement of a tcache however it's list is full, then it is inserted into the next bin that meets its size requirements. Let's see this in action.

Here is our source code:
```
#include <stdlib.h>

void main(void)
{
  char *p0, *p1, *p2, *p3, *p4, *p5, *p6, *p7;

  p0 = malloc(0x10);
  p1 = malloc(0x10);
  p2 = malloc(0x10);
  p3 = malloc(0x10);
  p4 = malloc(0x10);
  p5 = malloc(0x10);
  p6 = malloc(0x10);
  p7 = malloc(0x10);

  malloc(10); // Here to avoid consolidation with Top Chunk

  free(p0);
  free(p1);
  free(p2);
  free(p3);
  free(p4);
  free(p5);
  free(p6);
  free(p7);
}
```

Here is the state of the heap after everything's been freed:
```
gef➤  heap bins
───────────────────── Tcachebins for arena 0x7ffff7faec40 ─────────────────────
Tcachebins[idx=0, size=0x10] count=7  ←  Chunk(addr=0x555555559320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559280, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7ffff7faec40 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x555555559340, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we can see that we allocated and freed 8 chunks of size `0x20` (`0x10` from size requested, and `0x10` from heap metadata). The first seven of these chunks ended up in the tcache, since the tcache has a list for those size. After that list was filled up with seven chunks, the eight chunk we tried to free ended up in the fast bin, since there is a list for its size.

Also just to emphasize that the `0x7` chunk limit is just per list of the tcache, not total chunks in the entire tcache bin, we can see here that the tcache holds `14` chunks across two separate bins:

```
gef➤  heap bins
─────────────────────────────────────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7faec40 ───────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x10] count=7  ←  Chunk(addr=0x555555559320, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559280, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=1, size=0x20] count=7  ←  Chunk(addr=0x555555559460, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559430, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559400, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555593d0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5555555593a0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559370, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x555555559340, size=0x30, flags=PREV_INUSE)
──────────────────────────────────────────────────────────────────────────────────── Fastbins for arena 0x7ffff7faec40 ────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────────────────────────────────────────────────────────────────────── Small Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────────────────────────────────────────── Large Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

There are a total of `64` tcache lists, with idx values ranging from `0-63`, for chunk sizes between `0x20-0x410`:
```
gef➤  heap bins
─────────────────────────────────────────────────────────────────────────────────── Tcachebins for arena 0x7ffff7faec40 ───────────────────────────────────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x10] count=1  ←  Chunk(addr=0x555555559260, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=1, size=0x20] count=1  ←  Chunk(addr=0x555555559280, size=0x30, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=1  ←  Chunk(addr=0x5555555592b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x40] count=1  ←  Chunk(addr=0x5555555592f0, size=0x50, flags=PREV_INUSE)
Tcachebins[idx=4, size=0x50] count=1  ←  Chunk(addr=0x555555559340, size=0x60, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x5555555593a0, size=0x70, flags=PREV_INUSE)
Tcachebins[idx=6, size=0x70] count=1  ←  Chunk(addr=0x555555559410, size=0x80, flags=PREV_INUSE)
Tcachebins[idx=7, size=0x80] count=1  ←  Chunk(addr=0x555555559490, size=0x90, flags=PREV_INUSE)
Tcachebins[idx=8, size=0x90] count=1  ←  Chunk(addr=0x555555559520, size=0xa0, flags=PREV_INUSE)
Tcachebins[idx=9, size=0xa0] count=1  ←  Chunk(addr=0x5555555595c0, size=0xb0, flags=PREV_INUSE)
Tcachebins[idx=10, size=0xb0] count=1  ←  Chunk(addr=0x555555559670, size=0xc0, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x555555559730, size=0xd0, flags=PREV_INUSE)
Tcachebins[idx=12, size=0xd0] count=1  ←  Chunk(addr=0x555555559800, size=0xe0, flags=PREV_INUSE)
Tcachebins[idx=13, size=0xe0] count=1  ←  Chunk(addr=0x5555555598e0, size=0xf0, flags=PREV_INUSE)
Tcachebins[idx=14, size=0xf0] count=1  ←  Chunk(addr=0x5555555599d0, size=0x100, flags=PREV_INUSE)
Tcachebins[idx=15, size=0x100] count=1  ←  Chunk(addr=0x555555559ad0, size=0x110, flags=PREV_INUSE)
Tcachebins[idx=16, size=0x110] count=1  ←  Chunk(addr=0x555555559be0, size=0x120, flags=PREV_INUSE)
Tcachebins[idx=17, size=0x120] count=1  ←  Chunk(addr=0x555555559d00, size=0x130, flags=PREV_INUSE)
Tcachebins[idx=18, size=0x130] count=1  ←  Chunk(addr=0x555555559e30, size=0x140, flags=PREV_INUSE)
Tcachebins[idx=19, size=0x140] count=1  ←  Chunk(addr=0x555555559f70, size=0x150, flags=PREV_INUSE)
Tcachebins[idx=20, size=0x150] count=1  ←  Chunk(addr=0x55555555a0c0, size=0x160, flags=PREV_INUSE)
Tcachebins[idx=21, size=0x160] count=1  ←  Chunk(addr=0x55555555a220, size=0x170, flags=PREV_INUSE)
Tcachebins[idx=22, size=0x170] count=1  ←  Chunk(addr=0x55555555a390, size=0x180, flags=PREV_INUSE)
Tcachebins[idx=23, size=0x180] count=1  ←  Chunk(addr=0x55555555a510, size=0x190, flags=PREV_INUSE)
Tcachebins[idx=24, size=0x190] count=1  ←  Chunk(addr=0x55555555a6a0, size=0x1a0, flags=PREV_INUSE)
Tcachebins[idx=25, size=0x1a0] count=1  ←  Chunk(addr=0x55555555a840, size=0x1b0, flags=PREV_INUSE)
Tcachebins[idx=26, size=0x1b0] count=1  ←  Chunk(addr=0x55555555a9f0, size=0x1c0, flags=PREV_INUSE)
Tcachebins[idx=27, size=0x1c0] count=1  ←  Chunk(addr=0x55555555abb0, size=0x1d0, flags=PREV_INUSE)
Tcachebins[idx=28, size=0x1d0] count=1  ←  Chunk(addr=0x55555555ad80, size=0x1e0, flags=PREV_INUSE)
Tcachebins[idx=29, size=0x1e0] count=1  ←  Chunk(addr=0x55555555af60, size=0x1f0, flags=PREV_INUSE)
Tcachebins[idx=30, size=0x1f0] count=1  ←  Chunk(addr=0x55555555b150, size=0x200, flags=PREV_INUSE)
Tcachebins[idx=31, size=0x200] count=1  ←  Chunk(addr=0x55555555b350, size=0x210, flags=PREV_INUSE)
Tcachebins[idx=32, size=0x210] count=1  ←  Chunk(addr=0x55555555b560, size=0x220, flags=PREV_INUSE)
Tcachebins[idx=33, size=0x220] count=1  ←  Chunk(addr=0x55555555b780, size=0x230, flags=PREV_INUSE)
Tcachebins[idx=34, size=0x230] count=1  ←  Chunk(addr=0x55555555b9b0, size=0x240, flags=PREV_INUSE)
Tcachebins[idx=35, size=0x240] count=1  ←  Chunk(addr=0x55555555bbf0, size=0x250, flags=PREV_INUSE)
Tcachebins[idx=36, size=0x250] count=1  ←  Chunk(addr=0x55555555be40, size=0x260, flags=PREV_INUSE)
Tcachebins[idx=37, size=0x260] count=1  ←  Chunk(addr=0x55555555c0a0, size=0x270, flags=PREV_INUSE)
Tcachebins[idx=38, size=0x270] count=1  ←  Chunk(addr=0x55555555c310, size=0x280, flags=PREV_INUSE)
Tcachebins[idx=39, size=0x280] count=1  ←  Chunk(addr=0x55555555c590, size=0x290, flags=PREV_INUSE)
Tcachebins[idx=40, size=0x290] count=1  ←  Chunk(addr=0x55555555c820, size=0x2a0, flags=PREV_INUSE)
Tcachebins[idx=41, size=0x2a0] count=1  ←  Chunk(addr=0x55555555cac0, size=0x2b0, flags=PREV_INUSE)
Tcachebins[idx=42, size=0x2b0] count=1  ←  Chunk(addr=0x55555555cd70, size=0x2c0, flags=PREV_INUSE)
Tcachebins[idx=43, size=0x2c0] count=1  ←  Chunk(addr=0x55555555d030, size=0x2d0, flags=PREV_INUSE)
Tcachebins[idx=44, size=0x2d0] count=1  ←  Chunk(addr=0x55555555d300, size=0x2e0, flags=PREV_INUSE)
Tcachebins[idx=45, size=0x2e0] count=1  ←  Chunk(addr=0x55555555d5e0, size=0x2f0, flags=PREV_INUSE)
Tcachebins[idx=46, size=0x2f0] count=1  ←  Chunk(addr=0x55555555d8d0, size=0x300, flags=PREV_INUSE)
Tcachebins[idx=47, size=0x300] count=1  ←  Chunk(addr=0x55555555dbd0, size=0x310, flags=PREV_INUSE)
Tcachebins[idx=48, size=0x310] count=1  ←  Chunk(addr=0x55555555dee0, size=0x320, flags=PREV_INUSE)
Tcachebins[idx=49, size=0x320] count=1  ←  Chunk(addr=0x55555555e200, size=0x330, flags=PREV_INUSE)
Tcachebins[idx=50, size=0x330] count=1  ←  Chunk(addr=0x55555555e530, size=0x340, flags=PREV_INUSE)
Tcachebins[idx=51, size=0x340] count=1  ←  Chunk(addr=0x55555555e870, size=0x350, flags=PREV_INUSE)
Tcachebins[idx=52, size=0x350] count=1  ←  Chunk(addr=0x55555555ebc0, size=0x360, flags=PREV_INUSE)
Tcachebins[idx=53, size=0x360] count=1  ←  Chunk(addr=0x55555555ef20, size=0x370, flags=PREV_INUSE)
Tcachebins[idx=54, size=0x370] count=1  ←  Chunk(addr=0x55555555f290, size=0x380, flags=PREV_INUSE)
Tcachebins[idx=55, size=0x380] count=1  ←  Chunk(addr=0x55555555f610, size=0x390, flags=PREV_INUSE)
Tcachebins[idx=56, size=0x390] count=1  ←  Chunk(addr=0x55555555f9a0, size=0x3a0, flags=PREV_INUSE)
Tcachebins[idx=57, size=0x3a0] count=1  ←  Chunk(addr=0x55555555fd40, size=0x3b0, flags=PREV_INUSE)
Tcachebins[idx=58, size=0x3b0] count=1  ←  Chunk(addr=0x5555555600f0, size=0x3c0, flags=PREV_INUSE)
Tcachebins[idx=59, size=0x3c0] count=1  ←  Chunk(addr=0x5555555604b0, size=0x3d0, flags=PREV_INUSE)
Tcachebins[idx=60, size=0x3d0] count=1  ←  Chunk(addr=0x555555560880, size=0x3e0, flags=PREV_INUSE)
Tcachebins[idx=61, size=0x3e0] count=1  ←  Chunk(addr=0x555555560c60, size=0x3f0, flags=PREV_INUSE)
Tcachebins[idx=62, size=0x3f0] count=1  ←  Chunk(addr=0x555555561050, size=0x400, flags=PREV_INUSE)
Tcachebins[idx=63, size=0x400] count=1  ←  Chunk(addr=0x555555561450, size=0x410, flags=PREV_INUSE)
──────────────────────────────────────────────────────────────────────────────────── Fastbins for arena 0x7ffff7faec40 ────────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena 'main_arena' ───────────────────────────────────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x555555561850, bk=0x555555561850
 →   Chunk(addr=0x555555561860, size=0x19b0, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────────────────────────────────────────────────────────────────────── Small Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────────────────────────────────────────────────── Large Bins for arena 'main_arena' ────────────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

If it clears anything up, I feel like the best simple analogy I've heard for the tcache is it's the fast bin with less checks (and can take in somewhat larger chunks).

#### Unsorted, Large and Small Bins

The Small Bin, Large Bin, and Unsorted Bin are tied more closely together in how they work than the other bins. The Unsorted, Large, and Small Bins all live together in the same array. Each of the bins has different indexes to this array:

```
0x00:         Not Used
0x01:         Unsorted Bin
0x02 - 0x3f:  Small Bin
0x40 - 0x7e:  Large Bin
```

There is one list for the Unsorted Bin, 62 for the Small Bin, and 63 for the Large Bin. let's talk about the unsorted bin first.


For chunks that are inserted into one of the bins, however isn't inserted into the fast bin or tcache, it will first be inserted into the Unsorted Bin. Chunks will remain there until they are sorted. This happens when another call is made to malloc. It will then check through the Unsorted Bin for any possible chunks that can meet the allocation. Also one thing that you will see in the unsorted bin, is it is capable of taking off a piece of a chunk to serve a request (it can also consolidate chunks together). Also when it checks the unsorted bin, it will check if there are chunks that belong in one of the small / large bin lists. If there are it will move those chunks to the appropriate bins.

Like the fast bin, the 62 lists of the Small Bin and 63 lists of the Large Bin are divided by size. The small bins on `x64` consists of chunk sizes under `0x400` (`1024` bytes), and on `x86` consists of chunk sizes under `0x200` (`512` bytes), and the large bin consists of values above those.

Let's take at this C code:
```
#include <stdlib.h>

void main(void)
{
  char *ptr, *p1;

  ptr = malloc(0x200);

  malloc(10); // Here to avoid consolidation with Top Chunk

  free(ptr);

  malloc(0x1000);
}
```

Let's see how the start of the heap before the `malloc(0x1000)`:

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x210, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

Now let's see it after the `malloc(0x1000)`:
```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] small_bins[32]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x210, flags=PREV_INUSE)
[+] Found 1 chunks in 1 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

We can see since the unsorted bin chunk could not serve the requested size of `0x1000`, it was sorted to its corresponding list of in the small bin at idx `4`. Let's see what happens when we change the value to a large bin size:

The new C code:
```
#include <stdlib.h>

void main(void)
{
  char *ptr, *p1;

  ptr = malloc(0x400);

  malloc(10); // Here to avoid consolidation with Top Chunk

  free(ptr);

  malloc(10000);
}
```

Before the `malloc(10000)`:
```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x410, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

After the `malloc(10000)`:
```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] large_bins[63]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x410, flags=PREV_INUSE)
[+] Found 1 chunks in 1 large non-empty bins.
```

As we can see, the heap chunk was moved into its corresponding bin the large bin at idx `63`. Now what if an unsorted bin chunk can serve a malloc request?

Let's change the C code to this:

```
#include <stdlib.h>

void main(void)
{
  char *ptr, *p1;

  ptr = malloc(0x400);

  malloc(10); // Here to avoid consolidation with Top Chunk

  free(ptr);

  malloc(0x200);
}
```

Before the `malloc(0x200)`:

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] unsorted_bins[0]: fw=0x602000, bk=0x602000
 →   Chunk(addr=0x602010, size=0x410, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

After the `malloc(0x200)`:

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] unsorted_bins[0]: fw=0x602210, bk=0x602210
 →   Chunk(addr=0x602220, size=0x200, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

We can see here that the `0x210` bytes for the chunk was taken off of the chunk in the unsorted bin, and that the chunk remained in the unsorted bin.

Now let's look at chunk itself of a chunk in either the Unsorted, Small, or Large Bins.

Small Bin Chunk:

```
gef➤  x/6g 0x602000
0x602000: 0x0 0x211
0x602010: 0x7ffff7dd1d78  0x7ffff7dd1d78
0x602020: 0x0 0x0
```

Large Bin Chunk:

```
gef➤  x/6g 0x602000
0x602000: 0x0 0x411
0x602010: 0x7ffff7dd1f68  0x7ffff7dd1f68
0x602020: 0x602000  0x602000
```

Unsorted Bin Chunk:

```
gef➤  x/6g 0x602210
0x602210: 0x0 0x201
0x602220: 0x7ffff7dd1b78  0x7ffff7dd1b78
0x602230: 0x0 0x0
```

We can see that each of the chunks have the traditional header of a previous chunk size, and a chunk size. In addition to that, we see that all three chunks have two pointers as the first thing in the content section. That is because the lists in the Unsorted, Small, and Large bins are all doubly linked lists. The first pointer is the `fwd` pointer, and the second pointer is the `bk` pointer. However we can see that the large chunk has two pointer immediately after that.

These are pointers to `fwd_nextsize` and `bk_nextsize`. This will point to the next chunk of a different size. Since chunks in the large bin are stored largest to smallest, the `fwd_nextsize` will point to the next smallest chunk, and the `bk_nexsize` will allow it to jump to the next largest jump. It's kind of like a skip list.

## Consolidation

Now one issue the heap may run into is fragmentation. This is when the heap has a lot of free space, however it is in tiny chunks all over the place. This can become a problem when malloc tries to allocate a large chunk of space since it could have the space, but since it is broken up into a lot of smaller pieces and not continuous it will have to use different memory for it, and effectively waste space.

Consolidation tries to fix this by merging adjacent freed chunks together, into larger freed chunks. That way it will have larger freed chunks which can support larger allocations, and hopefully combat fragmentation.

## Top Chunk

The Top Chunk is essentially a large heap chunk that holds currently unallocated data. Think of it as where freed data that isn't in one of the bin lists goes.

Let's say you call `malloc(0x10)`, and it's your first time calling `malloc` so the heap isn't set up. When `malloc` sets up the heap, it will request some space from the kernel that is much larger than `0x10` bytes. Allocating large chunks of memory from the kernel, and managing memory allocations from that memory is a lot more efficient than requesting memory from the kernel each time. The remainder from the `0x20` bytes from the request (`0x10` from requested size and `0x10` from heap metadata) will end up in the top chunk (top chunk is sometimes also called). So just to reiterate the top chunk holds unallocated data that isn't in the bin list.

Now malloc will try to allocate chunks from the bin lists before allocating them from the top chunk, since it's faster. However if there isn't a chunk in any of the bin lists that will satisfy it, it will pull from the Top Chunk. Let's see that in action with this C Code:

```
#include <stdlib.h>

void main(void)
{
  char *p0, *p1;

  p0 = malloc(0x10);
  p1 = malloc(0xf0);

  free(p1);
}
```

Now let's see the top chunk before the `malloc(0xf0)` call:
```
gef➤  x/20g 0x602020
0x602020: 0x0 0x20fe1
0x602030: 0x0 0x0
0x602040: 0x0 0x0
0x602050: 0x0 0x0
0x602060: 0x0 0x0
0x602070: 0x0 0x0
0x602080: 0x0 0x0
0x602090: 0x0 0x0
0x6020a0: 0x0 0x0
0x6020b0: 0x0 0x0
```

So we can see that it's size is `0x20fe1`. Right now there are no chunks in any of the bin lists, so there is a `0x20fe0` bytes of unallocated space left in the heap (the previous in use bit for the top chunk is always set). Now let's see what happens to the top chunk after the `malloc(0xf0)` call:

```
gef➤  x/40g 0x602020
0x602020: 0x0 0x101
0x602030: 0x0 0x0
0x602040: 0x0 0x0
0x602050: 0x0 0x0
0x602060: 0x0 0x0
0x602070: 0x0 0x0
0x602080: 0x0 0x0
0x602090: 0x0 0x0
0x6020a0: 0x0 0x0
0x6020b0: 0x0 0x0
0x6020c0: 0x0 0x0
0x6020d0: 0x0 0x0
0x6020e0: 0x0 0x0
0x6020f0: 0x0 0x0
0x602100: 0x0 0x0
0x602110: 0x0 0x0
0x602120: 0x0 0x20ee1
0x602130: 0x0 0x0
0x602140: 0x0 0x0
0x602150: 0x0 0x0
```

We can see that two things have happened to the top chunk. Firstly that it moved down to `0x602120` from `0x602020` to make room for the new allocation from itself. Secondly, we see that it's size was shrunk by `0x100`, because of the `0x100` byte allocation from it. Now let's see what happens to the top chunk after the `free(p1)` call:

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/40g 0x602020
0x602020: 0x0 0x20fe1
0x602030: 0x0 0x0
0x602040: 0x0 0x0
0x602050: 0x0 0x0
0x602060: 0x0 0x0
0x602070: 0x0 0x0
0x602080: 0x0 0x0
0x602090: 0x0 0x0
0x6020a0: 0x0 0x0
0x6020b0: 0x0 0x0
0x6020c0: 0x0 0x0
0x6020d0: 0x0 0x0
0x6020e0: 0x0 0x0
0x6020f0: 0x0 0x0
0x602100: 0x0 0x0
0x602110: 0x0 0x0
0x602120: 0x0 0x20ee1
0x602130: 0x0 0x0
0x602140: 0x0 0x0
0x602150: 0x0 0x0
```

We can see that the chunk did not end up in the unsorted bin. Instead in consolidated with the top chunk. This is because it was a freed chunk right next to the top chunk, with no allocated space in between. So it just merged it with the top chunk (granted it left it's old size value behind).

Keep in mind, depending on the version of malloc and if the chunk size is fast bin or tcache, this behavior doesn't always show itself.

#### Top Chunk Consolidation

Now a lot of heap attacks we will go through target a bin list. For that we need freed chunks in the bins lists. Consolidation with the top chunk can prevent that, so one thing you will see us do a lot of is allocated a small chunk in between our freed chunks and the top chunk, just to prevent that consolidation.

## Main Arena

One term you will probably hear in heap exploitation is `Main Arena`. This is essentially the data structure used for managing heap memory. It actually contains the head pointers for the bin lists, which we can see here:

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x7ffff7dd1b20
0x7ffff7dd1b20 <main_arena>:  0x0 0x602000
0x7ffff7dd1b30 <main_arena+16>: 0x0 0x0
0x7ffff7dd1b40 <main_arena+32>: 0x0 0x0
0x7ffff7dd1b50 <main_arena+48>: 0x0 0x0
0x7ffff7dd1b60 <main_arena+64>: 0x0 0x0
0x7ffff7dd1b70 <main_arena+80>: 0x0 0x602120
0x7ffff7dd1b80 <main_arena+96>: 0x0 0x7ffff7dd1b78
0x7ffff7dd1b90 <main_arena+112>:  0x7ffff7dd1b78  0x7ffff7dd1b88
0x7ffff7dd1ba0 <main_arena+128>:  0x7ffff7dd1b88  0x7ffff7dd1b98
0x7ffff7dd1bb0 <main_arena+144>:  0x7ffff7dd1b98  0x7ffff7dd1ba8
```

## Exploitation

As you can see, there is a good bit of functionality with the heap (although we haven't covered it all). A lot of this functionality is beneficial to attacking the code. Here is kind of an outlay of how these attacks can work from super high level. Also the man, the myth, the legend himself `noopnoop` was the one to show me this, and I think it's a pretty good way for explaining heap exploitation:

```
+--------------------+----------------------------+-----------------------+
|   Bug Used         |  Bin Attack                |   House               |
+--------------------+----------------------------+-----------------------+
|                    |  Fast Bin Attack           |   House of Spirit     |
|   Double Free      |  tcache attack             |   House of Lore       |
|   Heap Overflow    |  Unsorted Bin Attck        |   House of Force      |
|   Use After Free   |  Small / Large Bin Attck   |   House of Einherjar  |
|                    |  Unsafe Unlink             |   House of Orange     |
+--------------------+----------------------------+-----------------------+
```

First off we have an actual bug. This can be something like a Heap overflow, Use After Free (UAF), a double free, or other things. We leverage the bugs and a bit of heap grooming to edit a freed chunk in one of the bin lists. Then from being able to edit a freed chunk in one of the bin lists we can launch a bin attack (also I'm not 100% sure if Unsafe Unlink counts as a Bin Attack, but that's where I'm putting it).

The Houses are essentially different types of Heap Attacks that we can do in different situations, that do different things. A lot of them are built off of the bin attacks, and they can get more complicated than some of the typical bin attacks.

Also this goes without saying, but there are a lot more heap attacks then the ones listed. These are just the ones that I cover in this project at the moment.

## Debugging Heap

As we are exploiting the Heap, we may run into some issues along the way. This can come from some of the many checks that malloc does on to check for memory corruption, to not fully understanding a bit of heap functionality. For that, these are two things that really helped me.

#### Gef

So the `gef` gdb wrapper has this super cool command called `heap bins` (as you've already seen) that will go through and show you the contents of all of the bin lists. Having a command like this to see the status of all of the bin lists is invaluable while doing heap exploitation. I know you've seen several instances of this already, however here is one more:

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602050, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602030, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] Found 0 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

#### Source code

Another useful tool for debugging failed heap checks, is the libc source code itself. It is all open source so you can just download it and look in `malloc.c` yourself. For instance let's say you are failing this check and we see the wonderful output from `malloc_printerr`:

```
*** Error in `./try': malloc(): memory corruption (fast): 0x000000000067f010 ***
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f75bc6ae7e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x82651)[0x7f75bc6b9651]
/lib/x86_64-linux-gnu/libc.so.6(__libc_malloc+0x54)[0x7f75bc6bb184]
./try[0x4005ab]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f75bc657830]
./try[0x400499]
======= Memory map: ========
00400000-00401000 r-xp 00000000 08:01 793072                             /Hackery/pod/modules/heap/try
00600000-00601000 r--p 00000000 08:01 793072                             /Hackery/pod/modules/heap/try
00601000-00602000 rw-p 00001000 08:01 793072                             /Hackery/pod/modules/heap/try
0067f000-006a0000 rw-p 00000000 00:00 0                                  [heap]
7f75b8000000-7f75b8021000 rw-p 00000000 00:00 0
7f75b8021000-7f75bc000000 ---p 00000000 00:00 0
7f75bc421000-7f75bc437000 r-xp 00000000 08:01 397746                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f75bc437000-7f75bc636000 ---p 00016000 08:01 397746                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f75bc636000-7f75bc637000 rw-p 00015000 08:01 397746                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f75bc637000-7f75bc7f7000 r-xp 00000000 08:01 397708                     /lib/x86_64-linux-gnu/libc-2.23.so
7f75bc7f7000-7f75bc9f7000 ---p 001c0000 08:01 397708                     /lib/x86_64-linux-gnu/libc-2.23.so
7f75bc9f7000-7f75bc9fb000 r--p 001c0000 08:01 397708                     /lib/x86_64-linux-gnu/libc-2.23.so
7f75bc9fb000-7f75bc9fd000 rw-p 001c4000 08:01 397708                     /lib/x86_64-linux-gnu/libc-2.23.so
7f75bc9fd000-7f75bca01000 rw-p 00000000 00:00 0
7f75bca01000-7f75bca27000 r-xp 00000000 08:01 397680                     /lib/x86_64-linux-gnu/ld-2.23.so
7f75bcc08000-7f75bcc0b000 rw-p 00000000 00:00 0
7f75bcc25000-7f75bcc26000 rw-p 00000000 00:00 0
7f75bcc26000-7f75bcc27000 r--p 00025000 08:01 397680                     /lib/x86_64-linux-gnu/ld-2.23.so
7f75bcc27000-7f75bcc28000 rw-p 00026000 08:01 397680                     /lib/x86_64-linux-gnu/ld-2.23.so
7f75bcc28000-7f75bcc29000 rw-p 00000000 00:00 0
7ffeb806d000-7ffeb808e000 rw-p 00000000 00:00 0                          [stack]
7ffeb808f000-7ffeb8092000 r--p 00000000 00:00 0                          [vvar]
7ffeb8092000-7ffeb8094000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
Aborted (core dumped)
```

We can just grep through the source code of `malloc.c` for the string `memory corruption (fast)` to find the code for the check we are failing:

```
      if (victim != 0)
        {
          if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
            {
              errstr = "malloc(): memory corruption (fast)";
            errout:
              malloc_printerr (check_action, errstr, chunk2mem (victim), av);
              return NULL;
            }
          check_remalloced_chunk (av, victim, nb);
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

Here we can see the check that we failed. The check is being done on a chunk allocated from the fast bin. It is checking to see if the size of the chunk matches the list (`idx`) it is coming from, which it doesn't due to some memory corruption.

#### Linking

When you attempt to use `LD_PRELOAD` to have a binary use a specific libc file, you might find an issue if the linker is not compatible. If you run into that issue where you try to `LD_PRELOAD` a libc version that isn't compatible and you have gdb attached, you should see an error message from gdb like this:

```
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.2.91.20190405-git using Python engine 3.7
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./cookbook...
(No debugging symbols found in ./cookbook)
Attaching to program: /Hackery/pod/modules/house_of_force/bkp16_cookbook/cookbook, process 21763
Could not attach to process.  If your uid matches the uid of the target
process, check the setting of /proc/sys/kernel/yama/ptrace_scope, or try
again as the root user.  For more details, see /etc/sysctl.d/10-ptrace.conf
warning: process 21763 is a zombie - the process has already terminated
ptrace: Operation not permitted.
/Hackery/pod/modules/house_of_force/bkp16_cookbook/21763: No such file or directory.
gef➤  
```

There are several ways you can tackle this problem. You could just keep all of the linkers on hand, and just use them as you need to. What I currently do is run several different vms with different versions of Ubuntu. This is because different versions of Ubuntu ship with different linkers, and different linkers work with different libc versions. I find this to be less of a hassle. For all of the libc dependent challenges, in the writeup I put what version of Ubuntu I used, so if you want to take the same approach you can.

## Explanations

Now since the attacks can get a bit more complicated, one thing I will start including in all of the modules is a well documented C file explaining how this attack works. I find this to be helpful at times. I did not come up with this idea. I saw it in how2heap from the ctf team shellphish (https://github.com/shellphish/how2heap), and I thought having something like that would be super helpful for this project. I would recommend looking at it, it's a great resource.

## References

Here are some references I used while writing this. If you want to learn more, I would recommend looking at them:

```
https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/
http://core-analyzer.sourceforge.net/index_files/Page335.html
https://sourceware.org/glibc/wiki/MallocInternals
https://github.com/shellphish/how2heap
```

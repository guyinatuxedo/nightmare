# pwntools intro

Pwntools is a python ctf library designed for rapid exploit development. It essentially help us write exploits quickly, and has a lot of useful functionality behind it.

Also one thing to note, pwntools has Python2 and Python3 versions. Atm this course uses the Python2, but I have plans to switch it all over to Python3. Just keep in mind that some things change between Python2 to the Python3 versions, however the changes are relatively small.

## Installation

It's fairly simple process. The installation process is pretty much just using pip:

```
$    sudo pip install pwn
```

If you have any problems, google will help a lot.

## Using it

So this is going to be an explanation on how you do various things with pwntools. It will only cover a small bit of functionality.

If we want to import it into python:

```
from pwn import *
```

Now one thing that pwntools does for us, is it has some nice piping functionality which helps with IO. If we want to connect to the server at `github.com` (if you have an IP address, just swap out the dns name with the IP address) on port `9000` via tcp:

```
target = remote("github.com", 9000)
```

If you want to run a target binary:

```
target = process("./challenge")
```

If you want to attach the `gdb` debugger to a process:

```
gdb.attach(target)
```

If we want to attach the `gdb` debugger to a process, and also immediately pass a command to `gdb` to set a breakpoint at main:

```
gdb.attach(target, gdbscript='b *main')
```

Now for actual I/O. If we want to send the variable `x` to the `target` (target can be something like a process, or remote connection established by pwntools):

```
target.send(x)
```

If we wanted to send the variable `x` followed by a newline character appended to the end:

```
target.sendline(x)
```

If we wanted to print a single line of text from `target`:
```
print target.recvline()
```

If we wanted to print all text from `target` up to the string `out`:
```
print target.recvuntil("out")
```

Now one more thing, ELFs store data via least endian, meaning that data is stored with the least significant byte first. In a few situations where we are scanning in an integer, we will need to take this into account. Luckily pwntools will take care of this for us.

To pack the integer `y` as a least endian QWORD (commonly used for `x64`):

```
p64(x)
```

To pack the integer `y` as a least endian DWORD (commonly used for `x86`):
```
p32(x)
```

It can also unpack values we get. Let's say we wanted to unpack a least endian QWORD and get it's integer value:

```
u64(x)
```

To unpack a DWORD:

```
u32(x)
```

Lastly if just wanted to interact directly with `target`:

```
target.interactive()
```

This is only a small bit of the functionality pwntools has. You will see a lot more of the functionality later. If you want to see more of pwntools, it has some great docs: http://docs.pwntools.com/en/stable/

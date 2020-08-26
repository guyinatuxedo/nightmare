# gdb-gef

This file had contributed by `deveynull`

We already went through GDB, but now we are going to learn about GDB with debugging symbols.

A Debugging Symbol Table maps instructions in the compiled binary program to their corresponding variable, function, or line in the source code. This mapping could be something like:
* Program instruction ⇒ item name, item type, original file, line number defined.

Symbol tables may be embedded into the program or stored as a separate file. So if you plan to debug your program, then it is required to create a symbol table which will have the required information to debug the program.

We can infer the following facts about symbol tables:

* A symbol table works for a particular version of the program – if the program changes, a new table must be created.
* Debug builds are often larger and slower than retail (non-debug) builds; debug builds contain the symbol table and other ancillary information.
* If you wish to debug a binary program you did not compile yourself, you must get the symbol tables from the author.

This means that most of time we will only be using a debugger on code that we compiled ourselves. That means this is for writing better code and troubleshooting, and less for reverse-engineering.

For this section we will use a slightly modified version of the Hello World program you just wrote.

```
#include <stdio.h>

int main(void)
{
  char* greeting = "Hello, World!\n";
  printf("%s", greeting);
  return 0;
}
```

The primary difference here is that the words, "Hello, World", are now stored inside of a variable named greeting. Don't worry too much about the "%s" yet.

To turn on Debugging Symbols during compilation use the "-g" argument for GCC. 


```
$ gcc -g hello.c -o hello
$ ./hello 
Hello, World!
$ gdb ./hello 
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
Reading symbols from ./hello...done.

```

You will see above in the last line that symbols were read into GDB. Now let's play around to see what we can do with that.

First, we can use GDB's `list` or `l` command to list out the source code. We can even specify down further to print out a specific function or line number.

```
gef➤  l
1	#include <stdio.h>
2	
3	int main(void)
4	{
5	  char* greeting = "Hello, World!\n";
6	  printf("%s", greeting);
7	  return 0;
8	}
9	

gef➤  l main
1	#include <stdio.h>
2	
3	int main(void)
4	{
5	  char* greeting = "Hello, World!\n";
6	  printf("%s", greeting);
7	  return 0;
8	}
9	
gef➤  l 6
1	#include <stdio.h>
2	
3	int main(void)
4	{
5	  char* greeting = "Hello, World!\n";
6	  printf("%s", greeting);
7	  return 0;
8	}
9	
```


We can also now set breakpoints at specific line numbers in addition to at functions! This is super helpful when we are debugging our own code.

```
gef➤  b 6
Breakpoint 1 at 0x65d: file hello.c, line 6.

```

```
gef➤  run
Starting program: /home/devey/nightmare/modules/02-intro_tooling/gdb-gef/hello_world 
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0000555555554704  →  "Hello, World!\n"
$rbx   : 0x0               
$rcx   : 0x0000555555554680  →  <__libc_csu_init+0> push r15
$rdx   : 0x00007fffffffe028  →  0x00007fffffffe38c  →  "CLUTTER_IM_MODULE=xim"
$rsp   : 0x00007fffffffdf20  →  0x00007fffffffe010  →  0x0000000000000001
$rbp   : 0x00007fffffffdf30  →  0x0000555555554680  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffe018  →  0x00007fffffffe349  →  "/home/devey/nightmare/modules/02-intro_tooling/gdb[...]"
$rdi   : 0x1               
$rip   : 0x000055555555465d  →  <main+19> mov rax, QWORD PTR [rbp-0x8]
$r8    : 0x00007ffff7dd0d80  →  0x0000000000000000
$r9    : 0x00007ffff7dd0d80  →  0x0000000000000000
$r10   : 0x0               
$r11   : 0x0               
$r12   : 0x0000555555554540  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe010  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdf20│+0x0000: 0x00007fffffffe010  →  0x0000000000000001	 ← $rsp
0x00007fffffffdf28│+0x0008: 0x0000555555554704  →  "Hello, World!\n"
0x00007fffffffdf30│+0x0010: 0x0000555555554680  →  <__libc_csu_init+0> push r15	 ← $rbp
0x00007fffffffdf38│+0x0018: 0x00007ffff7a05b97  →  <__libc_start_main+231> mov edi, eax
0x00007fffffffdf40│+0x0020: 0x0000000000000001
0x00007fffffffdf48│+0x0028: 0x00007fffffffe018  →  0x00007fffffffe349  →  "/home/devey/nightmare/modules/02-intro_tooling/gdb[...]"
0x00007fffffffdf50│+0x0030: 0x0000000100008000
0x00007fffffffdf58│+0x0038: 0x000055555555464a  →  <main+0> push rbp
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555464e <main+4>         sub    rsp, 0x10
   0x555555554652 <main+8>         lea    rax, [rip+0xab]        # 0x555555554704
   0x555555554659 <main+15>        mov    QWORD PTR [rbp-0x8], rax
 → 0x55555555465d <main+19>        mov    rax, QWORD PTR [rbp-0x8]
   0x555555554661 <main+23>        mov    rsi, rax
   0x555555554664 <main+26>        lea    rdi, [rip+0xa8]        # 0x555555554713
   0x55555555466b <main+33>        mov    eax, 0x0
   0x555555554670 <main+38>        call   0x555555554520 <printf@plt>
   0x555555554675 <main+43>        mov    eax, 0x0
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── source:hello.c+6 ────
      1	 #include <stdio.h>
      2	 
      3	 int main(void)
      4	 {
      5	   char* greeting = "Hello, World!\n";
           // greeting=0x00007fffffffdf28  →  [...]  →  "Hello, World!\n"
 →    6	   printf("%s", greeting);
      7	   return 0;
      8	 }
      9	 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hello_world", stopped 0x55555555465d in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555465d → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, main () at hello.c:6
6	  printf("%s", greeting);
```


As you can see, now it shows you the code of the line you are breaking on, which is super helpful. 

Using what you remember from the last section without symbols, lets figure out how to print the value of the string stored in greeting. 


```
gef➤  x/s $rax
0x555555554704:	"Hello, World!\n"
gef➤  p $rax
$1 = 0x555555554704
gef➤  x/s $1
0x555555554704:	"Hello, World!\n"
gef➤  x/s 0x555555554704
0x555555554704:	"Hello, World!\n"

```

All of those work fine, but we can also just print the variable name directly!

Like this:
```
gef➤  p greeting
$2 = 0x555555554704 "Hello, World!\n"
```
Or like this:
```
gef➤  x/s greeting
0x555555554704:	"Hello, World!\n"
```

Alright, there is plenty other things you can do, but this should help you to troubleshoot effectively as you write your C.


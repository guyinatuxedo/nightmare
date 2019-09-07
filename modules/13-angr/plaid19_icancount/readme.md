# Plaid CTF 2019

Let's take a look at the binary:
```
$    file icancount
icancount: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=e75719f2cd90c042f04af29a0cd1263bb72c7417, not stripped
$    pwn checksec icancount
[*] '/Hackery/pod/modules/angr/plaid19_icancount/icancount'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./icancount
We're going to count numbers, starting from one and
counting all the way up to the flag!
Are you ready? Go!
> 15935728
No, the correct number is 1.
But I believe in you. Let's try again sometime!
$    ./icancount
We're going to count numbers, starting from one and
counting all the way up to the flag!
Are you ready? Go!
> 1
Correct.
> 2
Yes.
> 3
Yes!
> 4
Congratz
> 5
Yep!
> 6
Right-o.
> 7
Wonderful.
> 8^C
```

So we can see that we are dealing with a `32` bit binary with `PIE`. When we run it, it prompts us for numbers that increments by `1`. When we take a look at the main function in Ghidra, we see this:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void main(void)

{
  uint __seed;
  size_t len;
  size_t sVar1;
  int iVar2;
  char *compliment;
  char input [31];
 
  __seed = time((time_t *)0x0);
  srand(__seed);
  puts("We\'re going to count numbers, starting from one and");
  puts("counting all the way up to the flag!");
  puts("Are you ready? Go!");
  while( true ) {
    incr_flag();
    printf("> ");
    fflush(stdout);
    fgets(input + 1,0x1e,stdin);
    if (input[1] != '\0') {
      len = strlen(input + 1);
      if (input[len] < ' ') {
        sVar1 = strlen(input + 1);
        input[sVar1] = '\0';
      }
    }
    iVar2 = strcmp(input + 1,flag_buf);
    if (iVar2 != 0) break;
    compliment = (char *)get_compliment();
    puts(compliment);
    check_flag();
  }
  printf("No, the correct number is %s.\n",flag_buf);
  puts("But I believe in you. Let\'s try again sometime!");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

So we can see that it prints out some text, sets the rng seed to time, then drops us into an infinite loop. The loop starts off by running the `incr_flag` function which we can see it increments `flag_buf` which is stored in the bss at address `0x13048`:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void incr_flag(void)

{
  size_t sVar1;
  size_t local_10;
 
  local_10 = strlen(flag_buf);
  while( true ) {
    if ((int)local_10 < 1) {
      sVar1 = strlen(flag_buf);
      if (sVar1 != 0x13) {
        sVar1 = strlen(flag_buf);
        flag_buf[sVar1] = 0x30;
        flag_buf[0] = 0x31;
        return;
      }
                    /* WARNING: Subroutine does not return */
      exit(2);
    }
    if (*(char *)((int)&__dso_handle + local_10 + 3) != '9') break;
    *(undefined *)((int)&__dso_handle + local_10 + 3) = 0x30;
    local_10 = local_10 - 1;
  }
  *(char *)((int)&__dso_handle + local_10 + 3) =
       *(char *)((int)&__dso_handle + local_10 + 3) + '\x01';
  return;
}
```

A couple of things from this, first if we weren't sure before we can see that flag_bug is only filled with the bytes between 0x30-0x39 (ASCII `0-9`). In addition to that, since if the length of flag_buf exceeds 19 (`0x13`) the program exits, our input is probably 19 characters long (and only consists of ASCII characters between `0-9`).

Proceeding that in the main function, we see that it allows us to scan in 0x1e bytes into the stack char array `input`. It then checks if the last character in our inputted string has a value less than `0x20` (which corresponds to the space `' '` character). If it does, then that character is swapped out with a null byte.

Following that, it compares our input against `flag_buf`. If they are not equal, the infinite loop breaks and we get told what the correct number should be. If it doesn't break, then it will print a random character and run the `check_flag` function which looks like this:

```
void check_flag(void)

{
  longlong lVar1;
  uint b;
  uint x;
  uint y;
  uint z;
  uint uVar2;
  int unaff_ESI;
  ulonglong a;
  ulonglong c;
  ulonglong d;
  ulonglong uVar3;
  ulonglong uVar4;
  ulonglong e;
  ulonglong g;
  ulonglong uVar5;
  longlong f;
  int i;
  char inputChar;
 
  __x86.get_pc_thunk.si();
  i = 0;
  while( true ) {
    if (0x13 < i) {
      printf((char *)(unaff_ESI + 0x93c),unaff_ESI + 0x25f2);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    inputChar = *(char *)(i + unaff_ESI + 0x25f2);
    x = (int)inputChar & 3;
    y = (int)(inputChar >> 2) & 3;
    z = (int)(inputChar >> 4) & 0xf;
    a = rol(x + 0xa55aa559,(uint)(0x5aa55aa6 < x) + 0xa55a,2);
    b = y - (uint)a;
    c = rol(b + 0xa55aa559,
            (-(uint)(y < (uint)a) - (int)(a >> 0x20)) + 0xa55a + (uint)(0x5aa55aa6 < b),0xd);
    c._4_4_ = (uint)(c >> 0x20);
    c._0_4_ = (uint)c;
    d = rol((z - (uint)c) + 0xa55aa559,
            (-(uint)(z < (uint)c) - c._4_4_) + 0xa55a + (uint)(0x5aa55aa6 < z - (uint)c),0x11);
    d._4_4_ = (uint)(d >> 0x20);
    uVar5 = c ^ a ^ d;
    lVar1 = a + CONCAT44((uint)((d & uVar5) >> 0x20) | ~(uint)(uVar5 >> 0x20) & c._4_4_,
                         (uint)(d & uVar5) | ~(uint)uVar5 & (uint)c);
    c._0_4_ = (uint)lVar1;
    c._4_4_ = z + (uint)c;
    uVar3 = rol(c._4_4_ + 0xf01f83c6,
                (int)((ulonglong)lVar1 >> 0x20) + (uint)CARRY4(z,(uint)c) + 0xf +
                (uint)(0xfe07c39 < c._4_4_),3);
    uVar2 = (uint)(uVar3 >> 0x20);
    lVar1 = c + CONCAT44((uint)((uVar3 & uVar5) >> 0x20) | ~uVar2 & d._4_4_,
                         (uint)(uVar3 & uVar5) | ~(uint)uVar3 & (uint)d);
    c._0_4_ = (uint)lVar1;
    c._4_4_ = x + (uint)c;
    uVar4 = rol(c._4_4_ + 0xf01f83c6,
                (int)((ulonglong)lVar1 >> 0x20) + (uint)CARRY4(x,(uint)c) + 0xf +
                (uint)(0xfe07c39 < c._4_4_),0xb);
    lVar1 = uVar5 + CONCAT44((uint)((d & uVar4) >> 0x20) | ~d._4_4_ & uVar2,
                             (uint)(d & uVar4) | ~(uint)d & (uint)uVar3);
    c._0_4_ = (uint)lVar1;
    c._4_4_ = y + (uint)c;
    e = rol(c._4_4_ + 0xf01f83c6,
            (int)((ulonglong)lVar1 >> 0x20) + (uint)CARRY4(y,(uint)c) + 0xf +
            (uint)(0xfe07c39 < c._4_4_),0x13);
    lVar1 = uVar3 + (e ^ d ^ uVar4);
    c._0_4_ = (uint)lVar1;
    c._4_4_ = y + (uint)c;
    g = rol(c._4_4_ + 0x867b8ca6,
            (int)((ulonglong)lVar1 >> 0x20) + (uint)CARRY4(y,(uint)c) + 0xb744 +
            (uint)(0x79847359 < c._4_4_),5);
    lVar1 = d + (uVar4 ^ g ^ e);
    c._0_4_ = (uint)lVar1;
    c._4_4_ = x + (uint)c;
    uVar5 = rol(c._4_4_ + 0x867b8ca6,
                (int)((ulonglong)lVar1 >> 0x20) + (uint)CARRY4(x,(uint)c) + 0xb744 +
                (uint)(0x79847359 < c._4_4_),7);
    lVar1 = e + (uVar5 ^ uVar4 ^ g);
    c._0_4_ = (uint)lVar1;
    c._4_4_ = z + (uint)c;
    f = rol(c._4_4_ + 0x867b8ca6,
            (int)((ulonglong)lVar1 >> 0x20) + (uint)CARRY4(z,(uint)c) + 0xb744 +
            (uint)(0x79847359 < c._4_4_),0x17);
    lVar1 = uVar4 + uVar5 + g + f;
    c._0_4_ = (uint)lVar1 ^ (uint)((ulonglong)lVar1 >> 0x20);
    c._0_4_ = (uint)c ^ (uint)c >> 0x10;
    if (*(byte *)(i + *(int *)(unaff_ESI + 0x2692)) != (byte)((byte)(uint)c ^ (byte)((uint)c >> 8)))
    break;
    i = i + 1;
  }
  return;
}
```

This may seem like a mess, but we don't need to understand a lot about what's going on. We can see that the loop runs for `0x13` times (iteration count stored in `i`). If it runs that many times then it will call `printf` (probably will print the flag). Also we can see that it checks our input which is stored in `inputChar` at `0x10a73`:

```
gef➤  pie b *0xa73
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)
We're going to count numbers, starting from one and
counting all the way up to the flag!
Are you ready? Go!
> 1
Congratz

Breakpoint 1, 0x56555a73 in check_flag ()
[+] base address 0x56555000
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0x56558048  →  0x00000031 ("1"?)
$ebx   : 0x56558000  →  0x00002ef0
$ecx   : 0x56559160  →  "Congratz\neady? Go!\ny up to the flag!\ng from one[...]"
$edx   : 0x56558048  →  0x00000031 ("1"?)
$esp   : 0xffffcf20  →  0x00000000
$ebp   : 0xffffd028  →  0xffffd058  →  0x00000000
$esi   : 0x56558000  →  0x00002ef0
$edi   : 0x0       
$eip   : 0x56555a73  →  <check_flag+46> movzx eax, BYTE PTR [eax]
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffcf20│+0x0000: 0x00000000     ← $esp
0xffffcf24│+0x0004: 0x00000009
0xffffcf28│+0x0008: 0x56559160  →  "Congratz\neady? Go!\ny up to the flag!\ng from one[...]"
0xffffcf2c│+0x000c: 0xf7e48dab  →  <_IO_file_write+43> add esp, 0x10
0xffffcf30│+0x0010: 0x00000001
0xffffcf34│+0x0014: 0x56559160  →  "Congratz\neady? Go!\ny up to the flag!\ng from one[...]"
0xffffcf38│+0x0018: 0x00000009
0xffffcf3c│+0x001c: 0xf7ffd000  →  0x00026f34
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0x56555a68 <check_flag+35>  lea    edx, [esi+0x48]
   0x56555a6e <check_flag+41>  mov    eax, DWORD PTR [ebp-0x1c]
   0x56555a71 <check_flag+44>  add    eax, edx
 → 0x56555a73 <check_flag+46>  movzx  eax, BYTE PTR [eax]
   0x56555a76 <check_flag+49>  mov    BYTE PTR [ebp-0x1d], al
   0x56555a79 <check_flag+52>  movsx  eax, BYTE PTR [ebp-0x1d]
   0x56555a7d <check_flag+56>  cdq    
   0x56555a7e <check_flag+57>  mov    ecx, eax
   0x56555a80 <check_flag+59>  and    ecx, 0x3
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "icancount", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x56555a73 → check_flag()
[#1] 0x56556109 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0x31      
$ebx   : 0x56558000  →  0x00002ef0
$ecx   : 0x56559160  →  "Congratz\neady? Go!\ny up to the flag!\ng from one[...]"
$edx   : 0x56558048  →  0x00000031 ("1"?)
$esp   : 0xffffcf20  →  0x00000000
$ebp   : 0xffffd028  →  0xffffd058  →  0x00000000
$esi   : 0x56558000  →  0x00002ef0
$edi   : 0x0       
$eip   : 0x56555a76  →  <check_flag+49> mov BYTE PTR [ebp-0x1d], al
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffcf20│+0x0000: 0x00000000     ← $esp
0xffffcf24│+0x0004: 0x00000009
0xffffcf28│+0x0008: 0x56559160  →  "Congratz\neady? Go!\ny up to the flag!\ng from one[...]"
0xffffcf2c│+0x000c: 0xf7e48dab  →  <_IO_file_write+43> add esp, 0x10
0xffffcf30│+0x0010: 0x00000001
0xffffcf34│+0x0014: 0x56559160  →  "Congratz\neady? Go!\ny up to the flag!\ng from one[...]"
0xffffcf38│+0x0018: 0x00000009
0xffffcf3c│+0x001c: 0xf7ffd000  →  0x00026f34
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0x56555a67 <check_flag+34>  add    BYTE PTR [ebp+0x4896], cl
   0x56555a6d <check_flag+40>  add    BYTE PTR [ebx-0x2ffe1bbb], cl
   0x56555a73 <check_flag+46>  movzx  eax, BYTE PTR [eax]
 → 0x56555a76 <check_flag+49>  mov    BYTE PTR [ebp-0x1d], al
   0x56555a79 <check_flag+52>  movsx  eax, BYTE PTR [ebp-0x1d]
   0x56555a7d <check_flag+56>  cdq    
   0x56555a7e <check_flag+57>  mov    ecx, eax
   0x56555a80 <check_flag+59>  and    ecx, 0x3
   0x56555a83 <check_flag+62>  mov    DWORD PTR [ebp-0x28], ecx
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "icancount", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x56555a76 → check_flag()
[#1] 0x56556109 → main()
────────────────────────────────────────────────────────────────────────────────
0x56555a76 in check_flag ()
gef➤  p $eax
$1 = 0x31
```

There is an if then check at the end which is ran at the very end, if the check fails the loop ends (which means we don't have the correct input):
```
    if (*(byte *)(i + *(int *)(unaff_ESI + 0x2692)) != (byte)((byte)(uint)c ^ (byte)((uint)c >> 8)))
    break;
```

So to solve this challenge, we can use Angr. We need three things, what input it takes (which we know), an instruction pointer that if it's executed the problem is solved, and an instruction pointer that if it's executed then we know we have the wrong input.

For the address that designates a failed address, in the `check_flag` function we see at the end there is the if then check, which if it fails it will make a jump to `0x10fae`:

```
        00010f75 38 c2           CMP        f,f
        00010f77 75 35           JNZ        LAB_00010fae
```

Which we can see that at the address it just exits. Since this code path is executed when we don't have the right input, I choose to use the address `0xfae`:

```
                             LAB_00010fae                                    XREF[1]:     00010f77(j)  
        00010fae 90              NOP
        00010faf 8d 65 f4        LEA        ESP=>local_10,[EBP + -0xc]
        00010fb2 5b              POP        EBX
        00010fb3 5e              POP        ESI
        00010fb4 5f              POP        EDI
        00010fb5 5d              POP        EBP
        00010fb6 c3              RET
```

Now we need the instruction address that if it's executed, it means we have the correct input. For this I choose `0xf9a` since that is the `printf` call that has been made if the loop has ran `19` times, and it probably is printing the flag (which means that this code path is ran when we have the correct input):

```
        00010f98 89 f3           MOV        EBX,ESI
        00010f9a e8 b1 f6        CALL       printf                                           int printf(char * __format, ...)
                 ff ff
        00010f9f 83 c4 10        ADD        ESP,0x10
        00010fa2 83 ec 0c        SUB        ESP,0xc
        00010fa5 6a 00           PUSH       0x0
        00010fa7 89 f3           MOV        EBX,ESI
        00010fa9 e8 f2 f6        CALL       exit                                             void exit(int __status)
                 ff ff
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```

Also one last thing about the Angr script. We will set the enter state to be the start of the `check_flag` function. The reason for this being is if we were to start from the beginning of the binary, we would have to essentially brute force the binary because it checks if our input is equal to `flag_buf`, and it is initialized at `0` and incremented by `1` each time (so we would have to brute force it by entering `0`, then `1`, then `2` ...). Also since it expects our input in `flag_buf`, we will just establish our input and set `flag_buf` equal to our input. With that we have everything we need for our Angr Script:

```
import angr
import claripy

# Establish the project

target = angr.Project('icancount', auto_load_libs=False)

# Because PIE is enabled, we have to grab the randomized addresses for various things

# Grab the address of flag_buf which stores our input
flag_buf = target.loader.find_symbol('flag_buf').rebased_addr

# Grab the address of the check_flag function which is where we will start
check_flag = target.loader.find_symbol('check_flag').rebased_addr

# Grab the instruction addresses which indicate either a success or a failure

desired_adr = 0xf9a + target.loader.main_object.min_addr
failed_adr = 0xfae + target.loader.main_object.min_addr

# Establish the entry state
entry_state = target.factory.blank_state(addr = check_flag)

# Establish our input, 0x13 bytes
inp = claripy.BVS('inp', 0x13*8)

# Assign the condition that each byte of our input must be between `0-9` (0x30 - 0x39)
for i in inp.chop(8):
    entry_state.solver.add(entry_state.solver.And(i >= '0', i <= '9'))

# Set the memory region of flag_buf equal to our input
entry_state.memory.store(flag_buf, inp)

# Establish the simulation
simulation = target.factory.simulation_manager(entry_state)

# Setup the simulation with the addresses to specify a success / failure
simulation.use_technique(angr.exploration_techniques.Explorer(find = desired_adr, avoid = failed_adr))

# Run the simulation
simulation.run()

# Parse out the solution, and print it
flag_int = simulation.found[0].solver.eval(inp)

flag = ""
for i in xrange(19):
    flag = chr(flag_int & 0xff) + flag
    flag_int = flag_int >> 8

print "flag: PCTF{" + flag + "}"
```

When we run it:
```
$	python rev.py 
WARNING | 2019-07-21 16:19:08,277 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
WARNING | 2019-07-21 16:19:08,324 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
flag: PCTF{2052419606511006177}
```

Just like that, we captured the flag!


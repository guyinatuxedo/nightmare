# defcamp 2015 quals r100

Let's take a look at the binary:

```
$    file r100
r100: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.24, BuildID[sha1]=0f464824cc8ee321ef9a80a799c70b1b6aec8168, stripped
$    pwn checksec r100
[*] '/Hackery/pod/modules/angr/defcamp_r100/r100'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./r100
Enter the password: 15935728
Incorrect password!
```

So we can see we are dealing with a `64` bit binary, that when we run it, it prompts us for input via `stdin`. When we take a look at the binary in Ghidra, we see this function at `0x4007e8`:

```
undefined8 promptPassword(void)

{
  long lVar1;
  int check;
  char *bytesRead;
  undefined8 passedCheck;
  long in_FS_OFFSET;
  char input [264];
  long canary;
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter the password: ");
  bytesRead = fgets(input,0xff,stdin);
  if (bytesRead == (char *)0x0) {
    passedCheck = 0;
  }
  else {
    check = checkInput(input);
    if (check == 0) {
      puts("Nice!");
      passedCheck = 0;
    }
    else {
      puts("Incorrect password!");
      passedCheck = 1;
    }
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return passedCheck;
}
```

So we can see it first calls `printf` to prompt us for a password. It will then scan in at most `0xff` bytes into `input`. Provided that the `fgets` call actually scanned any bytes in, it will run `input` through the `checkInput` function. If it returns `0` then we solved the challenge. Looking at the `checkInput` function we see this:

```
undefined8 checkInput(long input)

{
  int i;
  long local_28 [4];
 
  i = 0;
  while( true ) {
    if (0xb < i) {
      return 0;
    }
    if ((int)*(char *)((long)((i / 3) * 2) + local_28[(long)(i % 3)]) -
        (int)*(char *)(input + (long)i) != 1) break;
    i = i + 1;
  }
  return 1;
}
```

So we can see here, the code enters into a `while (true)` loop. Each iteration it will take our input and evaluates it. If it passes the check, it will then move on to the next iteration. If there are more than `0xc` iterations of the loop, the function will return `0` meaning that we solved the challenge. If it fails one of the iteration checks, it will return `1` meaning that our input isn't valid.

So we are dealing with a crackme which is a challenge that scans in a piece of data, and evaluates it, and we need to figure out what that data is. We will use Angr to solve this. For Angr we need to know three things. The first is what input we have control over (here it is `0xff` bytes or less via stdin). The second is an instruction address that if it is executed, that means our input was successful (in other words an instruction address along the code path we want to hit). For this I choose `0x4007a1` in `checkInput` where it sets `EAX` (the return value) equal to `0x0`:

```
                             LAB_0040079b                                    XREF[1]:     0040072b(j)  
        0040079b 83 7d dc 0b     CMP        dword ptr [RBP + i],0xb
        0040079f 7e 8c           JLE        LAB_0040072d
        004007a1 b8 00 00        MOV        EAX,0x0
                 00 00
```

That instruction address should only be called when we have the correct input, so it is a good candidate. Now the last piece we need is an instruction address that when it is called, means that our input is not correct. For this I choose `0x400790` which is along the code path if the if then check in `checkInput` fails (specifically when it moves `1` into `EAX` so the return value specifies a failure):

```
        0040078b 83 f8 01        CMP        EAX,0x1
        0040078e 74 07           JZ         LAB_00400797
        00400790 b8 01 00        MOV        EAX,0x1
                 00 00
```

With that, we have everything that we need to make our Angr script:

```
# Import Angr
import angr

# Establish the Angr Project
target = angr.Project('r100')

# Specify the desired address which means we have the correct input
desired_adr = 0x4007a1

# Specify the address which if it executes means we don't have the correct input
wrong_adr = 0x400790

# Establish the entry state
entry_state = target.factory.entry_state(args=["./fairlight"])

# Establish the simulation
simulation = target.factory.simulation_manager(entry_state)

# Start the simulation
simulation.explore(find = desired_adr, avoid = wrong_adr)

solution = simulation.found[0].posix.dumps(0)
print solution
```

When we run it:
```
$    python rev.py
WARNING | 2019-07-21 18:55:53,628 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
Code_Talkers�������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������
$    ./r100
Enter the password: Code_Talkers
Nice!
```

Just like that, we solved the challenge!

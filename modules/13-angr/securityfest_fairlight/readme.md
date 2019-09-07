# Securityfest 2019 fairlight

Let's take a look at the binary:

```
$    file fairlight
fairlight: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.24, BuildID[sha1]=382cac0a89b47b48f6e24cdad066e1ac605bd3e5, not stripped
$    ./fairlight
useage: ./keygen code
$    ./fairlight 15935728
NOPE - ACCESS DENIED!
```

So we can see that we are dealing with a `64` bit binary. When we run it, we see that it takes in input through an argument. It appears to be a crackme that scans in input, evaluates it, and if it's write we get the flag. When we take a look at the `main` function in Ghidra, we see this:

```
undefined8 main(int argc,long argv)

{
  size_t inputLen;
  long lVar1;
  undefined8 *puVar2;
  long in_FS_OFFSET;
  undefined8 victory;
  undefined8 local_1b0 [50];
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  victory = 0;
  lVar1 = 0x31;
  puVar2 = local_1b0;
  while (lVar1 != 0) {
    lVar1 = lVar1 + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  if (argc < 2) {
    puts("useage: ./keygen code");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  inputLen = strlen(*(char **)(argv + 8));
  if (inputLen != 0xe) {
    denied_access();
  }
  strncpy(code,*(char **)(argv + 8),0x28);
  check_0();
  check_1();
  check_2();
  check_3();
  check_4();
  check_5();
  check_6();
  check_7();
  check_8();
  check_9();
  check_10();
  check_11();
  check_12();
  check_13();
  sprintf((char *)&victory,success,code);
  printf("%s",&victory);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So we can see that it only takes a single argument (other than the binary's name). It then checks if the length of our input is `0xe` characters (if not it runs `denied_access`). Proceeding that it copies our input to the bss variable `code` located at `0x6030b8`. After that it runs a series of `check` functions that reference our input stored in `code`, to evaluate it to see if it is correct.

So there are two ways I can see us solve this (although there are more). The first is that we go through and reverse all of the `check` functions to see what it actually expects (would probably use Z3 to help with this). The second is we just throw Angr at it. Angr is a binary analysis framework that can do a lot (such as code flow analysis and symbolic execution). We can use it as a symbolic execution engine (which figures out what inputs will execute what parts of the program) to figure out how to solve this challenge.

To use Angr here, we will need three things. The first is what input we have, and how it gets passed to the binary. This we already know, which is `0xe` (`14`) byte char characters passed in as a single argument. The second is the instruction address that we want Angr to reach. While it performs its analysis, it's goal will be to reach this function. For this I chose the `printf("%s",&victory);` call `0x401a6e` since if we hit that code path, it means we passed the check:

```
        00401a6e b8 00 00        MOV        inputLen,0x0
                 00 00
        00401a73 e8 88 eb        CALL       printf                                           int printf(char * __format, ...)
                 ff ff
        00401a78 b8 00 00        MOV        inputLen,0x0
                 00 00
```

Moving on, the last thing we need is an instruction address that if it is executed, then Angr knows that it's input isn't correct. For this, we can see that in all of the `check` functions if the check isn't passed it runs the `denied_access` function:

```
void check_0(void)

{
  rand();
  rand();
  if ((int)code[0] * ((int)code[11] + (int)(char)(code[9] ^ code[5])) + -0xab8 != (int)code[13]) {
    denied_access();
  }
  return;
}
```

So for this address I choose the start of `denied_access` at `0x40074d`. This instruction is part of the code path that is executed when our input is incorrect, so this address would be a good candidate to use:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined denied_access()
             undefined         AL:1           <RETURN>
                             denied_access                                   XREF[17]:    check_0:004008a6(c),
                                                                                          check_1:004009e2(c),
                                                                                          check_2:00400b1f(c),
                                                                                          check_3:00400c5c(c),
                                                                                          check_4:00400d96(c),
                                                                                          check_5:00400ed0(c),
                                                                                          check_6:0040100d(c),
                                                                                          check_7:00401147(c),
                                                                                          check_8:00401284(c),
                                                                                          check_9:004013be(c),
                                                                                          check_10:004014fb(c),
                                                                                          check_11:00401650(c),
                                                                                          check_12:004017a7(c),
                                                                                          check_13:004018fe(c),
                                                                                          main:00401990(c), 00401b60,
                                                                                          00401c68(*)  
        0040074d 55              PUSH       RBP
        0040074e 48 89 e5        MOV        RBP,RSP
        00400751 be a0 30        MOV        ESI=>failure,failure                             = "NOPE - ACCESS DENIED!\n"
                 60 00
```

You can install Angr with pip:
```
$    sudo pip install angr
```

With that we have everything we need to write the Angr Script:

```
# Import angr and claripy
import angr
import claripy

# Establish the angr
target = angr.Project('./fairlight', load_options={"auto_load_libs": False})

# Establish our input as an array of 0xe bytes
inp = claripy.BVS("inp", 0xe*8)

# Establish the entry state, with our input passed in as an argument
entry_state = target.factory.entry_state(args=["./fairlight", inp])

# Establish the simulation with the entry state
simulation = target.factory.simulation_manager(entry_state)

# Start the symbolic execution, specify the desired instruction address, and the one to avoid
simulation.explore(find = 0x401a6e, avoid = 0x040074d)

# Parse the correct input and print it
solution = simulation.found[0]
print solution.solver.eval(inp, cast_to=bytes)
```

When we run it:
```
$    python rev.py
WARNING | 2019-07-21 14:18:20,477 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
WARNING | 2019-07-21 14:18:27,811 | angr.state_plugins.symbolic_memory | Concretizing symbolic length. Much sad; think about implementing.
4ngrman4gem3nt
$    ./fairlight 4ngrman4gem3nt
OK - ACCESS GRANTED: CODE{4ngrman4gem3nt}
```

Just like that, we used Angr to solve the challenge!
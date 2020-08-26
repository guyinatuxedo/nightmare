# h3 h3machine 0

So starting off, for these challenges we will have to set up a few things before we can really dive in. We will have to set up a virtual environment for this to work.

First if you don't have it already, you will need to install pipenv:
```
$    sudo pip install pipenv
```

Then unzip the tar file and traverse into it:
```
$    tar -zxvf h3-machine-emulator.tar.gz

.    .    .

$    cd h3-machine-emulator/
```

Then setup the virtual environment:

```
$    pipenv --three install
Virtualenv already exists!
Removing existing virtualenv...
Creating a virtualenv for this project...
Pipfile: /Hackery/pod/modules/custom_architecture/h3_h3machine0/h3-machine-emulator/Pipfile
Using /usr/bin/python3 (3.6.8) to create virtualenv...
⠙ Creating virtual environment...Using base prefix '/usr'
New python executable in /home/guyinatuxedo/.local/share/virtualenvs/h3-machine-emulator-1bmi1h2b/bin/python3
Also creating executable in /home/guyinatuxedo/.local/share/virtualenvs/h3-machine-emulator-1bmi1h2b/bin/python
Installing setuptools, pip, wheel...
done.
Running virtualenv with interpreter /usr/bin/python3

✔ Successfully created virtual environment!
Virtualenv location: /home/guyinatuxedo/.local/share/virtualenvs/h3-machine-emulator-1bmi1h2b
Virtualenv already exists!
Removing existing virtualenv...
Creating a virtualenv for this project...
Pipfile: /Hackery/pod/modules/custom_architecture/h3_h3machine0/h3-machine-emulator/Pipfile
Using /usr/bin/python3 (3.6.8) to create virtualenv...
⠙ Creating virtual environment...Using base prefix '/usr'
New python executable in /home/guyinatuxedo/.local/share/virtualenvs/h3-machine-emulator-1bmi1h2b/bin/python3
Also creating executable in /home/guyinatuxedo/.local/share/virtualenvs/h3-machine-emulator-1bmi1h2b/bin/python
Installing setuptools, pip, wheel...
done.
Running virtualenv with interpreter /usr/bin/python3

✔ Successfully created virtual environment!
Virtualenv location: /home/guyinatuxedo/.local/share/virtualenvs/h3-machine-emulator-1bmi1h2b
Installing dependencies from Pipfile.lock (ed1172)...
  🐍   ▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉▉ 4/4 — 00:00:02
To activate this project's virtualenv, run pipenv shell.
Alternatively, run a command inside the virtualenv with pipenv run.
```

After that you will need to compile the emulator. Just run `make` in the same directory:

```
$	make
cc --std=gnu99 -Wall -Wextra -Werror -Wpedantic   -c -o src/h3emu.o src/h3emu.c
cc --std=gnu99 -Wall -Wextra -Werror -Wpedantic   -c -o src/machine.o src/machine.c
cc --std=gnu99 -Wall -Wextra -Werror -Wpedantic   -c -o src/opcodes.o src/opcodes.c
cc --std=gnu99 -Wall -Wextra -Werror -Wpedantic   -c -o src/opcode_lookup.o src/opcode_lookup.c
cc    -o h3emu src/h3emu.o src/machine.o src/opcodes.o src/opcode_lookup.o
```

So now that the setup is out of the way, let's focus on the challenge. So this module is all about dealing with a custom architecture (rather one particular instance of a custom architecture). This means that the assembly code of the binaries wasn't written in `x86`, `x64`, `MIPS`, `ARM` or anything else that you will typically see. The assembly code itself is custom and unique. Fortunately they provided some documentation in the `README.md` file that I will copy and paste here for convenience (reading this will really help). Again this following chunk of documentation was made by the challenge authors, not me:

```
# H3 Machine

The H3 Machine is a simple computer designed for writing interesting binary reversing problems.
It is a stack machine with no general-purpose registers.

# tl;dr

Each challenge is an executable image that can be run with the H3 machine
emulator. If the challenge runs correctly, it will print out the flag.

You can run the challenges like:

    ./h3emu [--trace] IMAGE [ARG1 [ARG2 [...]]]

For example,

  ./h3emu --trace challenge1.h3i 10 20 30

The --trace flag will print out each instruction as it executes.

You can also get a static disassembly with:

  ./h3disasm IMAGE


To get the flag, you may have to modify the challenge image slightly or provide
a particular set of arguments. Good luck!


# Building

    make

# Developers

To run the assembler or code generation, you need [pipenv][] installed.

You should say

    pipenv --three install

to get the virtualenv set up. After that, everything should just work.

# Registers

There are four special-purpose registers which are 16 bits in length:

-   IP: Instruction Pointer
-   SP: Stack Pointer
-   FR: Flag Register

The currently-defined flags are:

-   0x0001: Zero flag: set when 0x00000000 is pushed;
    cleared when any other value is pushed
-   0x0002: Carry flag: set when an arithmetic operation overflows;
    cleared when an arithmetic operation does not overflow.
    Non-arithmetic instructions do not update this flag.
-   0x8000: Flag flag: set when the top value of the stack at the HALT
    instruction most likely contains the flag.

There's a hidden stack used for CALL/RET.

# Memory

This machine operates on 32-bit words.
The total memory consists of 2^16 word-addressed 32-bit words (1 MiB).

By convention, word 0x0000 should always contain the value 0x00000000.

## Loading

An executable is loaded into the machine by memory mapping the file with 1 MiB total size.
IP is initialized to 0x0001, SP, and FR are initialized to 0x0000.

# Emulator

Additional command line arguments will be pushed on the stack before execution begins.

When the HALT instruction is reached, the stack and registers will be printed.

    h3emu [--trace] IMAGE [ARG1 [ARG2 [...]]]
    h3emu --version
    h3emu --help

# Disassembler

You can use the --trace flag of the emulator to get a dynamic stream of
instructions as they execute. Alternatively, you can use h3disasm to get a
basic static disassembly of the image.

  h3disasm IMAGE

# Instructions

The bits of the instruction are allocated like this:

    0123456789abcdef 0123456789abcdef
    -------- opcode
            ----- reserved
                 --- addressing mode
                     ---------------- address

## Opcodes

Opcodes can take operands.
The first operand is read from the location indicated by the address field of the instruction.
Second and further operands are always popped from the stack.
Results are pushed onto the stack.

-   0x00 HALT: Machine stops execution

### Stack manip opcodes

-   0x10 DROP: Increment SP.
-   0x11 SWAP: Get two operands, then push them in reverse order.
-   0x12 PUSH: Get one operand, then push it.
-   0x13 POP: Remove the topmost stack entry, put it somewhere else according to the address.
    This operation is the only exception to the rule that the first argument is based on the address and the result goes on the stack.
    This operation works the other way around, the argument comes from the stack and the result goes to the location of the address.

### Arithmetic opcodes

-   0x20 ADD: Get two operands, add them (mod 2^32)
-   0x21 SUB: Get two operands, subtract the second from the first.
-   0x22 MUL: Get two operands, multiply them.
-   0x23 DIV: Get two operands, divide the first by the second to get the integer quotient.
-   0x24 MOD: Get two operands, divide the first by the second to get the integer remainder.
-   0x25 NEGATE: Get one operand, two's-complement negate.

### Logical opcodes

-   0x30 AND: Get two operands, push the bitwise-and.
-   0x31 OR: Get two operands, push the bitwise-or.
-   0x32 NOT: Get one operand, push the bitwise-inversion (one's-complement negate).
-   0x33 XOR: Get two operands, push the bitwise-exclusive-or.
-   0x34 NAND: Get two operands, push the bitwise-negated-and.
-   0x35 NOR: Get two operands, push the bitwise-negated-or.
-   0x36 ASHIFT: Get two operands, shift the second one right arithmetically by the number of bits specified in the first argument.
    "Arithmetically" means that the MSB is shifted in on the left.
    To shift left, provide a first operand less than zero.
    If the first operand has magnitude greater than 32, the result is undefined.
-   0x37 LSHIFT: Get two operands, shift the second one right logically by the number of bits specified in the first argument.
    "Logically" means that `0` is shifted in on the left.
    To shift left, provide a first operand less than zero.
    If the first operand has magnitude greater than 32, the result is undefined.
-   0x38 ROTATE: Get two operands, rotate the second one right by the number of bits specified in the first argument.
    To rotate left, provide a first operand less than zero.
    If the first operand has magnitude greater than 32, the result is undefined.
    (a.k.a. circular shift)

### Compare & Jump

-   0x40 JMP: One operand. Unconditional jump to the specified address.
-   0x41 JZ: One operand. Jump to specified address if ZF is set.
-   0x41 JC: One operand. Jump to specified address if CF is set.

### Flag Register

-   0x50 SETF: One operand. Set flags in the flag register indicated by the mask.
    (N.B. `SETF 8000` sets the Flag flag.
    If you insert this instruction into the image so it gets run,
    the emulator will print the output as if it were a flag,
    but it will probably be wrong.)
-   0x51 CLF: One operand. Clear flags in the flag register indicated by the mask.

### Call & Return

-   0x60 CALL: One operand: address of function to call.
    The return address is stored on a separate hidden stack.
-   0x61 RET: No operands. Return.

### Data

To write raw data into the image (a global constant, for instance), use this syntax:

    foo: =01234567

Note that this takes a 32-bit hexadecimal value, instead of the 16-bit value used by an address.
While the label is still optional, this form isn't very useful without the label.

## Addressing Modes

### Null Addressing Mode (0x0) ""

The address field of the instruction is ignored.
All of the operands are popped from the stack.

### Stack-Relative Addressing Mode (0x1) "+[0-9a-f]{1,4}"

The address is added (mod 2^16) to SP before the value for the first operand is read.
Any remaining operands will be popped off the stack.

### Absolute Addressing Mode (0x2) "\$[0-9a-f]{1,4}" or "\$&[a-zA-Z]\w*"

The address is used to read the first operand.
Any remaining operands are popped from the stack.

The second form allows referring to the address of a label in the assembly.


### Indirect Addressing Mode (0x3) "\[[+-]?[0-9a-f]{1,4}\]"

The top value of the stack is popped and added to the immediate address and the value of the first operand is read from there.
Any remaining operands are popped from the stack.

### Immediate Addressing Mode (0x4) "[0-9a-f]{1,4}" or "&[a-zA-Z]\w*"

The address is sign-extended to 32 bits and used as the first operand.
Any remaining operands are popped from the stack.
```

So a few things of note from this documentation. This architecture is 16 bit (so the registers can only hold 16 bit values, and the total memory space is `2^16`). There are only three registers, one for the instruction pointer `IP` (does the job of the `eip/rip` registers). The second registers `SP` is the stack pointer register, which serves the same purpose as the `esp/rsp` registers. The last register `FR` is to keep track of the flags. It has three flags, which are a `Zero` flag, `Carry` flag, and a `Flag` flag. The `Zero` flag is set when `0x0` is pushed, and cleared when any other value is pushed. The `Carry` flag is set when am arithmetic operation overflows, and is cleared when an arithmetic operation does not overflow. The `Flag` register is set when the value on top of the stack most likely contains the flag (by flag I mean the actual flag we are trying to get to solve the challenge). Also one last thing, we are dealing with a little-endian architecture.

Also we can see it gives us a lot of documentation on the opcodes, however I won't really be going over that in depth since the instructions are very similar to their `x64/x86` counterparts. We can also see that we are given an assembler, dissasembler, and emulator for this architecutre. So we can write our own code for this custom architecture, run the code, and disassemble it. Let's take a look at the first challenge:

```
$    ./h3disasm challenge0.h3i
0001: 12020400 push $0004
0002: 50040080 setf 8000
0003: 00000000 halt
0004: 07530bf1
```

So we can see here there are only three instructions. It first pushes the address `0x4` onto the stack. Then it runs the `setf` operation to set the flag register to `0x8000`. When we check the documentation to see what this corresponds to, we see this is equivalent to setting the `FLAG` register, and clearing the other two. Then it runs the `halt` instruction with the `FLAG` register set which specifies that the value on top of the stack is the flag we are looking for. Let's run it:

```
$    ./h3emu challenge0.h3i
Stack:
ffff: flag{f10b5307}

Registers:
IP: 0004
SP: ffff
Flags:   F
```

So the point of this challenge was really just checking if we could get the emulator up and running. We see that it printed out the flag to us since it ran the `halt` instruction with the `F` (`FLAG`) flag set. We see that the flag is `flag{f10b5307}`, which we can see `f10b5307` is the value stored at address `4` in the code (although it is in little endian so the bytes are backwards). Just like that, we solved the challenge!

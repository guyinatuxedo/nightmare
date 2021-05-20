# Introduction to Assembly

So the first big wall you will need to tackle is starting to learn assembly. It may be a little bit tough, but it is perfectly doable and a critical step for what comes after. To start this off, I would recommend watching this video. It was made by the guy who actually got me interested in this line of work. I started off learning assembly by watching this video several times. It's really well put together:

```
[x86 Assembly Crash Course](https://www.youtube.com/watch?v=75gBFiFtAb8)
```

Now that you have watched the video, we will go through some documentation explaining some of the concepts around assembly code. A lot of this will be a repeat of that video, some of it won't be. Also all of this documentation will be for the Intel syntax. And one more thing; you don't need to have everything here memorized before moving on, and parts of it will make more sense when you actually see it in action.

## Compiling

So first off, what is assembly code? Assembly code is the code that is actually run on your computer by the processor. For instance take some C code:

```
#include <stdio.h>

void main(void)
{
    puts("Hello World!");
}
```

This code is not what runs. This code is compiled into assembly code, which looks like this:

```
0000000000001135 <main>:
    1135:       55                      push   rbp
    1136:       48 89 e5                mov    rbp,rsp
    1139:       48 8d 3d c4 0e 00 00    lea    rdi,[rip+0xec4]        # 2004 <_IO_stdin_used+0x4>
    1140:       e8 eb fe ff ff          call   1030 <puts@plt>
    1145:       90                      nop
    1146:       5d                      pop    rbp
    1147:       c3                      ret
    1148:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
    114f:       00
```

The purpose of languages like C, is that we can program without having to really deal with assembly code. We write code that is handed to a compiler, and the compiler takes that code and generates assembly code that will accomplish whatever the C code tells it to. Then the assembly code is what is actually ran on the processor. Since this is the code that is actually ran, it helps to understand it. Also since most of the time we are handed compiled binaries, we often only have the assembly code to work from. However, we have tools such as Ghidra that will take compiled assembly code and give us a view of what it thinks the C code that the code was compiled from looks like, so we don't need to read endless lines of assembly code. This is called a decompiler.

With assembly code, there are a lot of different architectures. Different types of processors can run different types of assembly code. The two we are dealing with the most here will be 64 bit, and 32 bit ELF (Executable and Linkable Format). I will often call these two things `x64` and `x86`.

## Registers

Registers are essentially places that the processor can store memory. You can think of them as buckets which the processor can store information in. Here is a list of the `x64` registers, and what their common use cases are.

```
rbp: Base Pointer, points to the bottom of the current stack frame
rsp: Stack Pointer, points to the top of the current stack frame
rip: Instruction Pointer, points to the instruction to be executed

General Purpose Registers
These can be used for a variety of different things.
rax:
rbx:
rcx:
rdx:
rsi:
rdi:
r8:
r9:
r10:
r11:
r12:
r13:
r14:
r15:
```

In `x64` linux arguments to a function are passed in via registers. The first few args are passed in by these registers:

```
rdi:    First Argument
rsi:    Second Argument
rdx:    Third Argument
rcx:    Fourth Argument
r8:     Fifth Argument
r9:     Sixth Argument
```

With the `x86` elf architecture, arguments are passed onto the stack. Also, as you may know, in C, functions can return a value. In `x64`, this value is passed in the `rax` register. In `x86` this value is passed in the `eax` register.

There are also different sizes for registers. The typical sizes we will be dealing with are `8` bytes, `4` bytes, `2` bytes, and `1` byte. The reason for these different sizes is due to the advancement of technology, so that we can store more data in a register.

```
+-----------------+---------------+---------------+------------+
| 8 Byte Register | Lower 4 Bytes | Lower 2 Bytes | Lower Byte |
+-----------------+---------------+---------------+------------+
|   rbp           |     ebp       |     bp        |     bpl    |
|   rsp           |     esp       |     sp        |     spl    |
|   rip           |     eip       |               |            |
|   rax           |     eax       |     ax        |     al     |
|   rbx           |     ebx       |     bx        |     bl     |
|   rcx           |     ecx       |     cx        |     cl     |
|   rdx           |     edx       |     dx        |     dl     |
|   rsi           |     esi       |     si        |     sil    |
|   rdi           |     edi       |     di        |     dil    |
|   r8            |     r8d       |     r8w       |     r8b    |
|   r9            |     r9d       |     r9w       |     r9b    |
|   r10           |     r10d      |     r10w      |     r10b   |
|   r11           |     r11d      |     r11w      |     r11b   |
|   r12           |     r12d      |     r12w      |     r12b   |
|   r13           |     r13d      |     r13w      |     r13b   |
|   r14           |     r14d      |     r14w      |     r14b   |
|   r15           |     r15d      |     r15w      |     r15b   |
+-----------------+---------------+---------------+------------+
```

In `x64` we will see the `8` byte registers. However in `x86` the largest registers we can use are the `4` byte registers like `ebp`, `esp`, `eip` etc. Now we can also use smaller registers than the maximum sized registers for the architecture.

In `x64` there is the `rax`, `eax`, `ax`, and `al` register. The `rax` register points to the full `8`. The `eax` register is just the lower four bytes of the `rax` register. The `ax` register is the last `2` bytes of the `rax` register. Lastly the `al` register is the last byte of the `rax` register.

## Words

You might hear the term word throughout this. A word is just two bytes of data. A dword is four bytes of data. A qword is eight bytes of data.

## Stacks

Now one of the most common memory regions you will be dealing with is the stack. It is where local function variables in the code are stored.

For instance, in this code the variable `x` is stored in the stack:
```
#include <stdio.h>

void main(void)
{
    int x = 5;
    puts("hi");
}
```

Now we can see it is stored on the stack at `rbp-0x4`.

```
0000000000001135 <main>:
    1135:       55                      push   rbp
    1136:       48 89 e5                mov    rbp,rsp
    1139:       48 83 ec 10             sub    rsp,0x10
    113d:       c7 45 fc 05 00 00 00    mov    DWORD PTR [rbp-0x4],0x5
    1144:       48 8d 3d b9 0e 00 00    lea    rdi,[rip+0xeb9]        # 2004 <_IO_stdin_used+0x4>
    114b:       e8 e0 fe ff ff          call   1030 <puts@plt>
    1150:       90                      nop
    1151:       c9                      leave
    1152:       c3                      ret
    1153:       66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
    115a:       00 00 00
    115d:       0f 1f 00                nop    DWORD PTR [rax]
```

Now values on the stack are moved on by either pushing them onto the stack, or popping them off. That is the only way to add or remove values from the stack, as it is a FILO(First In, Last Out) data structure. However, we can read and reference values on the stack at any time.

The exact bounds of the stack is recorded by two registers, `rbp` and `rsp`. The base pointer `rbp` points to the bottom of the stack. The stack pointer `rsp` points to the top of the stack.

## Flags

There is one register that contains flags. A flag is a particular bit of this register. If it is set or not typically means something. Here is the list of flags.

```
00:     Carry Flag
01:     always 1
02:     Parity Flag
03:     always 0
04:     Adjust Flag
05:     always 0
06:     Zero Flag
07:     Sign Flag
08:     Trap Flag
09:     Interruption Flag
10:     Direction Flag
11:     Overflow Flag
12:     I/O Privilege Field lower bit
13:     I/O Privilege Field higher bit
14:     Nested Task Flag
15:     Resume Flag
```

There are other flags then the one listed, however we really don't deal with them too much (and out of these, there are only a few we actively deal with).

If you want to hear more about this, check out: [Book on x86 Assembly and Architecture](https://en.wikibooks.org/wiki/X86_Assembly/X86_Architecture)

## Instructions

Now we will be covering some of the more common instructions you will see. This isn't every instruction you will see, just the often used ones.

#### mov

The move instruction just moves data from one register to another. For instance:

```
mov rax, rdx
```

This will just move the data from the `rdx` register to the `rax` register. Note that the data is moved into the *first* argument, not the second.

#### dereference

If you ever see brackets like `[]`, they are meant to dereference, which deals with pointers. A pointer is a value that points to a particular memory address (it is a memory address). Dereferencing a pointer means to treat a pointer like the value it points to. Put another way, a pointer is a variable that holds a memory address, and to dereference that pointer means you are accessing the value stored at that memory address. For instance:

```
mov rax, [rdx]
```

Will move the value pointed to by `rdx` into the `rax` register. On the flipside:

```
mov [rax], rdx
```

Will move the value of the `rdx` register into whatever memory is pointed to by the `rax` register. The actual value of the `rax` register does not change.

#### lea

The lea instruction calculates the address of the second operand, and moves that address in the first. For instance:

```
lea rdi, [rbx+0x10]
```

This will move the address `rbx+0x10` into the `rdi` register.

#### add
This just adds the two values together, and stores the sum in the first argument. For instance:

```
add rax, rdx
```

That will add the value of `rdx` to `rax`, setting `rax` equal to `rax + rdx`.

#### sub

This value will subtract the second operand from the first one, and store the difference in the first argument. For instance:

```
sub rsp, 0x10
```

This will subract 10 from `rsp`, setting the `rsp` register equal to `rsp - 0x10`

#### xor

This will perform the binary operation xor on the two arguments it is given, and stores the result in the first argument:

```
xor rdx, rax
```

This will set the `rdx` register equal to `rdx ^ rax`. If  the `xor` instruction is used with the same register for both argument, for example `xor rax, rax`, it will set all bits to zero, clearing the register.

To understand how `xor` works, you must understand that it is a *bitwise* operation, meaning it operates on the bits of a register. It compares the bits in each place, and sets the resulting bit to `1` if the bits are different, and `0` if they are the same. So for example, `xor 1011 1100` would return `0111`.

The `and` and `or` instructions essentially do the same thing, except with the `AND` or `OR` binary operators. For `and` it sets the resulting bit to `1` if both bits are also `1`, otherwise it sets it to `0`. For `or` it sets the resulting bit to `1` if either bit is `1`, otherwise it is set to `0`.

#### push

The `push` instruction will grow the stack by either `8` bytes (for `x64`, `4` for `x86`), then push the contents of a register onto the new stack space. For instance:

```
push rax
```

This will grow the stack by `8` bytes, and the contents of the `rax` register will be on top of the stack.

#### pop

The `pop` instruction will pop the top `8` bytes (for `x64`, `4` for `x86`) off of the stack and into the argument. Then it will shrink the stack. For instance:

```
pop rax
```

The top `8` bytes of the stack will end up in the `rax` register.

#### jmp

The `jmp` instruction will jump to an instruction address. It is used to redirect code execution. For instance:

```
jmp 0x602010
```

That instruction will cause the code execution to jump to `0x602010`, and execute whatever instruction is there.

#### call & ret

This is similar to the `jmp` instruction. The difference is it will push the values of `rbp` and `rip` onto the stack, then jump to whatever address it is given. This is used for calling functions. After the function is finished, a `ret` instruction is called which uses the pushed values of `rbp` and `rip` (saved base and instruction pointers) to return, it can continue execution right where it left off.

#### cmp

The cmp instruction is similar to that of the sub instruction. Except it doesn't store the result in the first argument. It checks if the result is less than zero, greater than zero, or equal to zero. Depending on the value it will set the flags accordingly.

#### jnz / jz

The `jump if not zero` and `jump if zero` (`jnz/jz`) instructions are pretty similar to the jump instruction. The difference is they will only execute the jump depending on the status of the `zero` flag. For `jz` it will only jump if the `zero` flag is set. The opposite is true for `jnz`. These instructions are how control flow is implemented in assembly.

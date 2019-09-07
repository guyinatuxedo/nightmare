# Elf Crumble

The challenge prompt is something about having an elf that prints the flag, however it was dropped and the pieces fell out. However the pieces of compiled code were not changed. We were given a `tgz` file. Let's see what we have when we decompress it:

```
$    ls pieces
broken          fragment_2.dat  fragment_4.dat  fragment_6.dat  fragment_8.dat
fragment_1.dat  fragment_3.dat  fragment_5.dat  fragment_7.dat
$    file pieces/broken
pieces/broken: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4cd47d8a237a3139d1884b3ef52f6ed387c75772, not stripped
$    file pieces/fragment_1.dat
pieces/fragment_1.dat: data
$    cat pieces/fragment_1.dat
[]�U��������E��#�U�����E��
                               �U��Љʈ�E��}�~א��U��S��
```

So in there we have an x86 binary and 8 files which just contain data. Let's see what happens when we run the binary:

```
$    pieces/broken
Segmentation fault (core dumped)
```

So when we run it, we get a segfault.  When we take a look at the binary in Ghidra, we see that there are five functions `main`, `recover_flag`, `f1`, `f2`, and `f3`. Let's take a look at the main function in gdb:

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x000007dc <+0>:    pop    eax
   0x000007dd <+1>:    pop    eax
   0x000007de <+2>:    pop    eax
   0x000007df <+3>:    pop    eax
   0x000007e0 <+4>:    pop    eax
```

So we can see that the main function is just the `pop eax` instruction repeated over and over again. We also see that this is the same way with the functions `recover_flag`, `f1`. `f2`, and `f3`. When we look at it in a hex editor we can see that the opcode for `pop eax` (which is `0x58`) has been overwritten to the five functions. We can see that the X's (`0x58` is hex for `X`) start at `0x5ad` and end at `0x8d3` for a total of 807 bytes. Let's see the size of all of the different fragments.

```
$    wc -c < fragment_1.dat
79
$    wc -c < fragment_2.dat
48
$    wc -c < fragment_3.dat
175
$    wc -c < fragment_4.dat
42
$    wc -c < fragment_5.dat
128
$    wc -c < fragment_6.dat
22
$    wc -c < fragment_7.dat
283
$    wc -c < fragment_8.dat
30
```

When we add up all of the different segments, we get 807 bytes the same amount as the written over opcodes. Now at this point we look back to the original challenge prompt about the elf being shattered into different pieces, however those pieces are still the same. At this point we can put two and two together and guess that the eight fragments make up the five different functions, we have to figure out what functions go where, and then patch over the binary.

#### Functions

Before we figure out where the fragments are, it would be helpful to figure out where the functions start and end. The five functions we are worried about are `f1`, `f2`, `f3`, `recover_flag`, and `main`. For this we can use gdb (or you could use binja):

To find the start of a function in gdb:
```
gef➤  p f1
$1 = {<text variable, no debug info>} 0x5ad <f1>
gef➤  p f2
$2 = {<text variable, no debug info>} 0x6e9 <f2>
gef➤  p f3
$3 = {<text variable, no debug info>} 0x72e <f3>
gef➤  p recover_flag
$4 = {<text variable, no debug info>} 0x7a2 <recover_flag>
gef➤  p main
$5 = {<text variable, no debug info>} 0x7dc <main>
```

Proceeding that we can find the following information:
```
f1 : starts 0x5ad
f2 : starts : starts 0x6e9
f3 : starts : starts 0x72e
recover_flag : starts 0x7a2
main : starts 0x7dc : ends 0x8d3
```

Also for this next part, you will probably need to use a hex editor like Bless or Binary Ninja.

#### Fragment 8

All x86 sub functions will start with the same three opcodes `0x55 0x89 0xe5`. These are the opcodes for `push ebp`, `mov ebp, esp`, and `sub esp, x` where x is some integer. With this we can identify the start of sub functions within the fragments. When we look at this fragment, we see that it starts with those three opcodes. As such we know that the start of this fragment must be the start of a sub function. Looking across all of the other fragments we don't see this anywhere else. We know that the start of the X's (which is the start of the f1 function) has to start with that, so we know that this fragment goes at the start of the X's.

#### Fragment 2

This fragment has an interesting three opcode combination in it. Those opcodes are `0x8d 0x4c 0x24`. Those are the opcodes for `lea ecx, [esp+0x4 {argc}]`, `and esp, 0xfffffff0 {__return_addr}`, and `push dword [ecx-0x4]`. This is a part of how the assembly code loads in arguments and sets up the stack. From that we know that the three opcode combination mush occur at the start of main, so we can position this fragment just write so that the main function starts off with those three.

#### Fragment 4

For this fragment we don't see the three opcode combination to designate the start of a subroutine function. However we do see that it ends with the opcode `0xc3` which is the opcode for the assembly instruction `retn`. We would expect to see this at the end of a function function. We also see that it is the only fragment to end with that opcode. Thing is we need this fragment at the end, since we need to end the main function with that instruction. Since this is the only fragment that has what we need there, this is the only fragment that can go there.

#### Fragment 3

Between fragments 2 and 4, we have a nice 175 byte block of data. Luckily this fragment is the only fragment that fits in. In addition to that we don't see the opcodes to start a new function or return, so we should be good.

#### Fragments 1, 5 - 7

For the next two segments, we can see that the next function start it 286 bytes away from our first fragment, fragment 8 ((0x6e9 - 0x5ad) - 30). We can reach that by first placing fragment 7 (which doesn't stop/start any functions) immediately followed by fragment 1 which starts a function on it's fourth byte. Together this fits and will properly start the `f2` function. In addition to that it will also start the `f3` function located 69 bytes after the start if `f2`.

Lastly we have the two pieces 5 and 6. For this it's just a matter of putting the two together in an order that will start the last function we need to start, `recover_flag`. If we place the fragment 5 first, that will properly start this function. After that we can just stick in the last fragment 6 into the remaining hole and we have successfully reassembled the binary.

#### Wrap Up

The order of the fragments is `8 7 1 5 6 2 3 4`. Once you have reassembled the fragments you can just patch over the binary with a hex editor like binja or bless (or whatever hex editor you want to use). Proceeding that you just have to run the program to get the flag:

```
$    ./rev
welcOOOme
```

Just like that, we captured the flag!
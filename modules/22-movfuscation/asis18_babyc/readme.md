# Asis 2018 Quals Babyc

The goal of this challenge is just to find the first `14` characters of the correct input (a bit different, the flag was a hash of the first `14` characters).

Let's take a look at the binary:

```
$    file babyc
babyc: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, stripped
$    ./babyc
15935728
Wrong!

```

So it looks like we are dealing with a `32` bit crackme challenge that takes in input via stdin. A crackme challenge is one that takes in input, and checks if it is what it expects (and we have to figure out the correct input). Looking at the assembly code of the binary in Ghidra, it becomes apparant very quickly that this binary has been obfuscated:

```
        08048343 a3 f0 5f        MOV        [DAT_081f5ff0],EAX
                 1f 08
        08048348 89 15 f4        MOV        dword ptr [DAT_081f5ff4],EDX
                 5f 1f 08
        0804834e b8 00 00        MOV        EAX,0x0
                 00 00
        08048353 b9 00 00        MOV        ECX,0x0
                 00 00
        08048358 c7 05 00        MOV        dword ptr [DAT_081f6000],0x0
                 60 1f 08
                 00 00 00 00
        08048362 66 a1 f0        MOV        AX,[DAT_081f5ff0]
                 5f 1f 08
        08048368 66 8b 0d        MOV        CX,word ptr [DAT_081f5ff4]
                 f4 5f 1f 08
        0804836f 8b 14 85        MOV        EDX,dword ptr [PTR_DAT_08060f30 + EAX*0x4]       = 080e0f34
                 30 0f 06 08
        08048376 8b 14 8a        MOV        EDX,dword ptr [EDX + ECX*0x4]
        08048379 66 8b 0d        MOV        CX,word ptr [DAT_081f6002]
                 02 60 1f 08
        08048380 8b 14 95        MOV        EDX,dword ptr [PTR_DAT_08060f30 + EDX*0x4]       = 080e0f34
                 30 0f 06 08
        08048387 8b 14 8a        MOV        EDX,dword ptr [EDX + ECX*0x4]
        0804838a 66 89 15        MOV        word ptr [DAT_081f5ff8],DX
                 f8 5f 1f 08
```

Specifically it has been obfuscated using Movfiscator, which is a compiler that obfuscates code by only using the `mov` instruction. Starting off I tried to do a side channel attack with perf, however that didn't work here. After I tried using a tool called `demovfuscator` (https://github.com/kirschju/demovfuscator) which is a tool designed to help reverse out movfuscated binaries. it can produce a graph showing the control flow through the program, and can even generate a binary from the movfuscated binary.

Let's run the tool to generate a patched version of the binary, and a graph:

```
$       ./demov -g char.dot -o demov_babyc babyc
```

and let's convert the .dot file to a pdf:

```
$       dot -Tpdf char.dot -o char.pdf
```

Looking at the graph `char.pdf`, we see that it starts at `0x804899e` and ends at `0x804b97c`. In between that we can see there is a string of conditionals, which if any of them fail it will lead us to `0x804b5d0`. These conditionals are at these addresses:

```
0x8049853:
0x8049b26:
0x8049e50:
0x804a17a:
0x804a6fc:
```

Let's take a look at the code for the `0x8049853` conditional, we see this (this is from the demovfuscated patched binary):


Let's us objdump to view it:
```
$       objdump -D demov_babyc -M intel | less
```

Then we see this:
```
 8049847:       a1 e0 5f 1f 08          mov    eax,ds:0x81f5fe0
 804984c:       85 c0                   test   eax,eax
 804984e:       90                      nop
 804984f:       90                      nop
 8049850:       90                      nop
 8049851:       90                      nop
 8049852:       90                      nop
 8049853:       0f 85 77 1d 00 00       jne    804b5d0 <strncmp@plt+0x3350>
```

So we can see that the comparison which determines if there is a jump is made at `0x804984c`. Let's see what the memory looks like there in gdb:

```
gef➤  b *0x804984c
Breakpoint 1 at 0x804984c
gef➤  r
Starting program: /Hackery/pod/modules/movfuscation/asis18_babyc/demov_babyc
15935728
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1       
$ebx   : 0xf7ffd000  →  0x00026f34
$ecx   : 0x1       
$edx   : 0x0       
$esp   : 0x085f6124  →  0x085f6133  →  "35728"
$ebp   : 0x0       
$esi   : 0xffffd0fc  →  0xffffd2de  →  "CLUTTER_IM_MODULE=xim"
$edi   : 0x0804829c  →   mov DWORD PTR ds:0x83f6140, esp
$eip   : 0x0804984c  →   test eax, eax
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x085f6124│+0x0000: 0x085f6133  →  "35728"       ← $esp
0x085f6128│+0x0004: 0x0804d036  →  "m0vfu3c4t0r!"
0x085f612c│+0x0008:  or al, 0x0
0x085f6130│+0x000c: "15935728"
0x085f6134│+0x0010: "5728"
0x085f6138│+0x0014:  or al, BYTE PTR [eax]
0x085f613c│+0x0018:  add BYTE PTR [eax], al
0x085f6140│+0x001c:  add BYTE PTR [eax], al
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804983e                  mov    edx, DWORD PTR ds:0x804d07c
    0x8049844                  mov    DWORD PTR [eax+0xc], edx
    0x8049847                  mov    eax, ds:0x81f5fe0
 →  0x804984c                  test   eax, eax
    0x804984e                  nop    
    0x804984f                  nop    
    0x8049850                  nop    
    0x8049851                  nop    
    0x8049852                  nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "demov_babyc", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x804984c → test eax, eax
─────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x0804984c in ?? ()
gef➤  
```

So we can see that our input is on the stack, or more specifically our input after the first three characters. After that is the string `m0vfu3c4t0r!`, which it is probably comparing our input after the first three characters to. When we input the string `012m0vfu3c4t0r!` we see that we pass this check which confirms our assumption.

The next check we have is at `0x8049b26`:

```
 8049a71:       a3 e0 5f 1f 08          mov    ds:0x81f5fe0,eax
 8049a76:       a1 e0 5f 1f 08          mov    eax,ds:0x81f5fe0
 8049a7b:       8b 04 85 60 61 3f 08    mov    eax,DWORD PTR [eax*4+0x83f6160]
 8049a82:       8b 15 00 61 1f 08       mov    edx,DWORD PTR ds:0x81f6100
 8049a88:       89 10                   mov    DWORD PTR [eax],edx
 8049a8a:       8b 0d e0 5f 1f 08       mov    ecx,DWORD PTR ds:0x81f5fe0
 8049a90:       c7 05 74 61 3f 08 90    mov    DWORD PTR ds:0x83f6174,0x85f6190
 8049a97:       61 5f 08
 8049a9a:       8b 04 8d 70 61 3f 08    mov    eax,DWORD PTR [ecx*4+0x83f6170]
 8049aa1:       8b 15 50 d0 04 08       mov    edx,DWORD PTR ds:0x804d050
 8049aa7:       89 10                   mov    DWORD PTR [eax],edx
 8049aa9:       8b 15 54 d0 04 08       mov    edx,DWORD PTR ds:0x804d054
 8049aaf:       89 50 04                mov    DWORD PTR [eax+0x4],edx
 8049ab2:       8b 15 58 d0 04 08       mov    edx,DWORD PTR ds:0x804d058
 8049ab8:       89 50 08                mov    DWORD PTR [eax+0x8],edx
 8049abb:       8b 15 5c d0 04 08       mov    edx,DWORD PTR ds:0x804d05c
 8049ac1:       89 50 0c                mov    DWORD PTR [eax+0xc],edx
 8049ac4:       c7 05 74 61 3f 08 a0    mov    DWORD PTR ds:0x83f6174,0x85f61a0
 8049acb:       61 5f 08
 8049ace:       8b 04 8d 70 61 3f 08    mov    eax,DWORD PTR [ecx*4+0x83f6170]
 8049ad5:       8b 15 60 d0 04 08       mov    edx,DWORD PTR ds:0x804d060
 8049adb:       89 10                   mov    DWORD PTR [eax],edx
 8049add:       8b 15 64 d0 04 08       mov    edx,DWORD PTR ds:0x804d064
 8049ae3:       89 50 04                mov    DWORD PTR [eax+0x4],edx
 8049ae6:       c7 05 74 61 3f 08 a8    mov    DWORD PTR ds:0x83f6174,0x85f61a8
 8049aed:       61 5f 08
 8049af0:       8b 04 8d 70 61 3f 08    mov    eax,DWORD PTR [ecx*4+0x83f6170]
 8049af7:       8b 15 70 d0 04 08       mov    edx,DWORD PTR ds:0x804d070
 8049afd:       89 10                   mov    DWORD PTR [eax],edx
 8049aff:       8b 15 74 d0 04 08       mov    edx,DWORD PTR ds:0x804d074
 8049b05:       89 50 04                mov    DWORD PTR [eax+0x4],edx
 8049b08:       8b 15 78 d0 04 08       mov    edx,DWORD PTR ds:0x804d078
 8049b0e:       89 50 08                mov    DWORD PTR [eax+0x8],edx
 8049b11:       8b 15 7c d0 04 08       mov    edx,DWORD PTR ds:0x804d07c
 8049b17:       89 50 0c                mov    DWORD PTR [eax+0xc],edx
 8049b1a:       a1 e0 5f 1f 08          mov    eax,ds:0x81f5fe0
 8049b1f:       85 c0                   test   eax,eax
 8049b21:       90                      nop
 8049b22:       90                      nop
 8049b23:       90                      nop
 8049b24:       90                      nop
 8049b25:       90                      nop
 8049b26:       0f 85 ca 18 00 00       jne    804b3f6 <strncmp@plt+0x3176>
```

This might seem like a lot, however I set a breakpoint for `0x8049a71` and stepped through this code while watching the registers. While stepping through I noticed something interesting.

We see that the `edx` register gets loaded with our first character:

```
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x085f6190  →   add BYTE PTR [eax], al
$ebx   : 0xf7ffd000  →  0x00026f34
$ecx   : 0x1       
$edx   : 0x30      
$esp   : 0x085f6124  →  0x085f6133  →  "m0vfu3c4t0r!"
$ebp   : 0x0       
$esi   : 0xffffd0fc  →  0xffffd2de  →  "CLUTTER_IM_MODULE=xim"
$edi   : 0x0804829c  →   mov DWORD PTR ds:0x83f6140, esp
$eip   : 0x08049aa7  →   mov DWORD PTR [eax], edx
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x085f6124│+0x0000: 0x085f6133  →  "m0vfu3c4t0r!"        ← $esp
0x085f6128│+0x0004: 0x0804d036  →  "m0vfu3c4t0r!"
0x085f612c│+0x0008:  or al, 0x0
0x085f6130│+0x000c: "012m0vfu3c4t0r!"
0x085f6134│+0x0010: "0vfu3c4t0r!"
0x085f6138│+0x0014: "3c4t0r!"
0x085f613c│+0x0018: 0x0a217230 ("0r!"?)
0x085f6140│+0x001c:  add BYTE PTR [eax], al
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049a90                  mov    DWORD PTR ds:0x83f6174, 0x85f6190
    0x8049a9a                  mov    eax, DWORD PTR [ecx*4+0x83f6170]
    0x8049aa1                  mov    edx, DWORD PTR ds:0x804d050
 →  0x8049aa7                  mov    DWORD PTR [eax], edx
    0x8049aa9                  mov    edx, DWORD PTR ds:0x804d054
    0x8049aaf                  mov    DWORD PTR [eax+0x4], edx
    0x8049ab2                  mov    edx, DWORD PTR ds:0x804d058
    0x8049ab8                  mov    DWORD PTR [eax+0x8], edx
    0x8049abb                  mov    edx, DWORD PTR ds:0x804d05c
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "demov_babyc", stopped, reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049aa7 → mov DWORD PTR [eax], edx
─────────────────────────────────────────────────────────────────────────────────────────────────────
0x08049aa7 in ?? ()
gef➤  
```

Proceeding that, the `edx` register gets loaded with the character `A` (`0x41`):

```
gef➤  s
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x085f6190  →  0x00000030 ("0"?)
$ebx   : 0xf7ffd000  →  0x00026f34
$ecx   : 0x1       
$edx   : 0x41      
$esp   : 0x085f6124  →  0x085f6133  →  "m0vfu3c4t0r!"
$ebp   : 0x0       
$esi   : 0xffffd0fc  →  0xffffd2de  →  "CLUTTER_IM_MODULE=xim"
$edi   : 0x0804829c  →   mov DWORD PTR ds:0x83f6140, esp
$eip   : 0x08049ab8  →   mov DWORD PTR [eax+0x8], edx
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x085f6124│+0x0000: 0x085f6133  →  "m0vfu3c4t0r!"        ← $esp
0x085f6128│+0x0004: 0x0804d036  →  "m0vfu3c4t0r!"
0x085f612c│+0x0008:  or al, 0x0
0x085f6130│+0x000c: "012m0vfu3c4t0r!"
0x085f6134│+0x0010: "0vfu3c4t0r!"
0x085f6138│+0x0014: "3c4t0r!"
0x085f613c│+0x0018: 0x0a217230 ("0r!"?)
0x085f6140│+0x001c:  add BYTE PTR [eax], al
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049aa9                  mov    edx, DWORD PTR ds:0x804d054
    0x8049aaf                  mov    DWORD PTR [eax+0x4], edx
    0x8049ab2                  mov    edx, DWORD PTR ds:0x804d058
 →  0x8049ab8                  mov    DWORD PTR [eax+0x8], edx
    0x8049abb                  mov    edx, DWORD PTR ds:0x804d05c
    0x8049ac1                  mov    DWORD PTR [eax+0xc], edx
    0x8049ac4                  mov    DWORD PTR ds:0x83f6174, 0x85f61a0
    0x8049ace                  mov    eax, DWORD PTR [ecx*4+0x83f6170]
    0x8049ad5                  mov    edx, DWORD PTR ds:0x804d060
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "demov_babyc", stopped, reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8049ab8 → mov DWORD PTR [eax+0x8], edx
─────────────────────────────────────────────────────────────────────────────────────────────────────
0x08049ab8 in ?? ()
gef➤  
```

From this, I decided to see if it was checking if the first character was `A`. After trying the string `A12m0vfu3c4t0r!` I saw that we passed this check, so our assumption was correct. Turns out there are just two last checks that we need to worry about, which are here:

```
0x8049e50:      starts at 0x8049d9b
0x804a17a:      starts at 0x804a0c5
```

The process of figuring out what characters they are checking for is exactly the same as with the first character. With that, we can figure out that the first three character it is checking for is `Ah_`. THat leaves us with the string `Ah_m0vfu3c4t0r!`, which is the first `14` characters of the string, so we have what we need to make the hash for the flag.

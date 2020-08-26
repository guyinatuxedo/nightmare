# helithumper re

The goal of this challenge is to get the flag. This was a challenge made by Helithumper (github.com/helithumper). Let's take a look at the binary:

```
$    ./rev
Welcome to the Salty Spitoon™, How tough are ya?
Tough as Joseph, but not Jotaro
Yeah right. Back to Weenie Hut Jr™ with ya
$    file rev
rev: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e4dbcb1281821db359d566c68fea7380aeb27378, for GNU/Linux 3.2.0, not stripped
```

So we can see that we are dealing with a `64` bit binary. When we run it, it prompts us for input. What is probably going on here, is it is scanning in data, and checking it. In order to get the flag, we will probably need to pass that check.

When we take a look at the main function in Ghidra, we see this (btw I cleaned up the code a little bit, what you see will probably look a little different):

```
ulong main(void)

{
  int check;
  void *ptr;
 
  ptr = calloc(0x32,1);
  puts("Welcome to the Salty Spitoon™, How tough are ya?");
  __isoc99_scanf(&DAT_0010203b,ptr);
  check = validate(ptr);
  if (check == 0) {
    puts("Yeah right. Back to Weenie Hut Jr™ with ya");
  }
  else {
    puts("Right this way...");
  }
  return (ulong)(check == 0);
}
```

So we can see that it is scanning in data to `ptr`, then running the `validate` function. We can see that the `validate` function does this:

```
undefined8 validate(char *input)

{
  long lVar1;
  size_t inputLen;
  undefined8 returnValue;
  long in_FS_OFFSET;
  int i;
  int checkValues [4];
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  checkValues[0] = 0x66;
  checkValues[1] = 0x6c;
  checkValues[2] = 0x61;
  checkValues[3] = 0x67;
  inputLen = strlen(input);
  i = 0;
  do {
    if ((int)inputLen <= i) {
      returnValue = 1;
LAB_001012b7:
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return returnValue;
    }
    if ((int)input[(long)i] != checkValues[(long)i]) {
      returnValue = 0;
      goto LAB_001012b7;
    }
    i = i + 1;
  } while( true );
}
```

So we can see that it essentially takes our input, and runs it though a while true loop. For each iteration of this loop, we see that it checks one character of our input against a character in `checkValues`. The character it checks depends on which iteration of the loop it is. For instance iteration `0` will check the character of our input at index `0`, iteration `2` will check the character of our input at index `2`, and so on:

```
    if ((int)input[(long)i] != checkValues[(long)i]) {
      returnValue = 0;
      goto LAB_001012b7;
```

We also see there is a termination condition where if the iteration count exceeds the length of the string, it will exit. That is because it has finished checking the string:

```
    if ((int)inputLen <= i) {
      returnValue = 1;
```

Now this check will either return a `1`, or a `0`. In order to solve this challenge, we need it to ouput a `1`. In order for that to happen, we can't fail any of the character checks. In order for that to happen our input needs to be the same as the characters it checks it against. Looking at the code, we see that the first four characters it sets. However looking at the assembly code shows us that there is more:

```
        00101205 c7 45 c0        MOV        dword ptr [RBP + checkValues[0]],0x66
                 66 00 00 00
        0010120c c7 45 c4        MOV        dword ptr [RBP + checkValues[1]],0x6c
                 6c 00 00 00
        00101213 c7 45 c8        MOV        dword ptr [RBP + checkValues[2]],0x61
                 61 00 00 00
        0010121a c7 45 cc        MOV        dword ptr [RBP + checkValues[3]],0x67
                 67 00 00 00
        00101221 c7 45 d0        MOV        dword ptr [RBP + local_38],0x7b
                 7b 00 00 00
        00101228 c7 45 d4        MOV        dword ptr [RBP + local_34],0x48
                 48 00 00 00
        0010122f c7 45 d8        MOV        dword ptr [RBP + local_30],0x75
                 75 00 00 00
        00101236 c7 45 dc        MOV        dword ptr [RBP + local_2c],0x43
                 43 00 00 00
        0010123d c7 45 e0        MOV        dword ptr [RBP + local_28],0x66
                 66 00 00 00
        00101244 c7 45 e4        MOV        dword ptr [RBP + local_24],0x5f
                 5f 00 00 00
        0010124b c7 45 e8        MOV        dword ptr [RBP + local_20],0x6c
                 6c 00 00 00
        00101252 c7 45 ec        MOV        dword ptr [RBP + local_1c],0x41
                 41 00 00 00
        00101259 c7 45 f0        MOV        dword ptr [RBP + local_18],0x62
                 62 00 00 00
        00101260 c7 45 f4        MOV        dword ptr [RBP + local_14],0x7d
                 7d 00 00 00
```

From this, we can get this list of bytes that our input needs to be:

```
0x66
0x6c
0x61
0x67
0x7b
0x48
0x75
0x43
0x66
0x5f
0x6c
0x41
0x62
0x7d
```

We can use python to convert them into ascii like so:

```
$    python
Python 2.7.16 (default, Apr  6 2019, 01:42:57)
[GCC 8.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> x = [0x66, 0x6c, 0x61, 0x67, 0x7b, 0x48, 0x75, 0x43, 0x66, 0x5f, 0x6c, 0x41, 0x62, 0x7d]
>>> input = ""
>>> for i in x:
...     input += chr(i)
...
>>> input
'flag{HuCf_lAb}'
```

So we can see that our needed input is `flag{HuCf_lAb}` which is probably the flag (we can tell this, since the flag is usually in a format similar to `flag{x}`, with `x` being some string):

```
$    ./rev
Welcome to the Salty Spitoon™, How tough are ya?
flag{HuCf_lAb}
Right this way...
```

Just like that we got the flag!
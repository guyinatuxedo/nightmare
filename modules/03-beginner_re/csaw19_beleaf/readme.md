# CSAW 2019 beleaf

When we take a look at the binary, we see this:

```
$    file beleaf
beleaf: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6d305eed7c9bebbaa60b67403a6c6f2b36de3ca4, stripped
$    pwn checksec beleaf
[*] '/Hackery/pod/modules/3-beginner_re/csaw19_beleaf/beleaf'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./beleaf
Enter the flag
>>> 15935728
Incorrect!
```

So we can see that we are dealing with a `64` bit binary. When we run the binary, it prompts us for input. This is probably a crackme challenge. This is a type of challenge that scans in input, and checks it. The goal is to pass it the correct input, to pass whatever check it does.

## Reversing

Looking at the main function at `0x1008a1`, we see this:

```
undefined8 main(void)

{
  size_t inputLen;
  long transformedInput;
  long in_FS_OFFSET;
  ulong i;
  char input [136];
  long stackCanary;
 
  stackCanary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter the flag\n>>> ");
  __isoc99_scanf(&DAT_00100a78,input);
  inputLen = strlen(input);
  if (inputLen < 0x21) {
    puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  i = 0;
  while (i < inputLen) {
    transformedInput = transformFunc(input[i]);
    if (transformedInput != *(long *)(&desiredOutput + i * 8)) {
      puts("Incorrect!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    i = i + 1;
  }
  puts("Correct!");
  if (stackCanary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So we can see, it starts off by scanning in input. If our input is less than `0x21` (`33`) bytes, the code exits (so our input probably has to be `33`) bytes, Looking at it later, we see that it enters into a for loop. It will run each character through the `transformFunc` (or at least until the code calls `exit`). It will then compare the output of that functions (stored in `transformedInput`) against the corresponding character in the bss array `desiredOutput` (characters are stored at offsets of `8`) bytes. If the two are not equivalent, `exit` is called and we fail the challenge. We can see the contents of `desiredOutput` by double clicking on it. When we look at `desiredOutput`, we see this:

```
                             desiredOutput                                   XREF[2]:     main:0010096b(*),
                                                                                          main:00100972(R)  
        003014e0 01              ??         01h
        003014e1 00              ??         00h
        003014e2 00              ??         00h
        003014e3 00              ??         00h
        003014e4 00              ??         00h
        003014e5 00              ??         00h
        003014e6 00              ??         00h
        003014e7 00              ??         00h
        003014e8 09              ??         09h
        003014e9 00              ??         00h
        003014ea 00              ??         00h
        003014eb 00              ??         00h
        003014ec 00              ??         00h
        003014ed 00              ??         00h
        003014ee 00              ??         00h
        003014ef 00              ??         00h
        003014f0 11              ??         11h
        003014f1 00              ??         00h
        003014f2 00              ??         00h
        003014f3 00              ??         00h
        003014f4 00              ??         00h
        003014f5 00              ??         00h
        003014f6 00              ??         00h
        003014f7 00              ??         00h
        003014f8 27              ??         27h    '
        003014f9 00              ??         00h
        003014fa 00              ??         00h
        003014fb 00              ??         00h
        003014fc 00              ??         00h
        003014fd 00              ??         00h
        003014fe 00              ??         00h
        003014ff 00              ??         00h
        00301500 02              ??         02h
```

So here we see that our first output has to be equal to `0x1`, our second has to be `0x9`, our third has to be `0x11`, and so on and so forth. Looking at the `transformFunc`, we see this:

```
long transformFunc(char input)

{
  long i;
 
  i = 0;
  while ((i != -1 && ((int)input != *(int *)(&lookup + i * 4)))) {
    if ((int)input < *(int *)(&lookup + i * 4)) {
      i = i * 2 + 1;
    }
    else {
      if (*(int *)(&lookup + i * 4) < (int)input) {
        i = (i + 1) * 2;
      }
    }
  }
  return i;
}
```

Here we can see that it essentially just takes a character, and looks at what it's index is in the `lookup` bss array. The characters are stored at offsets of `4` bytes. Let's take a look at the array:

```
                             lookup                                          XREF[6]:     transformFunc:00100820(*),
                                                                                          transformFunc:00100827(R),
                                                                                          transformFunc:00100844(*),
                                                                                          transformFunc:0010084b(R),
                                                                                          transformFunc:00100873(*),
                                                                                          transformFunc:0010087a(R)  
        00301020 77              ??         77h    w
        00301021 00              ??         00h
        00301022 00              ??         00h
        00301023 00              ??         00h
        00301024 66              ??         66h    f
        00301025 00              ??         00h
        00301026 00              ??         00h
        00301027 00              ??         00h
        00301028 7b              ??         7Bh    {
        00301029 00              ??         00h
        0030102a 00              ??         00h
        0030102b 00              ??         00h
        0030102c 5f              ??         5Fh    _
        0030102d 00              ??         00h
        0030102e 00              ??         00h
        0030102f 00              ??         00h
        00301030 6e              ??         6Eh    n
        00301031 00              ??         00h
        00301032 00              ??         00h
        00301033 00              ??         00h
        00301034 79              ??         79h    y
        00301035 00              ??         00h
        00301036 00              ??         00h
        00301037 00              ??         00h
        00301038 7d              ??         7Dh    }
        00301039 00              ??         00h
        0030103a 00              ??         00h
        0030103b 00              ??         00h
        0030103c ff              ??         FFh
        0030103d ff              ??         FFh
        0030103e ff              ??         FFh
        0030103f ff              ??         FFh
        00301040 62              ??         62h    b
        00301041 00              ??         00h
        00301042 00              ??         00h
        00301043 00              ??         00h
        00301044 6c              ??         6Ch    l
        00301045 00              ??         00h
        00301046 00              ??         00h
        00301047 00              ??         00h
        00301048 72              ??         72h    r
        00301049 00              ??         00h
        0030104a 00              ??         00h
        0030104b 00              ??         00h
        0030104c ff              ??         FFh
        0030104d ff              ??         FFh
        0030104e ff              ??         FFh
        0030104f ff              ??         FFh
        00301050 ff              ??         FFh
        00301051 ff              ??         FFh
        00301052 ff              ??         FFh
        00301053 ff              ??         FFh
        00301054 ff              ??         FFh
        00301055 ff              ??         FFh
        00301056 ff              ??         FFh
        00301057 ff              ??         FFh
        00301058 ff              ??         FFh
        00301059 ff              ??         FFh
        0030105a ff              ??         FFh
        0030105b ff              ??         FFh
        0030105c ff              ??         FFh
        0030105d ff              ??         FFh
        0030105e ff              ??         FFh
        0030105f ff              ??         FFh
        00301060 ff              ??         FFh
        00301061 ff              ??         FFh
        00301062 ff              ??         FFh
        00301063 ff              ??         FFh
        00301064 61              ??         61h    a
        00301065 00              ??         00h
        00301066 00              ??         00h
        00301067 00              ??         00h
        00301068 65              ??         65h    e
        00301069 00              ??         00h
        0030106a 00              ??         00h
        0030106b 00              ??         00h
        0030106c 69              ??         69h    i
```

Here we can see that the character `f` is stored at `00301024`. This will output `1` since `((0x00301024 - 0x00301020) / 4) = 1` (`0x00301020` is the start of the array). This also corresponds to the first byte of the `desiredOutput` array, since it is `1`. The second byte is `0x9`, so the character that should correspond to it is `(0x00301020 + (4*9)) = 0x301044`, and we can see that the character there is `l`:

```
        00301044 6c              ??         6Ch    l
        00301045 00              ??         00h
        00301046 00              ??         00h
        00301047 00              ??         00h
        00301048 72              ??         72h    r
```

So the second character is `l`. Moving on through the rest of the list, we can find the full string `flag{we_beleaf_in_your_re_future}`:

```
$    ./beleaf
Enter the flag
>>> flag{we_beleaf_in_your_re_future}
Correct!
```

Just like that, we solved the challenge!
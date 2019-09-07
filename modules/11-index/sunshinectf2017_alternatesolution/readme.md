# Sunshine CTF 2017 Alternate Solution

Let's take a look at the binary. Also a bit of a spoiler, this isn't exactly index related however at the time this is the best place I thought to put this (and I didn't want to make an entire module for this):

```
$    file alternate_solution
alternate_solution: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=71145a1bcd538b6d000dfce2357c01cfe53a3db9, not stripped
$    pwn checksec alternate_solution
[*] '/Hackery/pod/modules/index/sunshinectf2017_alternatesolution/alternate_solution'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./alternate_solution
15935728
Too high just like your hopes of reaching the bottom.
```

So we can see that we are dealing with a `64` bit binary. When we look at the main function in Ghidra we see this:

```

undefined8 main(void)

{
  long lVar1;
  FILE *flagFile;
  char *pcVar2;
  long in_FS_OFFSET;
  double inpFloat;
  char input [10];
  char flagBuf [56];
  long canary;
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(input,10,stdin);
  inpFloat = atof(input);
  if ((float)inpFloat < 37.35928345) {
    puts("Too low just like you\'re chances of reaching the bottom.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (37.35928345 < (float)inpFloat) {
    puts("Too high just like your hopes of reaching the bottom.");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  flagFile = fopen("flag.txt","r");
  while( true ) {
    pcVar2 = fgets(flagBuf,0x32,flagFile);
    if (pcVar2 == (char *)0x0) break;
    printf("%s",flagBuf);
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So we can see that the input we gave it is converted to a float. If it is greater than or less than `37.35928345`, the program will exit. We can see that if it doesn't exit, then it will scan in the contents of `flag.txt` and print it (thus we get the flag). However there is one issue. The value `37.35928345` contains more decimal places than a float handles, so we can get the number `37.35928345` to pass those checks:

```
$    ./alternate_solution
37.35928345
Too low just like you're chances of reaching the bottom.
```

So we can't pass in the number `37.35928345` which is the only number not greater than or less than `37.35928345`. However we can still fail both checks. Floats have a special value called `nan` (stands for not a number). If the float is not a number, it will not be greater than, less than, or equal to `37.35928345` since it isn't a number. With that we can fail both checks and get the flag:

```
$    ./alternate_solution
nan
sun{50m3times yoU_h@v3_t0 get cr3@t1v3}
```

Just like that, we got the flag. Also this is another challenge I made for Sunshine CTF back in 20117.
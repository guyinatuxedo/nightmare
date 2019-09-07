# Sunshine CTF 2017 Prepared

Let's take a look at the binary:

```
$    pwn checksec prepared
[*] '/Hackery/pod/modules/bad_seed/sunshinectf17_prepared/prepared'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    file prepared
prepared: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=9cd9483ed0e7707d3addd2de44da60d2575652fb, not stripped
$    ./prepared
0 days without an incident.
159
Well that didn't take long.
You should have used 13.
```

So we can see that we are dealing with a 64 bit binary that prompts us for input. Looking at the main function in Ghidra, we see this:

```

undefined8 main(void)

{
  long lVar1;
  int randVal;
  int check;
  time_t time;
  FILE *flagFile;
  char *pcVar2;
  long in_FS_OFFSET;
  uint i;
  char flag [64];
  char input [512];
  char target [504];
  long stackCanary;
 
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  time = time((time_t *)0x0);
  srand((uint)time);
  i = 0;
  while ((int)i < 0x32) {
    randVal = rand();
    printf("%d days without an incident.\n",(ulong)i);
    sprintf(target,"%d",(ulong)(uint)(randVal % 100));
    __isoc99_scanf(" %10s",input);
    strtok(input,"\n");
    check = strcmp(target,input);
    if (check != 0) {
      puts("Well that didn\'t take long.");
      printf("You should have used %s.\n",target);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    i = i + 1;
  }
  puts("How very unpredictable. Level Cleared");
  flagFile = fopen("flag.txt","r");
  while( true ) {
    pcVar2 = fgets(flag,0x32,flagFile);
    if (pcVar2 == (char *)0x0) break;
    printf("%s",flag);
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So we can see, this is pretty similar to the other challenges in this module. It declares time as a seed with the `srand` function, then uses `rand` to generate values (that are modded by 100) that we have to guess in a loop that will run `50` times. So we have to guess what number `rand` will generate 50 times in a row.

Luckily for us, the value `rand` generate is directly based off of the seed. So if we have the same seed, we can generate the same sequence of numbers. Also since the seed is the current time, we know what the seed is. With this we can just write a simple C program which will use time as a seed and generate the numbers it expects:

```
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

int main(void)    
{
    int i, out;
    time_t var0 = time(NULL);
    srand(var0);

    for (i = 0; i < 50; i++)
    {
        out = rand() % 100;
        printf("%d\n", out);
    }
    
    return 0;
}
```

When we run it:

```
$    ./solve | ./prepared
0 days without an incident.
1 days without an incident.
2 days without an incident.
3 days without an incident.
4 days without an incident.
5 days without an incident.
6 days without an incident.
7 days without an incident.
8 days without an incident.
9 days without an incident.
10 days without an incident.
11 days without an incident.
12 days without an incident.
13 days without an incident.
14 days without an incident.
15 days without an incident.
16 days without an incident.
17 days without an incident.
18 days without an incident.
19 days without an incident.
20 days without an incident.
21 days without an incident.
22 days without an incident.
23 days without an incident.
24 days without an incident.
25 days without an incident.
26 days without an incident.
27 days without an incident.
28 days without an incident.
29 days without an incident.
30 days without an incident.
31 days without an incident.
32 days without an incident.
33 days without an incident.
34 days without an incident.
35 days without an incident.
36 days without an incident.
37 days without an incident.
38 days without an incident.
39 days without an incident.
40 days without an incident.
41 days without an incident.
42 days without an incident.
43 days without an incident.
44 days without an incident.
45 days without an incident.
46 days without an incident.
47 days without an incident.
48 days without an incident.
49 days without an incident.
How very unpredictable. Level Cleared
isun{pr3d1ct_3very_p[]5s1bl3_scen@r10}
```

Just like that, we got the flag. Also fun fact, this was a challenge I made back for Sunshine CTF 2017.

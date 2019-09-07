#	h3 time

Let's take a look at the binary:

```
$	file time 
time: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=4972fe3e2914c74bc97f0623f0c4643c40300dab, not stripped
$	pwn checksec time 
[*] '/Hackery/pod/modules/bad_seed/h3_time/time'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
$	./time 
Welcome to the number guessing game!
I'm thinking of a number. Can you guess it?
Guess right and you get a flag!
Enter your number: 15935728
Your guess was 15935728.
Looking for 1618853741.
Sorry. Try again, wrong guess!
```

So we can see that we are dealing with a 64 bit binary. When we run it, it prompts us to guess a number. When we take a look at the main function in Ghidra, we see this:

```
undefined8 main(void)

{
  long lVar1;
  uint targetNumber;
  time_t time;
  long in_FS_OFFSET;
  uint input;
  uint randomValue;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  time = time((time_t *)0x0);
  srand((uint)time);
  targetNumber = rand();
  puts("Welcome to the number guessing game!");
  puts("I\'m thinking of a number. Can you guess it?");
  puts("Guess right and you get a flag!");
  printf("Enter your number: ");
  fflush(stdout);
  __isoc99_scanf(&fmtString,&input);
  printf("Your guess was %u.\n",(ulong)input);
  printf("Looking for %u.\n",(ulong)targetNumber);
  fflush(stdout);
  if (targetNumber == input) {
    puts("You won. Guess was right! Here\'s your flag:");
    giveFlag();
  }
  else {
    puts("Sorry. Try again, wrong guess!");
  }
  fflush(stdout);
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So we can see it generates a random number using the `rand` function. It then prompts us for input using `scanf` with the `%u` format string stored in `fmtString` (double click on `fmtString` in the assembly to see it). Then it checks if the two number are the same, and if they are it will run the `giveFlag` function which when we look at it, we can see that it reads prints out the flag file from `/home/h3/flag.txt`:

```
void giveFlag(void)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_118 [264];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  memset(local_118,0,0x100);
  __stream = fopen("/home/h3/flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("Flag file not found!  Contact an H3 admin for assistance.");
  }
  else {
    fgets(local_118,0x100,__stream);
    fclose(__stream);
    puts(local_118);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So we need to figure out what the output of the `rand` function will be. Thing is the output of the `rand` function is not actually random. The output is based off a value called a seed, which it uses to determine what number sequence to generate. So if we can get the same seed, we can get `rand` to generate the same sequence of numbers. Looking at the decompiled code, we see that it uses the current time as a seed:

```
  time = time((time_t *)0x0);
  srand((uint)time);
```

So if we just write a simple C program to use the current time as a seed, and output a digit and redirect the output to the target, we will solve the challenge:

```
#include<stdio.h>
#include<time.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

int main()
{
    uint32_t rand_num;
    srand(time(0)); //seed with current time
    rand_num = rand();
    uint32_t ans;
    printf("%d\n", rand_num);	
}
```

When we compile and run it:

```
$	cat solve.c 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

int main()
{
    uint32_t rand_num;
    srand(time(0)); 
    rand_num = rand();
    uint32_t ans;
    printf("%d\n", rand_num);	
}
$	gcc solve.c -o solve
$	./solve | ./time 
Welcome to the number guessing game!
I'm thinking of a number. Can you guess it?
Guess right and you get a flag!
Enter your number: Your guess was 1075483710.
Looking for 1075483710.
You won. Guess was right! Here's your flag:
Flag file not found!  Contact an H3 admin for assistance.
```

We can see that we solved it. It didn't print the flag since the file `/home/h3/flag.txt` does not exist, however it prints out an error message seen in the `giveFlag` function so we know that we solved it.
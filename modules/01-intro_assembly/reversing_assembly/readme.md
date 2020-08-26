# Assembly Reversing Problems

These are some basic assembly reversing problems from: https://github.com/kablaa/CTF-Workshop/blob/master/Reversing/Challenges/IfThen/if_then

The purpose of these challenges is to get some experience reversing assembly code. Try to figure out what the binaries are doing. To view disassembly machine code into assembly code, you can use something like `objdump`.

## Hello World

First let's take a look at the assembly code:
```
$    objdump -D hello_world -M intel | less
```

After searching through for the string `main` to find the main function, we see this:

```
080483fb <main>:
 80483fb:       8d 4c 24 04             lea    ecx,[esp+0x4]
 80483ff:       83 e4 f0                and    esp,0xfffffff0
 8048402:       ff 71 fc                push   DWORD PTR [ecx-0x4]
 8048405:       55                      push   ebp
 8048406:       89 e5                   mov    ebp,esp
 8048408:       51                      push   ecx
 8048409:       83 ec 04                sub    esp,0x4
 804840c:       83 ec 0c                sub    esp,0xc
 804840f:       68 b0 84 04 08          push   0x80484b0
 8048414:       e8 b7 fe ff ff          call   80482d0 <puts@plt>
 8048419:       83 c4 10                add    esp,0x10
 804841c:       b8 00 00 00 00          mov    eax,0x0
 8048421:       8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 8048424:       c9                      leave  
 8048425:       8d 61 fc                lea    esp,[ecx-0x4]
 8048428:       c3                      ret    
 8048429:       66 90                   xchg   ax,ax
 804842b:       66 90                   xchg   ax,ax
 804842d:       66 90                   xchg   ax,ax
 804842f:       90                      nop
```

Looking at the code, we see a function call to `puts`:

```
push   0x80484b0
call   80482d0 <puts@plt>
```

Looking through the rest of the code, we really don't see much else that is interesting for our perspective. So this code probably just prints a string. When we run the binary, we see that is correct:

```
$    ./hello_world
hello world!
```

## If then

We start off by viewing the assembly code with `objdump`:

```
$    objdump -D if_then -M intel | less
```

After parsing through for the `main` function, we see this.

```
080483fb <main>:
 80483fb:       8d 4c 24 04             lea    ecx,[esp+0x4]
 80483ff:       83 e4 f0                and    esp,0xfffffff0
 8048402:       ff 71 fc                push   DWORD PTR [ecx-0x4]
 8048405:       55                      push   ebp
 8048406:       89 e5                   mov    ebp,esp
 8048408:       51                      push   ecx
 8048409:       83 ec 14                sub    esp,0x14
 804840c:       c7 45 f4 0a 00 00 00    mov    DWORD PTR [ebp-0xc],0xa
 8048413:       83 7d f4 0a             cmp    DWORD PTR [ebp-0xc],0xa
 8048417:       75 10                   jne    8048429 <main+0x2e>
 8048419:       83 ec 0c                sub    esp,0xc
 804841c:       68 c0 84 04 08          push   0x80484c0
 8048421:       e8 aa fe ff ff          call   80482d0 <puts@plt>
 8048426:       83 c4 10                add    esp,0x10
 8048429:       b8 00 00 00 00          mov    eax,0x0
 804842e:       8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 8048431:       c9                      leave  
 8048432:       8d 61 fc                lea    esp,[ecx-0x4]
 8048435:       c3                      ret    
 8048436:       66 90                   xchg   ax,ax
 8048438:       66 90                   xchg   ax,ax
 804843a:       66 90                   xchg   ax,ax
 804843c:       66 90                   xchg   ax,ax
 804843e:       66 90                   xchg   ax,ax
```

We can see that it loads the value `0xa` into `ebp-0xc`:

```
mov    DWORD PTR [ebp-0xc],0xa
```

Immediately proceeding that, we see that it runs a `cmp` instruction on it to check if it is equal. If they are not equal it will jump to `main+0x2e`. Since it was just loaded with the value `0xa`, it should not make the jump:

```
cmp    DWORD PTR [ebp-0xc],0xa
jne    8048429 <main+0x2e>
```

proceeding that it should make a call to puts:
```
sub    esp,0xc
push   0x80484c0
call   80482d0 <puts@plt>
```

So after looking at this code, we see that it should make that `puts` call. When we run it, we see that is what it does:

```
$    ./if_then
x = ten
```

## Loop

Let's take a look at the assembly code:

```
$    objdump -D loop -M intel | less
```

Quickly searching for the main function, we find it:

```
080483fb <main>:
 80483fb:       8d 4c 24 04             lea    ecx,[esp+0x4]
 80483ff:       83 e4 f0                and    esp,0xfffffff0
 8048402:       ff 71 fc                push   DWORD PTR [ecx-0x4]
 8048405:       55                      push   ebp
 8048406:       89 e5                   mov    ebp,esp
 8048408:       51                      push   ecx
 8048409:       83 ec 14                sub    esp,0x14
 804840c:       c7 45 f4 00 00 00 00    mov    DWORD PTR [ebp-0xc],0x0
 8048413:       eb 17                   jmp    804842c <main+0x31>
 8048415:       83 ec 08                sub    esp,0x8
 8048418:       ff 75 f4                push   DWORD PTR [ebp-0xc]
 804841b:       68 c0 84 04 08          push   0x80484c0
 8048420:       e8 ab fe ff ff          call   80482d0 <printf@plt>
 8048425:       83 c4 10                add    esp,0x10
 8048428:       83 45 f4 01             add    DWORD PTR [ebp-0xc],0x1
 804842c:       83 7d f4 13             cmp    DWORD PTR [ebp-0xc],0x13
 8048430:       7e e3                   jle    8048415 <main+0x1a>
 8048432:       b8 00 00 00 00          mov    eax,0x0
 8048437:       8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 804843a:       c9                      leave  
 804843b:       8d 61 fc                lea    esp,[ecx-0x4]
 804843e:       c3                      ret    
 804843f:       90                      nop
```

In this function, we can see that it will initialize a stack variable at `ebp-0xc` to `0`, then jump to `0x804842c` (`main+0x31`):

```
mov    DWORD PTR [ebp-0xc],0x0
jmp    804842c <main+0x31>
```

Looking at the instructions at `0x804842c` we see this:

```
cmp    DWORD PTR [ebp-0xc],0x13
jle    8048415 <main+0x1a>
```

We see that it compares the stack value at `ebp-0xc` against `0x13`, and if it is less than or equal then it will jump to `0x8048415` (`0x80483fb + 0x1a`). That brings us to a printf call:

```
sub    esp,0x8
push   DWORD PTR [ebp-0xc]
push   0x80484c0
call   80482d0 <printf@plt>
```

It looks like it is printing out the contents of `ebp-0xc` in some sort of format string. After that we can see that it increments the value of `ebp-0xc`, before doing the `cmp` again:

```
add    DWORD PTR [ebp-0xc],0x1
```

So right, putting all of the pieces together, now we are probably looking at a for loop that will run `20` times, and print the iteration counter each time. Something that looks similar to this:

```
int i = 0;
for (i = 0; i < 20; i ++)
{
    printf("%d", i);
}
```

When we run the binary, we see that it is true:

```
$    ./loop
0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19
```

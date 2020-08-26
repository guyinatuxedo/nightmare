# pico ctf 2018 strings

The goal of this challenge is to find the flag

Let's take a look at the binary:

```
$    file strings
strings: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e337b489c47492dd5dff90353eb227b4e7e69028, not stripped
$    ./strings
Have you ever used the 'strings' function? Check out the man pages!
```

So we can see that we are dealing with a `64` bit binary. When we run it, it tells us about `strings`. Strings is a program which will parse through a file, and display ascii strings it finds. Ghidra, binja, and a lot of other binary analysis tools also have this functionality. Let's try using `strings`

```
$    strings strings | grep {
picoCTF{sTrIngS_sAVeS_Time_3f712a28}
```

Like that, we found the flag! The flag was stored as a string within the binary, so using `strings` we can see it.
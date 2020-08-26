# Csaw 2018 Tour of x86 pt 1

The goal of this challenge is to answer the following questions.

Starting off this challenge is meant to teach beginners a little bit about x86. The questions were only up during the competition, so I had to grab the questions that were asked from `https://github.com/mohamedaymenkarmous/CTF/tree/master/CSAWCTFQualificationRound2018#a-tour-of-x86---part-1`.

These questions are in regards to the `stage1.asm` file in this directory. That is just a text file which contains assembly code.

#### What is the value of dh after line 129 executes?

Line `129` is:
```
  xor dh, dh  ; <- Question 1
```

This command is xoring the `dh` register with itself, and stores the value in the `dh` register. Due to how the binary operation xoring works, whenever you xor something by itself the result is 0. So the value of dh after line 129 executes is `0x0`.

#### What is the value of gs after line 145 executes?

Line `145` is:
```
  mov gs, dx ; to use them to help me clear     <- Question 2
```

With this instruction the contents of the `dx` register get moved into the `gs` register. So we need to know the contents of the `dx` register. Looking a bit further up in the code, we see this (lines `131` and `132`):

```
  mov dx, 0xffff  ; Hexadecimal
  not dx
```

Here we see that the value `0xffff` is moved into the `dx` register, then noted. When a value is notted, the bits are flopped. And since with the value `0xffff`, all of the bits are `1s` (for 16 bit values), the result of `dx` will be zero. Also we see that between lines `132` and `145`, there is nothing that would change the value of `dx` to something other than `0x0`. So when the contents of `dx` gets moved into `gs`, the value of `gs` has to be `0x0`.

#### What is the value of si after line 151 executes?

Line `151` is:
```
  mov si, sp ; Source Index       <- Question 3
```

So for this just moves the value of the Stack Pointer register into the Source Index register. In order to know what the value of `si` is after this, we need to know what the value of `sp` is. Looking up in the code, we see this on line `149`:

```
  mov sp, cx ; Stack Pointer
```

So we know that the value of the `sp` register is equal to that of the `cx` register. Looking further up in the code, we see a comment telling us what it is (line 144):

```
  mov fs, cx ; already zero, I'm just going
```

And when we look at line 107, we can see where the register `cx` gets the value `0x0` assigned to it:

```
  mov cx, 0 ; The other two values get overwritten regardless, the value of ch and cl (the two components that make up cx) after this instruction are both 0, not 1.
```


#### What is the value of ax after line 169 executes?

Lines `168-169` are:
```
  mov al, 't'
  mov ah, 0x0e      ; <- question 4
```

This moves the value `0x0e` into the `ah` register, and moves the value `0x74` (hex for `t`) into the `al` register. Now the question asks about the `ax` register, which is a `16` bit register, comprised of the two `8` bit registers `al` and `ah`. Here is how this works:

 15 14 13 12 11 10 9  8  7  6  5  4  3  2  1  0                  
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                         |                        |
|           AH          |            AL            |
|                       |                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

The diagram above shows the 16 bits of the `ax` register. The lower 8 bits are comprised of the `al` register. The higher 8 bits are comprised of the `ah` register. Since the `al` register is equal to `0x74`, and the `ah` register is equal to `0x0e`, the `ax` register is equal to `0x0e74`.

#### What is the value of ax after line 199 executes for the first time?

Line `199` is:
```
    mov ah, 0x0e  ; <- Question 5!
```

So we see here that the value `0x0e` is loaded into the `ah` register. So from the previous question, we know that the higher 8 bits of the `ax` register must be equal to `0x0e`. That just leaves the question of the lower 8 bits. Looking at line 197 tells us the value which will be stored in the `al` register (lower 8 bits):

```
    mov al, [si]  ; Since this is treated as a dereference of si, we are getting the BYTE AT si... `al = *si`
```

Looking here we can see that the dereferenced value of `si` is moved into `al`. So whatever value `si` is pointing to, is now the new value in the `al` register. Looking at line `189` helps with that:

```
    mov si, ax  ; We have no syntactic way of passing parameters, so I'm just going to pass the first argument of a function through ax - the string to print.
```

Here we see that the contents of `ax` is moved into `si`. Looking around a bit more we see this.

```
  ; First let's define a string to print, but remember...now we're defining junk data in the middle of code, so we need to jump around it so there's no attempt to decode our text string
  mov ax, .string_to_print
```

So here we see that an address to a string is loaded into the `ax` register. We can also see what string the address points to.

```
.string_to_print: db "acOS", 0x0a, 0x0d, "  by Elyk", 0x00  ; label: <size-of-elements> <array-of-elements>
```

and lastly we can just take a quick look at the entire loop where line `199` resides:

```
; Now let's make a whole 'function' that prints a string
print_string:
  .init:
    mov si, ax  ; We have no syntactic way of passing parameters, so I'm just going to pass the first argument of a function through ax - the string to print.

  .print_char_loop:
    cmp byte [si], 0  ; The brackets around an expression is interpreted as "the address of" whatever that expression is.. It's exactly the same as the dereference operator in C-like languages
                        ; So in this case, si is a pointer (which is a copy of the pointer from ax (line 183), which is the first "argument" to this "function", which is the pointer to the string we are trying to print)
                        ; If we are currently pointing at a null-byte, we have the end of the string... Using null-terminated strings (the zero at the end of the string definition at line 178)
    je .end
   
    mov al, [si]  ; Since this is treated as a dereference of si, we are getting the BYTE AT si... `al = *si`

    mov ah, 0x0e  ; <- Question 5!
    int 0x10      ; Actually print the character
 
    inc si        ; Increment the pointer, get to the next character
    jmp .print_char_loop
    .end:
```

Here is a loop that is printing all of the characters of the string. At the start of this loop the pointer points to the beginning of the string (line 197), then gets incremented (line 202) by one meaning that it moves on to the next character untill it hits the null byte (`0x0`), which the comparison happens at line 192. It will print each character with the interrupt a line `200` (check out https://en.wikipedia.org/wiki/INT_10H for more info, the value `0x0e` in the `ah` register is an argument to the interrupt). Since the first character of the string is `a` which in hex is `0x61`, the value of `al` the first time it is ran should be `0x61`. So the value of the `ax` register should be `0x0e61`.

# Csaw 2016 Quals Gametime

Let's take a look at the binary:

```
$    file gametime.exe
gametime.exe: PE32 executable (console) Intel 80386, for MS Windows
```

So we are just given a 32 bit Windows executable . When we run the game in windows, we see that it prompts us to press certain keys when it displays certain letters (like press `m` when it displays `m`). Now it is actually possible to play the game and get the flag without hacking it, however we won't do that.

So we can see that is a 32 bit Windows Executable. When we look at in Ghidra at the binary we see two strings that can be of interest to us:

```
                             s__UDDER_FAILURE!_http://imgur.com_00417a80     XREF[1]:     FUN_00401435:004014f2(*)  
        00417a80 0d 55 44        ds         "\rUDDER FAILURE! http://imgur.com/4Ajx21P \n"
                 44 45 52
                 20 46 41
        00417aab 00              ??         00h
                             s__00417aac                                     XREF[1]:     FUN_00401507:00401526(*)  
        00417aac 0d 20 20        ds         "\r                                 \r"
                 20 20 20
                 20 20 20
                             s_UDDER_FAILURE!_http://imgur.com/_00417ad0     XREF[1]:     FUN_00401507:00401575(*)  
        00417ad0 55 44 44        ds         "UDDER FAILURE! http://imgur.com/4Ajx21P \n"
                 45 52 20
                 46 41 49
```

For now it should be safe to assume that this is a failure message, displayed when you loose the game. When we check the references to the to see where the first string is reference, we see that it is called after a test instruction like this (and the second string is referenced in a similar fashion):

```
                             LAB_004014ca                                    XREF[1]:     004014ad(j)  
        004014ca ba a0 86        MOV        param_2,0x186a0
                 01 00
        004014cf 8b ce           MOV        param_1,ESI
        004014d1 e8 8a fd        CALL       FUN_00401260                                     int FUN_00401260(int param_1, in
                 ff ff
        004014d6 5f              POP        EDI
        004014d7 5e              POP        ESI
        004014d8 5b              POP        EBX
        004014d9 84 c0           TEST       AL,AL
        004014db 75 26           JNZ        LAB_00401503
```

We see in both instances that if the output of the `test` instruction is not 0, we can continue playing the game. So we should be able to edit the assembly code to change the `jnz` to `jz`, that way if we don't do anything, the output of the `test` instruction should be 0 and we should be able to continue playing the game. We can see that the two functions which these two strings are called are at `0x401435` and `0x401507` (at the very beginning of the viewing the assembly code in proximity view we can see the function it is a part of).

We can edit it using Binary Ninja (or you can edit it using a different hex editor, although Binary Ninja is a lot more than a hex editor). There is a free version that we can use for personal use, and it is a great tool for patching binaries. To edit it in Binary Ninja, just open the executable in it, go to each of the two functions (at `0x401507` and `0x401435`), right click on the line we want to edit, go to Patch->Edit Current Line and then just change `jne` to `je`. Lastly just save it. After that you should just be able to run the exe in windows, not give it any input, and eventually it will print the flag (which isn't in the standard format, and may take a little bit):

```
key is <no5c30416d6cf52638460377995c6a8cf5>
```

Just like that, we get the flag which is `no5c30416d6cf52638460377995c6a8cf5`.
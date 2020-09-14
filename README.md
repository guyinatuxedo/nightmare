# Nightmare

Nightmare is an intro to binary exploitation / reverse engineering course based around ctf challenges. I call it that because it's a lot of people's nightmare to get hit by weaponized 0 days, which these skills directly translate into doing that type of work (plus it's a really cool song).

## What makes Nightmare different?

It's true there are a lot of resources out there to learn binary exploitation / reverse engineering skills, so what makes this different?

```
*    Amount of Content             -    There is a large amount of content in this course (currently over 90 challenges), laid out in a linear fashion.

*    Well Documented Write Ups         -    Each challenge comes with a well documented writeup explaining how to go from being handed the binary to doing the exploit dev.

*    Multiple Problems per Topic     -    Most modules have multiple different challenges. This way you can use one to learn how the attack works, and then apply it to the others. Also different iterations of the problem will have knowledge needed to solve it.

*    Using all open source tools     -    All the tools used here are free and open sourced. No IDA torrent needed.

*    A Place to Ask Questions         -    So if you have a problem that you've been working for days and can't get anywhere (and google isn't helping).
```

I have found that resources that have many of these things to be few and far between. As a result it can make learning these skills difficult since you don't really know what to learn, or how to learn it. This is essentially my attempt to help fix some of those problems.
## Static Site

If you want, there is a static github pages site which people say looks better: https://guyinatuxedo.github.io/

## Github

A copy of all of the challenges listed, can be found on the github: https://github.com/guyinatuxedo/nightmare

## Special Thanks

Special thanks to these people:

```
noopnoop     -    For dealing with me
digitalcold  -    For showing me how good nightmare could look with mdbook
you nerds     -    For looking at this
```

## Discord

If you get stuck on something for hours on end and google can't answer your question, try asking in the discord (or if you just feel like talking about cool security things). Here is a link to it `https://discord.gg/p5E3VZF`

Also if you notice any typos or mistakes, feel free to mention it in the Discord. With how much content is here, there is bound to be at least one.

# Index

Here is the index for all of the content in this course. Feel free to go through the whole thing, or only parts of it (don't let me tell you how to live your life). For the order that you do the challenges in a module, I would recommend starting with the first.


## Intro Departure

#### 0.) Intro to the Project    

#### 1.) Intro to Assembly     
-    Intro to assembly
-    Sample assembly reverse challs

#### 2.) Intro to Tooling     
-    gdb-gef     
-    pwntools
-    ghidra

#### 3.) Beginner RE     
-    pico18_strings     
-    helithumper_re
-    csaw18_tourofx86pt1     
-    csaw19_beleaf

## Stack pt 0 Stack Tendencies

#### 4.) Buffer Overflow of Variables

-    Csaw18/boi
-    TokyoWesterns17/just_do_it
-    Tamu19_pwn1

#### 5.) Buffer Overflow Call Function
-    Csaw18_getit     
-    Tu17_vulnchat
-    Csaw16_warmup

#### 5.1) aslr/pie intro     
-    quick aslr/pie explanation

#### 6.) Buffer Overflow Call Shellcode
-    Tamu19_pwn3  
-    Csaw17_pilot
-    Tu18_shelleasy  

#### 6.1) nx intro     
-    nx explanation

#### 7.) ROP Chain Statically compiled
-    dcquals19_speedrun1
-    bkp16_simplecalc
-    dcquals16_feedme

#### 7.1) stack canary intro     
-    stack canary introduction

#### 7.2) relro intro     
-    relro introduction

#### 8.) ROP Dynamically Compiled
-    csaw17_svc    
-    fb19_overfloat    
-    hs19_storytime    
-    csaw19_babyboi
-    utc19_shellme

## General pt 0 Stardust Challenges

#### 9.) Bad Seed     
-    h3_time      
-    hsctf19_tuxtalkshow        
-    sunshinectf17_prepared    


#### 10.) Format strings     
-    backdoor17_bbpwn  
-    twesterns16_greeting
-    pico_echo
-    watevr19_betstar

#### 11.) Index Array    
-    dcquals16_xkcd
-    sawmpctf19_dreamheaps
-    sunshinectf2017_alternativesolution

#### 12.) Z3    
-    tokyowesterns17_revrevrev        
-    tuctf_future    
-    hsctf19_abyte    

#### 13.) Angr    
-    securityfest_fairlight    
-    plaid19_icancount
-    defcamp15_r100

## Stack pt 1 Return to Stack, truly a perfect game

#### 14.) Ret2system     
-    asis17_marymorton    
-    hxp18_poorcanary    
-    tu_guestbook

#### 15.) Partial Overwrite     
-    Tu17_vulnchat2     
-    Tamu19_pwn2
-    hacklu15_stackstuff

#### 16.) SROP     
-    backdoorctf_funsignals    
-    inctf17_stupiddrop
-    swamp19_syscaller
-    csaw19_smallboi

#### 17.) Stack Pivot / Partial Overwrite
-    defconquals19_speedrun4
-    insomnihack18_onewrite
-    xctf16_b0verfl0w

#### 18.) Ret2Csu / Ret2dl     
-    ropemporium_ret2csu
-    0ctf 2018 babystack

## General pt 1 Armstrong challenges

#### 19.) Shellcoding pt 1    
-    defconquals19_s3    
-    Csaw18_shellpointcode
-    defconquals19_s6

#### 20.) Patching/Jumping    
-    dcquals18_elfcrumble                
-    plaid19_plaid_part_planning_III        
-    csaw16_gametime    


#### 21.) .NET Reversing    
-    csaw13_dotnet        
-    csaw13_bikinibonanza
-    whitehat18_re06

#### 22.) Movfuscation    
-    sawmpctf19_future    
-    asis18quals_babyc    
-    other_movfuscated

#### 23.) Custom Architectures
-    h3_challenge0    
-    h3_challenge1
-    h3_challenge2
-    h3_challenge3

## Heap Pt 0 rip Angel Beats

#### 24.) Basic Heap overflow
-    protostar_heap1
-    protostar_heap0
-    protostar_heap2

#### 25.) Intro to heap exploitation / binning    
-    explanation

#### 26.) Heap Grooming     
-    explanation     
-    swamp19_heapgolf
-    pico_areyouroot  

#### 27.) Edit Freed Chunk (pure explanation)    
-    Use After Free     
-    Double Free     
-    Null Byte Heap Consolidation

#### 28.) Fastbin Attack    
-    explanation     
-    0ctf18_babyheap
-    csaw17_auir    

#### 29.) tcache        
-    explanation
-    dcquals19_babyheap
-    plaid19_cpp        

#### 30.) unlink        
-    explanation
-    hitcon14_stkof    
-    zctf16_note        

#### 31.) Unsorted Bin Attack     
-    explanation
-    hitcon_magicheap     
-    0ctf16_zer0storage     

#### 32.) Large Bin Attack    
-    largebin0_explanation
-    largebin1_explanation

#### 33.) Custom Malloc     
-    csawquals17_minesweeper     
-    csawquals18_AliensVSSamurai
-    csawquals19_traveller

## General Pt 2 Generic Isekai #367

#### 34.) Qemu / Emulated Targets     
-   csaw18_tour_of_x86_pt_2     
-   csaw15_hackingtime             
-   csaw17_realism

#### 35.) Integer Exploitation     
-   puzzle
-   int_overflow_post
-   signed_unsigned_int_expl

#### 36.) Obfuscated Reversing     
-    csaw15_wyvern     
-    csaw17_prophecy
-    bkp16_unholy

#### 37.) FS Exploitation    
-    swamp19_badfile

#### 38.) Grab Bag         
-    csaw18_doubletrouble
-    hackim19_shop        
-    unit_vars_expl
-    csaw19_gibberish

## Heap pt 1 heap x heap

#### 39.) House of Spirit     
-    explanation
-    hacklu14_oreo

#### 40.) House of Lore         
-    explanation

#### 41.) House of Force        
-    explanation
-    bkp16_cookbook

#### 42.) House of Einherjar     
-    explanation

#### 43.) House of Orange     
-    explanation

#### 44.) More tcache
-    csaw19_poppingCaps0
-    csaw19_poppingCaps1

#### 45.) Automatic Exploit Generation
-    csaw20_rop

#### Ending Documentation
-    References
-    What's next



# Csaw 2015 Wyvern

Goal of this challenge is to get the flag, not pop a shell.

Let's take a look at the binary:

```
$    file wyvern
wyvern: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=45f9b5b50d013fe43405dc5c7fe651c91a7a7ee8, not stripped
$    ./wyvern
+-----------------------+
|    Welcome Hero       |
+-----------------------+

[!] Quest: there is a dragon prowling the domain.
    brute strength and magic is our only hope. Test your skill.

Enter the dragon's secret: 15935728

[-] You have failed. The dragon's power, speed and intelligence was greater.
```

So we are dealing with a `64` bit binary, that prompts us for input via stdin. It looks like a normal crackme which scans in data, and checks it.

## Reversing

When we take a look at the main function, we see this:

```
undefined8 main(void)

{
  int dragonBattle;
  basic_string local_148 [8];
  basic_string local_140 [24];
  allocator<char> local_128 [8];
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_120 [8];
  allocator input [268];
 
  operator<<<std--char_traits<char>>((basic_ostream *)cout,"+-----------------------+\n");
  operator<<<std--char_traits<char>>((basic_ostream *)cout,"|    Welcome Hero       |\n");
  operator<<<std--char_traits<char>>((basic_ostream *)cout,"+-----------------------+\n\n");
  operator<<<std--char_traits<char>>
            ((basic_ostream *)cout,"[!] Quest: there is a dragon prowling the domain.\n");
  operator<<<std--char_traits<char>>
            ((basic_ostream *)cout,
             "\tbrute strength and magic is our only hope. Test your skill.\n\n");
  operator<<<std--char_traits<char>>((basic_ostream *)cout,"Enter the dragon\'s secret: ");
  fgets((char *)input,0x101,stdin);
  allocator();
                    /* try { // try from 0040e217 to 0040e230 has its CatchHandler @ 0040e2ee */
  basic_string((char *)local_120,input);
  ~allocator(local_128);
                    /* try { // try from 0040e242 to 0040e254 has its CatchHandler @ 0040e30e */
  basic_string(local_140);
                    /* try { // try from 0040e25a to 0040e265 has its CatchHandler @ 0040e322 */
  dragonBattle = start_quest((basic_string)0xc0);
                    /* try { // try from 0040e27f to 0040e2c1 has its CatchHandler @ 0040e30e */
  ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)local_140);
  if (dragonBattle == 0x1337) {
    basic_string(local_148);
                    /* try { // try from 0040e2c7 to 0040e2d2 has its CatchHandler @ 0040e347 */
    reward_strength((basic_string)0xb8);
                    /* try { // try from 0040e2d8 to 0040e2e3 has its CatchHandler @ 0040e30e */
    ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)local_148);
  }
  else {
                    /* try { // try from 0040e36c to 0040e37e has its CatchHandler @ 0040e30e */
    operator<<<std--char_traits<char>>
              ((basic_ostream *)cout,
               "\n[-] You have failed. The dragon\'s power, speed and intelligence was greater.\n");
  }
  ~basic_string(local_120);
  return 0;
}
```

So we can see that it prompts us for input here:
```
  fgets((char *)input,0x101,stdin);
```

Looking through the code, we can see that it really doesn't do much input checking. It just passes our input to `start_quest`, and checks to see if it's output is `0x1337` (which we will need to figure out how to make that happen to solve this challenge). Also the disassembly shows that our input isn't passed, however that is wrong. We can see that in gdb our input is passed:

```
Breakpoint 1, 0x000000000040e261 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0xa38323735333935  ("5935728\n"?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffdd90  →  0x0000000000000000
$rbp   : 0x00007fffffffdf50  →  0x000000000040e5b0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00007fffffffde38  →  0x00000000006236a8  →  "15935728"
$rdi   : 0x00007fffffffde18  →  0x00000000006236a8  →  "15935728"
$rip   : 0x000000000040e261  →  <main+321> call 0x404350 <_Z11start_questSs>
$r8    : 0x00000000006236a8  →  "15935728"
$r9    : 0x00007ffff7a7ff40  →  0x00007ffff7a7ff40  →  [loop detected]
$r10   : 0x6               
$r11   : 0x00007ffff7ebd150  →  <std::basic_string<char,+0> push rbx
$r12   : 0x00000000004013bb  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe030  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdd90│+0x0000: 0x0000000000000000     ← $rsp
0x00007fffffffdd98│+0x0008: 0x0000000000000000
0x00007fffffffdda0│+0x0010: 0x0000000000000000
0x00007fffffffdda8│+0x0018: 0x0000000000000000
0x00007fffffffddb0│+0x0020: 0x0000000000000000
0x00007fffffffddb8│+0x0028: 0x00007fffffffde30  →  0x0000000000000000
0x00007fffffffddc0│+0x0030: 0x00007fffffffde40  →  "15935728"
0x00007fffffffddc8│+0x0038: 0x00007fffffffde40  →  "15935728"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40e250 <main+304>       call   0x400f20 <_ZNSsC1ERKSs@plt>
     0x40e255 <main+309>       jmp    0x40e25a <main+314>
     0x40e25a <main+314>       lea    rdi, [rbp-0x138]
 →   0x40e261 <main+321>       call   0x404350 <_Z11start_questSs>
   ↳    0x404350 <start_quest(std::string)+0> push   rbp
        0x404351 <start_quest(std::string)+1> mov    rbp, rsp
        0x404354 <start_quest(std::string)+4> push   r15
        0x404356 <start_quest(std::string)+6> push   r14
        0x404358 <start_quest(std::string)+8> push   rbx
        0x404359 <start_quest(std::string)+9> sub    rsp, 0x78
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_Z11start_questSs (
   $rdi = 0x00007fffffffde18 → 0x00000000006236a8 → "15935728",
   $rsi = 0x00007fffffffde38 → 0x00000000006236a8 → "15935728"
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "wyvern", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40e261 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

#### start_quest

So that brings us to the `start_quest` function:

```

/* start_quest(std::basic_string<char, std::char_traits<char>, std::allocator<char>>) */

ulong start_quest(basic_string param_1)

{
  undefined *puVar1;
  uint *puVar2;
  long inputLength;
  undefined *this;
  undefined *puVar3;
  undefined auStack152 [8];
  undefined8 local_90;
  uint local_50;
  bool lenCheck;
 
  puVar3 = auStack152;
  puVar1 = auStack152;
  if ((x25 * (x25 + -1) & 1U) == 0 || y26 < 10) goto LAB_004043a4;
  do {
    puVar3 = puVar1;
    *(undefined8 *)(puVar3 + -8) = 0x404c2c;
    push_back(hero,&secret_100,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404c45;
    push_back(hero,&secret_214,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404c5e;
    push_back(hero,&secret_266,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404c77;
    push_back(hero,&secret_369,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404c90;
    push_back(hero,&secret_417,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404ca9;
    push_back(hero,&secret_527,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404cc2;
    push_back(hero,&secret_622,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404cdb;
    push_back(hero,&secret_733,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404cf4;
    push_back(hero,&secret_847,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404d0d;
    push_back(hero,&secret_942,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404d26;
    push_back(hero,&secret_1054,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404d3f;
    push_back(hero,&secret_1106,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404d58;
    push_back(hero,&secret_1222,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404d71;
    push_back(hero,&secret_1336,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404d8a;
    push_back(hero,&secret_1441,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404da3;
    push_back(hero,&secret_1540,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404dbc;
    push_back(hero,&secret_1589,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404dd5;
    push_back(hero,&secret_1686,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404dee;
    push_back(hero,&secret_1796,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404e07;
    push_back(hero,&secret_1891,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404e20;
    push_back(hero,&secret_1996,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404e39;
    push_back(hero,&secret_2112,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404e52;
    push_back(hero,&secret_2165,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404e6b;
    push_back(hero,&secret_2260,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404e84;
    push_back(hero,&secret_2336,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404e9d;
    push_back(hero,&secret_2412,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404eb6;
    push_back(hero,&secret_2498,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404ecf;
    push_back(hero,&secret_2575,puVar3[-8]);
    *(undefined8 *)(puVar3 + -8) = 0x404ed8;
    local_90 = length(puVar3[-8]);
LAB_004043a4:
    puVar2 = (uint *)(puVar3 + -0x10);
    this = puVar3 + -0x20;
    *(undefined8 *)(puVar3 + -0x48) = 0x4043f5;
    push_back(hero,&secret_100,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40440e;
    push_back(hero,&secret_214,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404427;
    push_back(hero,&secret_266,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404440;
    push_back(hero,&secret_369,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404459;
    push_back(hero,&secret_417,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404472;
    push_back(hero,&secret_527,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40448b;
    push_back(hero,&secret_622,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4044a4;
    push_back(hero,&secret_733,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4044bd;
    push_back(hero,&secret_847,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4044d6;
    push_back(hero,&secret_942,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4044ef;
    push_back(hero,&secret_1054,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404508;
    push_back(hero,&secret_1106,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404521;
    push_back(hero,&secret_1222,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40453a;
    push_back(hero,&secret_1336,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404553;
    push_back(hero,&secret_1441,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40456c;
    push_back(hero,&secret_1540,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404585;
    push_back(hero,&secret_1589,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40459e;
    push_back(hero,&secret_1686,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4045b7;
    push_back(hero,&secret_1796,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4045d0;
    push_back(hero,&secret_1891,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4045e9;
    push_back(hero,&secret_1996,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404602;
    push_back(hero,&secret_2112,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40461b;
    push_back(hero,&secret_2165,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404634;
    push_back(hero,&secret_2260,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40464d;
    push_back(hero,&secret_2336,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404666;
    push_back(hero,&secret_2412,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40467f;
    push_back(hero,&secret_2498,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404698;
    push_back(hero,&secret_2575,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4046a1;
    inputLength = length(puVar3[-0x48]);
    lenCheck = inputLength + -1 != (long)(legend >> 2);
    puVar1 = puVar3 + -0x40;
  } while ((x25 * (x25 + -1) & 1U) != 0 && 9 < y26);
  if (lenCheck) {
    if ((x25 * (x25 + -1) & 1U) == 0 || y26 < 10) goto LAB_00404760;
    do {
      *puVar2 = legend >> 2;
LAB_00404760:
      *puVar2 = legend >> 2;
    } while ((x25 * (x25 + -1) & 1U) != 0 && 9 < y26);
  }
  else {
    if ((x25 * (x25 + -1) & 1U) == 0 || y26 < 10) goto LAB_004047fb;
    do {
      *(undefined8 *)(puVar3 + -0x48) = 0x404f06;
      basic_string(this,puVar3[-0x48]);
LAB_004047fb:
      *(undefined8 *)(puVar3 + -0x48) = 0x404808;
      basic_string(this,puVar3[-0x48]);
    } while ((x25 * (x25 + -1) & 1U) != 0 && 9 < y26);
                    /* try { // try from 0040484b to 00404853 has its CatchHandler @ 004048fb */
    *(undefined8 *)(puVar3 + -0x48) = 0x404854;
    local_50 = sanitize_input((char)this,puVar3[-0x48]);
    if ((x25 * (x25 + -1) & 1U) == 0 || y26 < 10) goto LAB_0040489f;
    do {
      *puVar2 = local_50;
      *(undefined8 *)(puVar3 + -0x48) = 0x404f1d;
      ~basic_string(this,puVar3[-0x48]);
LAB_0040489f:
      *puVar2 = local_50;
      *(undefined8 *)(puVar3 + -0x48) = 0x4048b1;
      ~basic_string(this,puVar3[-0x48]);
    } while ((x25 * (x25 + -1) & 1U) != 0 && 9 < y26);
  }
  do {
  } while ((x25 * (x25 + -1) & 1U) != 0 && 9 < y26);
  return (ulong)*puVar2;
}
```

So looking at this code, it becomes apparant that it has been obfuscated. Obfuscating code means that it has essentially been made harder to reverse and understand what it does. Throughout this code, we see a lot of code segments like this:

```
((x25 * (x25 + -1) & 1U) == 0 || y26 < 10)
```

and this:

```
while ((x25 * (x25 + -1) & 1U) != 0 && 9 < y26)
```

This is a part of the obfuscation. Thing is, in these statements they reference variables like `x25` and `y26`. The thing is, these variables are never given a non-zero value. That way their value is `0`. As a result this expression:

```
((x25 * (x25 + -1) & 1U) == 0 || y26 < 10)
```

really means this:

```
((0 * (0 + -1) & 1U) == 0 || 0 < 10)
```

So realistically, these statements are just a complicated way of stating things like `if (true)`. These statements evaluate to the following:

```
((x25 * (x25 + -1) & 1U) == 0 || y26 < 10)
```

^ evaluates to true

```
((x25 * (x25 + -1) & 1U) != 0 && 9 < y26)
```

^ evaluates to false

So going through and editing the code (I just did this in a text editor) to remove some of the obfuscation, we are left with this:

```

/* start_quest(std::basic_string<char, std::char_traits<char>, std::allocator<char>>) */

ulong start_quest(basic_string param_1)

{
  undefined *puVar1;
  uint *puVar2;
  long inputLength;
  undefined *this;
  undefined *puVar3;
  undefined auStack152 [8];
  undefined8 local_90;
  uint local_50;
  bool lenCheck;
 
  puVar3 = auStack152;
  puVar1 = auStack152;
LAB_004043a4:
    puVar2 = (uint *)(puVar3 + -0x10);
    this = puVar3 + -0x20;
    *(undefined8 *)(puVar3 + -0x48) = 0x4043f5;
    push_back(hero,&secret_100,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40440e;
    push_back(hero,&secret_214,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404427;
    push_back(hero,&secret_266,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404440;
    push_back(hero,&secret_369,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404459;
    push_back(hero,&secret_417,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404472;
    push_back(hero,&secret_527,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40448b;
    push_back(hero,&secret_622,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4044a4;
    push_back(hero,&secret_733,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4044bd;
    push_back(hero,&secret_847,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4044d6;
    push_back(hero,&secret_942,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4044ef;
    push_back(hero,&secret_1054,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404508;
    push_back(hero,&secret_1106,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404521;
    push_back(hero,&secret_1222,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40453a;
    push_back(hero,&secret_1336,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404553;
    push_back(hero,&secret_1441,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40456c;
    push_back(hero,&secret_1540,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404585;
    push_back(hero,&secret_1589,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40459e;
    push_back(hero,&secret_1686,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4045b7;
    push_back(hero,&secret_1796,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4045d0;
    push_back(hero,&secret_1891,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4045e9;
    push_back(hero,&secret_1996,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404602;
    push_back(hero,&secret_2112,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40461b;
    push_back(hero,&secret_2165,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404634;
    push_back(hero,&secret_2260,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40464d;
    push_back(hero,&secret_2336,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404666;
    push_back(hero,&secret_2412,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x40467f;
    push_back(hero,&secret_2498,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x404698;
    push_back(hero,&secret_2575,puVar3[-0x48]);
    *(undefined8 *)(puVar3 + -0x48) = 0x4046a1;
    inputLength = length(puVar3[-0x48]);
    lenCheck = inputLength + -1 != (long)(legend >> 2);
    puVar1 = puVar3 + -0x40;

  if (lenCheck) {

  }
  else {
                    /* try { // try from 0040484b to 00404853 has its CatchHandler @ 004048fb */
    *(undefined8 *)(puVar3 + -0x48) = 0x404854;
    local_50 = sanitize_input((char)this,puVar3[-0x48]);
    if ((x25 * (x25 + -1) & 1U) == 0 || y26 < 10) goto LAB_0040489f;
      *puVar2 = local_50;
      *(undefined8 *)(puVar3 + -0x48) = 0x404f1d;
      ~basic_string(this,puVar3[-0x48]);
LAB_0040489f:
      *puVar2 = local_50;
      *(undefined8 *)(puVar3 + -0x48) = 0x4048b1;
      ~basic_string(this,puVar3[-0x48]);
  }

  return (ulong)*puVar2;
}
```

This looks much readable. Starting off we see `28` calls to `push_back`. Looking at the calls in gdb tell us roughly what they do:

Before the call:
```
Breakpoint 1, 0x0000000000404409 in start_quest(std::string) ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0xffffffff        
$rsp   : 0x00007fffffffdcd0  →  0x0000000000000000
$rbp   : 0x00007fffffffdda0  →  0x00007fffffffdf70  →  0x000000000040e5b0  →  <__libc_csu_init+0> push r15
$rsi   : 0x0000000000610140  →  0x0000010a000000d6
$rdi   : 0x00000000006102f8  →  0x00000000006236c0  →  0x0000000000000064 ("d"?)
$rip   : 0x0000000000404409  →  <start_quest(std::string)+185> call 0x405750 <_ZNSt6vectorIiSaIiEE9push_backERKi>
$r8    : 0x0               
$r9    : 0xffffffff        
$r10   : 0x1               
$r11   : 0xffffff01        
$r12   : 0x00000000004013bb  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe050  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
──────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdcd0│+0x0000: 0x0000000000000000     ← $rsp
0x00007fffffffdcd8│+0x0008: 0x0000000000000000
0x00007fffffffdce0│+0x0010: 0x0000000000000000
0x00007fffffffdce8│+0x0018: 0x0000000000000000
0x00007fffffffdcf0│+0x0020: 0x0000000000000000
0x00007fffffffdcf8│+0x0028: 0x0000000000000000
0x00007fffffffdd00│+0x0030: 0x0000000000000000
0x00007fffffffdd08│+0x0038: 0x0000000000000000
────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4043f0 <start_quest(std::string)+160> call   0x405750 <_ZNSt6vectorIiSaIiEE9push_backERKi>
     0x4043f5 <start_quest(std::string)+165> movabs rdi, 0x6102f8
     0x4043ff <start_quest(std::string)+175> movabs rsi, 0x610140
 →   0x404409 <start_quest(std::string)+185> call   0x405750 <_ZNSt6vectorIiSaIiEE9push_backERKi>
   ↳    0x405750 <std::vector<int,+0> push   rbp
        0x405751 <std::vector<int,+0> mov    rbp, rsp
        0x405754 <std::vector<int,+0> push   r15
        0x405756 <std::vector<int,+0> push   r14
        0x405758 <std::vector<int,+0> push   rbx
        0x405759 <std::vector<int,+0> sub    rsp, 0x38
────────────────────────────────────────────────────── arguments (guessed) ────
_ZNSt6vectorIiSaIiEE9push_backERKi (
   $rdi = 0x00000000006102f8 → 0x00000000006236c0 → 0x0000000000000064 ("d"?),
   $rsi = 0x0000000000610140 → 0x0000010a000000d6
)
────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "wyvern", stopped, reason: BREAKPOINT
──────────────────────────────────────────────────────────────────── trace ────
[#0] 0x404409 → start_quest(std::string)()
[#1] 0x40e266 → main()
───────────────────────────────────────────────────────────────────────────────
gef➤  
```

With the next call, we see this:
```
0x0000000000404422 in start_quest(std::string) ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0xffffffff        
$rsp   : 0x00007fffffffdcd0  →  0x0000000000000000
$rbp   : 0x00007fffffffdda0  →  0x00007fffffffdf70  →  0x000000000040e5b0  →  <__libc_csu_init+0> push r15
$rsi   : 0x0000000000610144  →  0x000001710000010a
$rdi   : 0x00000000006102f8  →  0x00000000006236e0  →  0x000000d600000064 ("d"?)
$rip   : 0x0000000000404422  →  <start_quest(std::string)+210> call 0x405750 <_ZNSt6vectorIiSaIiEE9push_backERKi>
$r8    : 0x0               
$r9    : 0xffffffff        
$r10   : 0x1               
$r11   : 0xffffff01        
$r12   : 0x00000000004013bb  →  <_start+0> xor ebp, ebp
$r13   : 0x00007fffffffe050  →  0x0000000000000001
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
──────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdcd0│+0x0000: 0x0000000000000000     ← $rsp
0x00007fffffffdcd8│+0x0008: 0x0000000000000000
0x00007fffffffdce0│+0x0010: 0x0000000000000000
0x00007fffffffdce8│+0x0018: 0x0000000000000000
0x00007fffffffdcf0│+0x0020: 0x0000000000000000
0x00007fffffffdcf8│+0x0028: 0x0000000000000000
0x00007fffffffdd00│+0x0030: 0x0000000000000000
0x00007fffffffdd08│+0x0038: 0x0000000000000000
────────────────────────────────────────────────────────────── code:x86:64 ────
     0x404409 <start_quest(std::string)+185> call   0x405750 <_ZNSt6vectorIiSaIiEE9push_backERKi>
     0x40440e <start_quest(std::string)+190> movabs rdi, 0x6102f8
     0x404418 <start_quest(std::string)+200> movabs rsi, 0x610144
 →   0x404422 <start_quest(std::string)+210> call   0x405750 <_ZNSt6vectorIiSaIiEE9push_backERKi>
   ↳    0x405750 <std::vector<int,+0> push   rbp
        0x405751 <std::vector<int,+0> mov    rbp, rsp
        0x405754 <std::vector<int,+0> push   r15
        0x405756 <std::vector<int,+0> push   r14
        0x405758 <std::vector<int,+0> push   rbx
        0x405759 <std::vector<int,+0> sub    rsp, 0x38
────────────────────────────────────────────────────── arguments (guessed) ────
_ZNSt6vectorIiSaIiEE9push_backERKi (
   $rdi = 0x00000000006102f8 → 0x00000000006236e0 → 0x000000d600000064 ("d"?),
   $rsi = 0x0000000000610144 → 0x000001710000010a
)
────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "wyvern", stopped, reason: SINGLE STEP
──────────────────────────────────────────────────────────────────── trace ────
[#0] 0x404422 → start_quest(std::string)()
[#1] 0x40e266 → main()
───────────────────────────────────────────────────────────────────────────────
gef➤  
```

So we can see that it is essentially writing one byte of data to an array. Each byte is written to the lowest byte of a four byte segment. We can also see that the byte being written matches the `secret` value with the call. So essentially this is just making an array of `28` bytes, where each byte is stored in a `4` byte segment.

After that we have a check for the length of our input:

```
    inputLength = length(puVar3[-0x48]);
    lenCheck = inputLength + -1 != (long)(legend >> 2);
    puVar1 = puVar3 + -0x40;

  if (lenCheck) {

  }
```

We can see that the value of `legend` is `0x73`:

```
                             legend                                          XREF[5]:     Entry Point(*),
                                                                                          sanitize_input:00401ece(R),
                                                                                          start_quest:004046a7(R),
                                                                                          start_quest:00404760(R),
                                                                                          start_quest:00404ee4(R)  
        00610138 73 00 00 00     undefined4 00000073h
```

`0x73 >> 2 = 28`, which also corresponds to the number of `push_back` calls made earlier. So our input has to be `28` bytes (not counting the null byte). The final portion of the code runs the `sanitize_input` function, and essentially just returns the value of it. The rest of the checks will happen in that function:

```
    local_50 = sanitize_input((char)this,puVar3[-0x48]);
```

Transfers data:

```
      *puVar2 = local_50;
```

Returns it:

```
  return (ulong)*puVar2;
```

#### Sanitize Input

Looking at `sanitize_input` function initially, we see this:

```

/* sanitize_input(std::basic_string<char, std::char_traits<char>, std::allocator<char>>) */

ulong sanitize_input(basic_string param_1)

{
  uint uVar1;
  uint *puVar2;
  undefined4 *this;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined7 in_register_00000039;
  bool bVar5;
  undefined auStack392 [24];
  undefined4 *local_170;
  uint local_144;
  basic_ostream *local_140;
  bool local_136;
  bool local_135;
  bool local_134;
  bool local_133;
  bool local_132;
  uint *local_108;
  long local_100;
  uint local_f8;
  bool local_f2;
  bool local_f1;
  int local_f0;
  bool local_e9;
  int local_e8;
  bool local_e1;
  int *local_e0;
  long local_d8;
  bool local_ca;
  bool local_c9;
  undefined8 local_c8;
  bool local_b9;
  long local_b8;
  bool local_a9;
  char *local_a8;
  bool local_99;
  long local_98;
  bool local_8a;
  bool local_89;
  undefined4 *local_88;
  uint *local_80;
  undefined4 *local_78;
  undefined4 *local_70;
  int *local_68;
  uint *i;
 
  puVar3 = (undefined4 *)auStack392;
  puVar4 = (undefined4 *)auStack392;
  do {
  } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
  if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_00401da6;
  do {
    puVar3 = puVar4 + -0x10;
    *(undefined8 *)(puVar4 + -0x12) = 0x403db1;
    local_170 = puVar3;
    vector(puVar4 + -0xc,*(undefined *)(puVar4 + -0x12));
    *local_170 = 0;
LAB_00401da6:
    puVar2 = puVar3 + -4;
    this = puVar3 + -0xc;
    i = puVar3 + -0x10;
    local_68 = puVar3 + -0x14;
    local_78 = puVar3 + -0x1c;
    local_80 = puVar3 + -0x20;
    local_88 = puVar3 + -0x28;
    puVar4 = puVar3 + -0x2c;
    *(undefined8 *)(puVar3 + -0x2e) = 0x401e2c;
    local_70 = puVar4;
    vector(this,*(undefined *)(puVar3 + -0x2e));
    *i = 0;
  } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
  while( true ) {
    do {
      local_89 = (int)*i < legend >> 2;
    } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
    if (!local_89) goto LAB_00403729;
    do {
      local_8a = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    do {
      do {
        local_98 = (long)(int)*i;
        bVar5 = (x17 * (x17 + -1) & 1U) == 0;
        local_99 = bVar5 || y18 < 10;
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    } while (!bVar5 && y18 >= 10);
    do {
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
                    /* try { // try from 0040217d to 00402879 has its CatchHandler @ 00402e05 */
    *(undefined8 *)(puVar3 + -0x2e) = 0x40218d;
    local_a8 = (char *)operator[](CONCAT71(in_register_00000039,param_1),local_98,
                                  *(undefined *)(puVar3 + -0x2e));
    if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_004021dc;
    do {
      if ((x3 * (x3 + -1) & 1U) == 0 || y4 < 10) goto LAB_00403e10;
      do {
        *local_68 = (int)*local_a8;
LAB_00403e10:
        *local_68 = (int)*local_a8;
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
LAB_004021dc:
      *local_68 = (int)*local_a8;
    } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
    do {
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    *(undefined8 *)(puVar3 + -0x2e) = 0x4022c4;
    push_back(this,local_68,*(undefined *)(puVar3 + -0x2e));
    do {
      local_a9 = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    if (local_a9) goto LAB_0040239d;
    do {
      *local_80 = *i;
LAB_0040239d:
      if ((x3 * (x3 + -1) & 1U) == 0 || y4 < 10) goto LAB_004023e0;
      do {
        *local_80 = *i;
LAB_004023e0:
        *local_80 = *i;
        local_b8 = (long)(int)*local_80;
        bVar5 = (x17 * (x17 + -1) & 1U) == 0;
        local_b9 = bVar5 || y18 < 10;
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    } while (!bVar5 && y18 >= 10);
    *(undefined8 *)(puVar3 + -0x2e) = 0x40249a;
    local_c8 = length(*(undefined *)(puVar3 + -0x2e));
    do {
      local_c9 = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    uVar1 = (uint)((ulong)local_c8 >> 0x20);
    if (local_c9) goto LAB_0040257a;
    do {
      *local_80 = (uint)local_b8 & uVar1 >> 8 | 0x1c;
LAB_0040257a:
      *local_80 = (uint)local_b8 & uVar1 >> 8 | 0x1c;
      local_ca = *local_80 != 0;
    } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
    do {
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    if (local_ca) {
      do {
        local_d8 = (long)(int)*i;
      } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
      *(undefined8 *)(puVar3 + -0x2e) = 0x402739;
      local_e0 = (int *)operator[](hero,local_d8,*(undefined *)(puVar3 + -0x2e));
      do {
        local_e1 = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
      do {
        local_e8 = *local_e0;
      } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
      *(undefined8 *)(puVar3 + -0x2e) = 0x40287a;
      vector(local_88,this,*(undefined *)(puVar3 + -0x2e));
      do {
        local_e9 = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
      do {
      } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
      do {
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
                    /* try { // try from 00402a1c to 00402a24 has its CatchHandler @ 00402f44 */
      *(undefined8 *)(puVar3 + -0x2e) = 0x402a25;
      local_f0 = transform_input((int)local_88,*(undefined *)(puVar3 + -0x2e));
      if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_00402a73;
      do {
        do {
        } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
LAB_00402a73:
        local_f1 = local_e8 == local_f0;
      } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
      do {
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
                    /* try { // try from 00402b58 to 00402d49 has its CatchHandler @ 00402e05 */
      *(undefined8 *)(puVar3 + -0x2e) = 0x402b61;
      ~vector(local_88,*(undefined *)(puVar3 + -0x2e));
      do {
        local_f2 = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
      do {
      } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
      if ((local_f1 & 1U) != 0) {
        do {
          local_f8 = *local_80;
          local_100 = (long)(int)*i;
        } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
        *(undefined8 *)(puVar3 + -0x2e) = 0x402d4a;
        local_108 = (uint *)operator[](hero,local_100,*(undefined *)(puVar3 + -0x2e));
        if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_00402d99;
        do {
          *local_80 = (uint)((int)(local_f8 & *local_108) < 0);
LAB_00402d99:
          *local_80 = (uint)((int)(local_f8 & *local_108) < 0);
        } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
      }
      if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_0040315a;
      do {
        do {
        } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
LAB_0040315a:
      } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
    }
    do {
      do {
        local_132 = *local_80 != 0;
        bVar5 = (x17 * (x17 + -1) & 1U) == 0;
        local_133 = bVar5 || y18 < 10;
      } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    } while (!bVar5 && y18 >= 10);
    do {
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    if (local_132) break;
    do {
      local_135 = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    do {
    } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
    do {
    } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
    if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_0040368e;
    do {
      *i = *i + 1;
LAB_0040368e:
      *i = *i + 1;
    } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
  }
  do {
    local_134 = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
  } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
  if (local_134) goto LAB_0040343d;
  do {
    *puVar2 = (*i & 1) << 8;
    *local_70 = 1;
LAB_0040343d:
    *puVar2 = (*i & 1) << 8;
    *local_70 = 1;
  } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
LAB_004038bd:
  if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_00403900;
  do {
    *(undefined8 *)(puVar3 + -0x2e) = 0x40411c;
    ~vector(this,*(undefined *)(puVar3 + -0x2e));
LAB_00403900:
    *(undefined8 *)(puVar3 + -0x2e) = 0x403909;
    ~vector(this,*(undefined *)(puVar3 + -0x2e));
    local_144 = *puVar2;
  } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
  do {
  } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
  return (ulong)local_144;
LAB_00403729:
  do {
    local_136 = (x17 * (x17 + -1) & 1U) == 0 || y18 < 10;
  } while ((x3 * (x3 + -1) & 1U) != 0 && 9 < y4);
  do {
  } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
                    /* try { // try from 004037fd to 0040380f has its CatchHandler @ 00402e05 */
  *(undefined8 *)(puVar3 + -0x2e) = 0x403810;
  local_140 = operator<<<std--char_traits<char>>(cout,"success\n",*(undefined *)(puVar3 + -0x2e));
  if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_0040385f;
  do {
    *puVar2 = 0x1337;
    *local_70 = 1;
LAB_0040385f:
    *puVar2 = 0x1337;
    *local_70 = 1;
  } while ((x17 * (x17 + -1) & 1U) != 0 && 9 < y18);
  goto LAB_004038bd;
}
```

So let's start going through this. First we can see that there is an iteration counter, which is initialized here:

```
    *i = 0;
```

You can see it checked here. It checks to see if it is greater than `28`:

```
      lenCheck = (int)*i < legend >> 2;
    if (!lenCheck) goto LAB_00403729;
```

And it is incremented here:

```
      *i = *i + 1;
```

Checking `LAB_00403729`, we see that it is probably the code path we want to take in order to solve the challenge:

```
LAB_00403729:
  *(undefined8 *)(puVar3 + -0x2e) = 0x403810;
  local_140 = operator<<<std--char_traits<char>>(cout,"success\n",*(undefined *)(puVar3 + -0x2e));
  if ((x17 * (x17 + -1) & 1U) == 0 || y18 < 10) goto LAB_0040385f;
    *puVar2 = 0x1337;
    *local_70 = 1;
LAB_0040385f:
    *puVar2 = 0x1337;
    *local_70 = 1;
  goto LAB_004038bd;
```

In order to execute that code path, we will need to run this loop `28` times.

Later on, we can see that the actual check it performs is here:
```
passedCheck = heroValue == transformedValue;
```

The first time we hit the check, it looks like it just checking the first character of our input against the first `hero` value:
```
gef➤  b *0x402a7f
Breakpoint 1 at 0x402a7f
gef➤  r
Starting program: /Hackery/pod/modules/obfuscated_reversing/csaw15_wyvern/wyvern
+-----------------------+
|    Welcome Hero       |
+-----------------------+

[!] Quest: there is a dragon prowling the domain.
  brute strength and magic is our only hope. Test your skill.

Enter the dragon's secret: d000000000000000000000000000

Breakpoint 1, 0x0000000000402a7f in sanitize_input(std::string) ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────── registers ────
$rax   : 0x64              
$rbx   : 0x0               
$rcx   : 0x64              
$rdx   : 0xffffffff        
$rsp   : 0x00007fffffffda70  →  0x0000000000000000
$rbp   : 0x00007fffffffdca0  →  0x00007fffffffdd80  →  0x00007fffffffdf50  →  0x000000000040e5b0  →  <__libc_csu_init+0> push r15
$rsi   : 0xffffff01        
$rdi   : 0x1               
$rip   : 0x0000000000402a7f  →  <sanitize_input(std::string)+3519> cmp eax, ecx
$r8    : 0x1               
$r9    : 0xffffffff        
$r10   : 0x1               
$r11   : 0x1               
$r12   : 0x0000000000401301  →  <_GLOBAL__sub_I_wyvern.cpp+81> mov eax, DWORD PTR ds:0x610420
$r13   : 0x00007fffffffe001  →  0x3000000000004013
$r14   : 0x0               
$r15   : 0xffffffff        
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda70│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffda78│+0x0008: 0x0000000000000000
0x00007fffffffda80│+0x0010: 0x00000000006236f0  →  0x0000000000000064 ("d"?)
0x00007fffffffda88│+0x0018: 0x00000000006236f4  →  0x0000000000000000
0x00007fffffffda90│+0x0020: 0x00000000006236f4  →  0x0000000000000000
0x00007fffffffda98│+0x0028: 0x0000000000000000
0x00007fffffffdaa0│+0x0030: 0x000000000000001c
0x00007fffffffdaa8│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────── code:x86:64 ────
     0x402a6e <sanitize_input(std::string)+3502> jmp    0x403eb3 <_Z14sanitize_inputSs+8691>
     0x402a73 <sanitize_input(std::string)+3507> mov    eax, DWORD PTR [rbp-0xe0]
     0x402a79 <sanitize_input(std::string)+3513> mov    ecx, DWORD PTR [rbp-0xe8]
 →   0x402a7f <sanitize_input(std::string)+3519> cmp    eax, ecx
     0x402a81 <sanitize_input(std::string)+3521> sete   dl
     0x402a84 <sanitize_input(std::string)+3524> mov    esi, DWORD PTR ds:0x610594
     0x402a8b <sanitize_input(std::string)+3531> mov    edi, DWORD PTR ds:0x610434
     0x402a92 <sanitize_input(std::string)+3538> mov    r8d, esi
     0x402a95 <sanitize_input(std::string)+3541> sub    r8d, 0x1
───────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "wyvern", stopped, reason: BREAKPOINT
─────────────────────────────────────────────────────────────────── trace ────
[#0] 0x402a7f → sanitize_input(std::string)()
[#1] 0x404854 → start_quest(std::string)()
[#2] 0x40e266 → main()
──────────────────────────────────────────────────────────────────────────────
gef➤  p $eax
$1 = 0x64
gef➤  p $ecx
$2 = 0x64
gef➤  x/g 0x6102f8
0x6102f8 <hero>:  0x623790
gef➤  x/g 0x623790
0x623790: 0xd600000064
```

However the second time around, it looks a bit different. It is still checking our input against the `hero` value we would expect, however the value our input influences is different from what we would expect:
```
Breakpoint 1, 0x0000000000402a7f in sanitize_input(std::string) ()
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────── registers ────
$rax   : 0xd6              
$rbx   : 0x0               
$rcx   : 0x94              
$rdx   : 0xffffffff        
$rsp   : 0x00007fffffffda70  →  0x0000000000000000
$rbp   : 0x00007fffffffdca0  →  0x00007fffffffdd80  →  0x00007fffffffdf50  →  0x000000000040e5b0  →  <__libc_csu_init+0> push r15
$rsi   : 0xffffff01        
$rdi   : 0x1               
$rip   : 0x0000000000402a7f  →  <sanitize_input(std::string)+3519> cmp eax, ecx
$r8    : 0x1               
$r9    : 0xffffffff        
$r10   : 0x1               
$r11   : 0x1               
$r12   : 0x0000000000401301  →  <_GLOBAL__sub_I_wyvern.cpp+81> mov eax, DWORD PTR ds:0x610420
$r13   : 0x00007fffffffe001  →  0x3000000000004013
$r14   : 0x0               
$r15   : 0xffffffff        
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
─────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffda70│+0x0000: 0x0000000000000000   ← $rsp
0x00007fffffffda78│+0x0008: 0x0000000000000000
0x00007fffffffda80│+0x0010: 0x00000000006236d0  →  0x0000003000000064 ("d"?)
0x00007fffffffda88│+0x0018: 0x00000000006236d8  →  0x0000000000000000
0x00007fffffffda90│+0x0020: 0x00000000006236d8  →  0x0000000000000000
0x00007fffffffda98│+0x0028: 0x0000000000000000
0x00007fffffffdaa0│+0x0030: 0x000000000000001c
0x00007fffffffdaa8│+0x0038: 0x0000000000000000
───────────────────────────────────────────────────────────── code:x86:64 ────
     0x402a6e <sanitize_input(std::string)+3502> jmp    0x403eb3 <_Z14sanitize_inputSs+8691>
     0x402a73 <sanitize_input(std::string)+3507> mov    eax, DWORD PTR [rbp-0xe0]
     0x402a79 <sanitize_input(std::string)+3513> mov    ecx, DWORD PTR [rbp-0xe8]
 →   0x402a7f <sanitize_input(std::string)+3519> cmp    eax, ecx
     0x402a81 <sanitize_input(std::string)+3521> sete   dl
     0x402a84 <sanitize_input(std::string)+3524> mov    esi, DWORD PTR ds:0x610594
     0x402a8b <sanitize_input(std::string)+3531> mov    edi, DWORD PTR ds:0x610434
     0x402a92 <sanitize_input(std::string)+3538> mov    r8d, esi
     0x402a95 <sanitize_input(std::string)+3541> sub    r8d, 0x1
───────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "wyvern", stopped, reason: BREAKPOINT
─────────────────────────────────────────────────────────────────── trace ────
[#0] 0x402a7f → sanitize_input(std::string)()
[#1] 0x404854 → start_quest(std::string)()
[#2] 0x40e266 → main()
──────────────────────────────────────────────────────────────────────────────
gef➤  p $eax
$3 = 0xd6
gef➤  p $ecx
$4 = 0x94
```

Let's see where it comes up with those values. For `heroValue` we can see that it grabs it from the `hero` array:

```
      heroValueTransfer = (int *)operator[](hero,(long)(int)*puVar4,*(undefined *)(puVar5 + -0x2e));
        heroValue = *heroValueTransfer;
```

In addition to that, when we stop at the check in the debugger, we see that it always has a value that corresponds to `hero[i]` where `i` is the iteration count. For `transformedValue` we see that it is grabbed from here:

```
transformedValue = transform_input((int)this_00,*(undefined *)(puVar5 + -0x2e));
```

When we stop at this call in gdb, we see that it's argument is our input stored in the same style as the `hero` array.

```
────────────────────────────────────────────────────────────── code:x86:64 ────
     0x402a11 <sanitize_input(std::string)+3409> jne    0x402a1c <_Z14sanitize_inputSs+3420>
     0x402a17 <sanitize_input(std::string)+3415> jmp    0x404298 <_Z14sanitize_inputSs+9688>
     0x402a1c <sanitize_input(std::string)+3420> mov    rdi, QWORD PTR [rbp-0x80]
 →   0x402a20 <sanitize_input(std::string)+3424> call   0x4014b0 <_Z15transform_inputSt6vectorIiSaIiEE>
   ↳    0x4014b0 <transform_input(std::vector<int,+0> push   rbp
        0x4014b1 <transform_input(std::vector<int,+0> mov    rbp, rsp
        0x4014b4 <transform_input(std::vector<int,+0> push   rbx
        0x4014b5 <transform_input(std::vector<int,+0> sub    rsp, 0x48
        0x4014b9 <transform_input(std::vector<int,+0> mov    eax, DWORD PTR ds:0x610368
        0x4014c0 <transform_input(std::vector<int,+0> mov    ecx, DWORD PTR ds:0x610558
────────────────────────────────────────────────────── arguments (guessed) ────
_Z15transform_inputSt6vectorIiSaIiEE (
   $rdi = 0x00007fffffffda80 → 0x00000000006236f0 → 0x0000000000000064 ("d"?),
   $rsi = 0x0000000000000001,
   $rdx = 0x00000000ffffffff,
   $rcx = 0x0000000000000000
)
────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "wyvern", stopped, reason: BREAKPOINT
──────────────────────────────────────────────────────────────────── trace ────
[#0] 0x402a20 → sanitize_input(std::string)()
[#1] 0x404854 → start_quest(std::string)()
[#2] 0x40e266 → main()
───────────────────────────────────────────────────────────────────────────────
gef➤  
```

output is `0x64` in `eax`. For the second iteration, we have this:

```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x402a11 <sanitize_input(std::string)+3409> jne    0x402a1c <_Z14sanitize_inputSs+3420>
     0x402a17 <sanitize_input(std::string)+3415> jmp    0x404298 <_Z14sanitize_inputSs+9688>
     0x402a1c <sanitize_input(std::string)+3420> mov    rdi, QWORD PTR [rbp-0x80]
 →   0x402a20 <sanitize_input(std::string)+3424> call   0x4014b0 <_Z15transform_inputSt6vectorIiSaIiEE>
   ↳    0x4014b0 <transform_input(std::vector<int,+0> push   rbp
        0x4014b1 <transform_input(std::vector<int,+0> mov    rbp, rsp
        0x4014b4 <transform_input(std::vector<int,+0> push   rbx
        0x4014b5 <transform_input(std::vector<int,+0> sub    rsp, 0x48
        0x4014b9 <transform_input(std::vector<int,+0> mov    eax, DWORD PTR ds:0x610368
        0x4014c0 <transform_input(std::vector<int,+0> mov    ecx, DWORD PTR ds:0x610558
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
_Z15transform_inputSt6vectorIiSaIiEE (
   $rdi = 0x00007fffffffda80 → 0x00000000006236d0 → 0x0000003000000064 ("d"?),
   $rsi = 0x0000000000000001,
   $rdx = 0x00000000ffffffff,
   $rcx = 0x0000000000000000
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "wyvern", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x402a20 → sanitize_input(std::string)()
[#1] 0x404854 → start_quest(std::string)()
[#2] 0x40e266 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Output is `0x94` in the `eax` register. We can see a pattern here. The input to this function is a single QWORD that stores two bytes. It then adds those two values and returns whatever the sum is. In the first case that was `0x64 + 0 = 0x64`. For the second case that was `0x64 + 0x30 = 0x94`. So the value that is derived from our input in the compare is essentially `inp[i] + inp[i - 1]` (with `inp[-1]` being `0`).

So now that we know how exactly our input is influencing the check, we can figure out what input we need to give it to pass everything. Since it is adding our values together, we can just subtract the `hero` values in the same manner to undo it. First here is all of the `hero` values:

```
gef➤  x/14g 0x623790
0x623790: 0xd600000064  0x1710000010a
0x6237a0: 0x20f000001a1 0x2dd0000026e
0x6237b0: 0x3ae0000034f 0x4520000041e
0x6237c0: 0x538000004c6 0x604000005a1
0x6237d0: 0x69600000635 0x76300000704
0x6237e0: 0x840000007cc 0x8d400000875
0x6237f0: 0x96c00000920 0xa0f000009c2
```

When we subtract it:
```
0x64 - 0x00   = 0x64 'd'
0xd6 - 0x64   = 0x72 'r'
0x10a - 0xd6  = 0x34 '4'
0x171 - 0x10a = 0x67 'g'
0x1a1 - 0x171 = 0x30 '0'
```

So we can see that this is starting to give us something that looks like a solution. When we script this out, we get this:

```
hero = [0x0, 0x64, 0xd6, 0x10a, 0x171, 0x1a1, 0x20f, 0x26e, 0x2dd, 0x34f, 0x3ae, 0x41e, 0x452, 0x4c6, 0x538, 0x5a1, 0x604, 0x635, 0x696, 0x704, 0x763, 0x7cc, 0x840, 0x875, 0x8d4, 0x920, 0x96c, 0x9c2, 0xa0f]

flag = ""

for i in range(1, len(hero)):
  flag += chr(hero[i] - hero[i - 1])

print "We fought off the dragon: " + flag
```

When we run it:

```
$ ./wyvern
+-----------------------+
|    Welcome Hero       |
+-----------------------+

[!] Quest: there is a dragon prowling the domain.
  brute strength and magic is our only hope. Test your skill.

Enter the dragon's secret: dr4g0n_or_p4tric1an_it5_LLVM
success

[+] A great success! Here is a flag{dr4g0n_or_p4tric1an_it5_LLVM}
```

Just like that, we solved the challenge!
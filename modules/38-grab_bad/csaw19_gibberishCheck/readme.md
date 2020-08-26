# Csaw 2019 Gibberish Check

Let's take a look at the binary:

```
$    file gibberish_check
gibberish_check: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=248693b90a85745125ac4d8241d53503e822a4c7, stripped
$    pwn checksec gibberish_check
[*] '/Hackery/pod/modules/38-grab_bad/csaw19_gibberishCheck/gibberish_check'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$    ./gibberish_check
Find the Key!
15935728
Wrong D:
```

So we can see that we are dealing with a `x64` bit elf (with `PIE`) that scans in input, and check it. When we take a look at the code in ghidra, we see this:

```

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_00101d98(void)

{
  char cVar1;
  int iVar2;
  basic_ostream *this;
  basic_string<char,std--char_traits<char>,std--allocator<char>> *this_00;
  long in_FS_OFFSET;
  allocator<char> local_42d;
  allocator<char> local_42c;
  allocator<char> local_42b;
  allocator<char> local_42a;
  allocator<char> local_429;
  allocator<char> local_428;
  allocator<char> local_427;
  allocator<char> local_426;
  allocator<char> local_425;
  allocator<char> local_424;
  allocator<char> local_423;
  allocator<char> local_422;
  allocator<char> local_421;
  allocator<char> local_420;
  allocator<char> local_41f;
  allocator<char> local_41e;
  allocator<char> local_41d;
  allocator<char> local_41c;
  allocator<char> local_41b;
  allocator<char> local_41a;
  allocator<char> local_419;
  allocator<char> local_418;
  allocator<char> local_417;
  allocator<char> local_416;
  allocator<char> local_415;
  int local_414;
  undefined8 local_410;
  undefined8 local_408;
  undefined *local_400;
  undefined local_3f8 [32];
  basic_string local_3d8 [32];
  basic_string local_3b8 [32];
  basic_string local_398 [32];
  basic_string<char,std--char_traits<char>,std--allocator<char>> local_378 [32];
  char local_358 [32];
  char local_338 [32];
  char local_318 [32];
  char local_2f8 [32];
  char local_2d8 [32];
  char local_2b8 [32];
  char local_298 [32];
  char local_278 [32];
  char local_258 [32];
  char local_238 [32];
  char local_218 [32];
  char local_1f8 [32];
  char local_1d8 [32];
  char local_1b8 [32];
  char local_198 [32];
  char local_178 [32];
  char local_158 [32];
  char local_138 [32];
  char local_118 [32];
  char local_f8 [32];
  char local_d8 [32];
  char local_b8 [32];
  char local_98 [32];
  char local_78 [32];
  char local_58 [32];
  basic_string<char,std--char_traits<char>,std--allocator<char>> abStack56 [8];
  long local_30;
 
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  FUN_00101be1();
  allocator();
                    /* try { // try from 00101de3 to 00101de7 has its CatchHandler @ 00102950 */
  basic_string((char *)local_378,(allocator *)"dqzkenxmpsdoe_qkihmd");
  allocator();
                    /* try { // try from 00101e16 to 00101e1a has its CatchHandler @ 0010293c */
  basic_string(local_358,(allocator *)"jffglzbo_zghqpnqqfjs");
  allocator();
                    /* try { // try from 00101e49 to 00101e4d has its CatchHandler @ 00102928 */
  basic_string(local_338,(allocator *)"kdwx_vl_rnesamuxugap");
  allocator();
                    /* try { // try from 00101e7c to 00101e80 has its CatchHandler @ 00102914 */
  basic_string(local_318,(allocator *)"ozntzohegxagreedxukr");
  allocator();
                    /* try { // try from 00101eb2 to 00101eb6 has its CatchHandler @ 00102900 */
  basic_string(local_2f8,(allocator *)"xujaowgbjjhydjmmtapo");
  allocator();
                    /* try { // try from 00101ee8 to 00101eec has its CatchHandler @ 001028ec */
  basic_string(local_2d8,(allocator *)"pwbzgymqvpmznoanomzx");
  allocator();
                    /* try { // try from 00101f1e to 00101f22 has its CatchHandler @ 001028d8 */
  basic_string(local_2b8,(allocator *)"qaqhrjofhfiuyt_okwxn");
  allocator();
                    /* try { // try from 00101f54 to 00101f58 has its CatchHandler @ 001028c4 */
  basic_string(local_298,(allocator *)"a_anqkczwbydtdwwbjwi");
  allocator();
                    /* try { // try from 00101f8a to 00101f8e has its CatchHandler @ 001028b0 */
  basic_string(local_278,(allocator *)"zoljafyuxinnvkxsskdu");
  allocator();
                    /* try { // try from 00101fc0 to 00101fc4 has its CatchHandler @ 0010289c */
  basic_string(local_258,(allocator *)"irdlddjjokwtpbrrr_yj");
  allocator();
                    /* try { // try from 00101ff6 to 00101ffa has its CatchHandler @ 00102888 */
  basic_string(local_238,(allocator *)"cecckcvaltzejskg_qrc");
  allocator();
                    /* try { // try from 0010202c to 00102030 has its CatchHandler @ 00102874 */
  basic_string(local_218,(allocator *)"vlpwstrhtcpxxnbbcbhv");
  allocator();
                    /* try { // try from 00102062 to 00102066 has its CatchHandler @ 00102860 */
  basic_string(local_1f8,(allocator *)"spirysagnyujbqfhldsk");
  allocator();
                    /* try { // try from 00102098 to 0010209c has its CatchHandler @ 0010284c */
  basic_string(local_1d8,(allocator *)"bcyqbikpuhlwordznpth");
  allocator();
                    /* try { // try from 001020ce to 001020d2 has its CatchHandler @ 00102838 */
  basic_string(local_1b8,(allocator *)"_xkiiusddvvicipuzyna");
  allocator();
                    /* try { // try from 00102104 to 00102108 has its CatchHandler @ 00102824 */
  basic_string(local_198,(allocator *)"wsxyupdsqatrkzgawzbt");
  allocator();
                    /* try { // try from 0010213a to 0010213e has its CatchHandler @ 00102810 */
  basic_string(local_178,(allocator *)"ybg_wmftbdcvlhhidril");
  allocator();
                    /* try { // try from 00102170 to 00102174 has its CatchHandler @ 001027fc */
  basic_string(local_158,(allocator *)"ryvmngilaqkbsyojgify");
  allocator();
                    /* try { // try from 001021a6 to 001021aa has its CatchHandler @ 001027e8 */
  basic_string(local_138,(allocator *)"mvefjqtxzmxf_vcyhelf");
  allocator();
                    /* try { // try from 001021dc to 001021e0 has its CatchHandler @ 001027d4 */
  basic_string(local_118,(allocator *)"hjhofxwrk_rpwli_mxv_");
  allocator();
                    /* try { // try from 00102212 to 00102216 has its CatchHandler @ 001027c0 */
  basic_string(local_f8,(allocator *)"enupmannieqqzcyevs_w");
  allocator();
                    /* try { // try from 00102248 to 0010224c has its CatchHandler @ 001027ac */
  basic_string(local_d8,(allocator *)"uhmvvb_cfgjkggjpavub");
  allocator();
                    /* try { // try from 0010227e to 00102282 has its CatchHandler @ 00102798 */
  basic_string(local_b8,(allocator *)"gktdphqiswomuwzvjtog");
  allocator();
                    /* try { // try from 001022b4 to 001022b8 has its CatchHandler @ 00102784 */
  basic_string(local_98,(allocator *)"lgoehepwclbaifvtfoeq");
  allocator();
                    /* try { // try from 001022ea to 001022ee has its CatchHandler @ 00102770 */
  basic_string(local_78,(allocator *)"nm_uxrukmof_fxsfpcqz");
  allocator();
                    /* try { // try from 00102320 to 00102324 has its CatchHandler @ 0010275c */
  basic_string(local_58,(allocator *)"ttsbclzyyuslmutcylcm");
  FUN_00102e5a(&local_408);
                    /* try { // try from 0010236a to 0010236e has its CatchHandler @ 0010271a */
  FUN_00102eda(local_3f8,local_378,0x1a,&local_408);
  FUN_00102e76(&local_408);
  this_00 = abStack56;
  while (this_00 != local_378) {
    this_00 = this_00 + -0x20;
    ~basic_string(this_00);
  }
  ~allocator((allocator<char> *)&local_410);
  ~allocator(&local_415);
  ~allocator(&local_416);
  ~allocator(&local_417);
  ~allocator(&local_418);
  ~allocator(&local_419);
  ~allocator(&local_41a);
  ~allocator(&local_41b);
  ~allocator(&local_41c);
  ~allocator(&local_41d);
  ~allocator(&local_41e);
  ~allocator(&local_41f);
  ~allocator(&local_420);
  ~allocator(&local_421);
  ~allocator(&local_422);
  ~allocator(&local_423);
  ~allocator(&local_424);
  ~allocator(&local_425);
  ~allocator(&local_426);
  ~allocator(&local_427);
  ~allocator(&local_428);
  ~allocator(&local_429);
  ~allocator(&local_42a);
  ~allocator(&local_42b);
  ~allocator(&local_42c);
  ~allocator(&local_42d);
                    /* try { // try from 0010253a to 00102553 has its CatchHandler @ 001029bd */
  this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"Find the Key!");
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  basic_string();
  local_414 = 0;
                    /* try { // try from 0010257e to 00102601 has its CatchHandler @ 001029a9 */
  operator>><char,std--char_traits<char>,std--allocator<char>>((basic_istream *)cin,local_3d8);
  local_400 = local_3f8;
  local_410 = FUN_00102fd8(local_400);
  local_408 = FUN_00103020(local_400);
  while( true ) {
    cVar1 = FUN_0010306c(&local_410,&local_408,&local_408);
    if (cVar1 == '\0') break;
    FUN_001030c8(&local_410);
    basic_string(local_3b8);
                    /* try { // try from 00102616 to 0010261a has its CatchHandler @ 00102995 */
    basic_string((basic_string *)local_378);
                    /* try { // try from 0010262f to 00102633 has its CatchHandler @ 00102981 */
    basic_string(local_398);
                    /* try { // try from 00102648 to 0010264c has its CatchHandler @ 0010296d */
    iVar2 = FUN_0010164a(local_398,local_378,local_378);
    local_414 = local_414 + iVar2;
    ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)local_398);
    ~basic_string(local_378);
    ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)local_3b8);
    FUN_001030a8(&local_410);
  }
  if ((_FUN_0010164a & 0xff) == 0xcc) {
                    /* try { // try from 001026b3 to 001026de has its CatchHandler @ 001029a9 */
    puts("Rip");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (local_414 == 0x1f9) {
    FUN_00101b83();
    FUN_00101c62();
  }
  else {
    FUN_00101bb2();
  }
  ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)local_3d8);
  FUN_00102f94(local_3f8);
  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

One thing of immediate importance is the function `0x101be1`:

```

void FUN_00101be1(void)

{
  long lVar1;
  char local_9;
 
  local_9 = '\0';
  lVar1 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar1 == 0) {
    local_9 = '\x02';
  }
  lVar1 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar1 == -1) {
    local_9 = local_9 * '\x03';
  }
  if (local_9 != '\x06') {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}
```

This function essentially uses `PTRACE` to make it harder to debug the binary. However we can just patch out it's function call with nop instructions to prevent it from running, so we can debug the binary.

After we patch out the anti-debugging functionality with just nop instructions (`0x90`s), this is what the code looks like:

```

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined8 FUN_00101d98(void)

{
  char cVar1;
  int checkOutput;
  basic_ostream *this;
  basic_string<char,std--char_traits<char>,std--allocator<char>> *this_00;
  long in_FS_OFFSET;
  allocator<char> local_42d;
  allocator<char> local_42c;
  allocator<char> local_42b;
  allocator<char> local_42a;
  allocator<char> local_429;
  allocator<char> local_428;
  allocator<char> local_427;
  allocator<char> local_426;
  allocator<char> local_425;
  allocator<char> local_424;
  allocator<char> local_423;
  allocator<char> local_422;
  allocator<char> local_421;
  allocator<char> local_420;
  allocator<char> local_41f;
  allocator<char> local_41e;
  allocator<char> local_41d;
  allocator<char> local_41c;
  allocator<char> local_41b;
  allocator<char> local_41a;
  allocator<char> local_419;
  allocator<char> local_418;
  allocator<char> local_417;
  allocator<char> local_416;
  allocator<char> local_415;
  int check;
  undefined8 local_410;
  undefined8 local_408;
  undefined *local_400;
  undefined local_3f8 [32];
  basic_string local_3d8 [32];
  basic_string local_3b8 [32];
  basic_string string [32];
  basic_string<char,std--char_traits<char>,std--allocator<char>> inp0 [32];
  char local_358 [32];
  char local_338 [32];
  char local_318 [32];
  char local_2f8 [32];
  char local_2d8 [32];
  char local_2b8 [32];
  char local_298 [32];
  char local_278 [32];
  char local_258 [32];
  char local_238 [32];
  char local_218 [32];
  char local_1f8 [32];
  char local_1d8 [32];
  char local_1b8 [32];
  char local_198 [32];
  char local_178 [32];
  char local_158 [32];
  char local_138 [32];
  char local_118 [32];
  char local_f8 [32];
  char local_d8 [32];
  char local_b8 [32];
  char local_98 [32];
  char local_78 [32];
  char local_58 [32];
  basic_string<char,std--char_traits<char>,std--allocator<char>> abStack56 [8];
  long local_30;
 
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  allocator();
                    /* try { // try from 00101de3 to 00101de7 has its CatchHandler @ 00102950 */
  basic_string((char *)inp0,(allocator *)"dqzkenxmpsdoe_qkihmd");
  allocator();
                    /* try { // try from 00101e16 to 00101e1a has its CatchHandler @ 0010293c */
  basic_string(local_358,(allocator *)"jffglzbo_zghqpnqqfjs");
  allocator();
                    /* try { // try from 00101e49 to 00101e4d has its CatchHandler @ 00102928 */
  basic_string(local_338,(allocator *)"kdwx_vl_rnesamuxugap");
  allocator();
                    /* try { // try from 00101e7c to 00101e80 has its CatchHandler @ 00102914 */
  basic_string(local_318,(allocator *)"ozntzohegxagreedxukr");
  allocator();
                    /* try { // try from 00101eb2 to 00101eb6 has its CatchHandler @ 00102900 */
  basic_string(local_2f8,(allocator *)"xujaowgbjjhydjmmtapo");
  allocator();
                    /* try { // try from 00101ee8 to 00101eec has its CatchHandler @ 001028ec */
  basic_string(local_2d8,(allocator *)"pwbzgymqvpmznoanomzx");
  allocator();
                    /* try { // try from 00101f1e to 00101f22 has its CatchHandler @ 001028d8 */
  basic_string(local_2b8,(allocator *)"qaqhrjofhfiuyt_okwxn");
  allocator();
                    /* try { // try from 00101f54 to 00101f58 has its CatchHandler @ 001028c4 */
  basic_string(local_298,(allocator *)"a_anqkczwbydtdwwbjwi");
  allocator();
                    /* try { // try from 00101f8a to 00101f8e has its CatchHandler @ 001028b0 */
  basic_string(local_278,(allocator *)"zoljafyuxinnvkxsskdu");
  allocator();
                    /* try { // try from 00101fc0 to 00101fc4 has its CatchHandler @ 0010289c */
  basic_string(local_258,(allocator *)"irdlddjjokwtpbrrr_yj");
  allocator();
                    /* try { // try from 00101ff6 to 00101ffa has its CatchHandler @ 00102888 */
  basic_string(local_238,(allocator *)"cecckcvaltzejskg_qrc");
  allocator();
                    /* try { // try from 0010202c to 00102030 has its CatchHandler @ 00102874 */
  basic_string(local_218,(allocator *)"vlpwstrhtcpxxnbbcbhv");
  allocator();
                    /* try { // try from 00102062 to 00102066 has its CatchHandler @ 00102860 */
  basic_string(local_1f8,(allocator *)"spirysagnyujbqfhldsk");
  allocator();
                    /* try { // try from 00102098 to 0010209c has its CatchHandler @ 0010284c */
  basic_string(local_1d8,(allocator *)"bcyqbikpuhlwordznpth");
  allocator();
                    /* try { // try from 001020ce to 001020d2 has its CatchHandler @ 00102838 */
  basic_string(local_1b8,(allocator *)"_xkiiusddvvicipuzyna");
  allocator();
                    /* try { // try from 00102104 to 00102108 has its CatchHandler @ 00102824 */
  basic_string(local_198,(allocator *)"wsxyupdsqatrkzgawzbt");
  allocator();
                    /* try { // try from 0010213a to 0010213e has its CatchHandler @ 00102810 */
  basic_string(local_178,(allocator *)"ybg_wmftbdcvlhhidril");
  allocator();
                    /* try { // try from 00102170 to 00102174 has its CatchHandler @ 001027fc */
  basic_string(local_158,(allocator *)"ryvmngilaqkbsyojgify");
  allocator();
                    /* try { // try from 001021a6 to 001021aa has its CatchHandler @ 001027e8 */
  basic_string(local_138,(allocator *)"mvefjqtxzmxf_vcyhelf");
  allocator();
                    /* try { // try from 001021dc to 001021e0 has its CatchHandler @ 001027d4 */
  basic_string(local_118,(allocator *)"hjhofxwrk_rpwli_mxv_");
  allocator();
                    /* try { // try from 00102212 to 00102216 has its CatchHandler @ 001027c0 */
  basic_string(local_f8,(allocator *)"enupmannieqqzcyevs_w");
  allocator();
                    /* try { // try from 00102248 to 0010224c has its CatchHandler @ 001027ac */
  basic_string(local_d8,(allocator *)"uhmvvb_cfgjkggjpavub");
  allocator();
                    /* try { // try from 0010227e to 00102282 has its CatchHandler @ 00102798 */
  basic_string(local_b8,(allocator *)"gktdphqiswomuwzvjtog");
  allocator();
                    /* try { // try from 001022b4 to 001022b8 has its CatchHandler @ 00102784 */
  basic_string(local_98,(allocator *)"lgoehepwclbaifvtfoeq");
  allocator();
                    /* try { // try from 001022ea to 001022ee has its CatchHandler @ 00102770 */
  basic_string(local_78,(allocator *)"nm_uxrukmof_fxsfpcqz");
  allocator();
                    /* try { // try from 00102320 to 00102324 has its CatchHandler @ 0010275c */
  basic_string(local_58,(allocator *)"ttsbclzyyuslmutcylcm");
  FUN_00102e5a(&local_408);
                    /* try { // try from 0010236a to 0010236e has its CatchHandler @ 0010271a */
  FUN_00102eda(local_3f8,inp0,0x1a,&local_408);
  FUN_00102e76(&local_408);
  this_00 = abStack56;
  while (this_00 != inp0) {
    this_00 = this_00 + -0x20;
    ~basic_string(this_00);
  }
  ~allocator((allocator<char> *)&local_410);
  ~allocator(&local_415);
  ~allocator(&local_416);
  ~allocator(&local_417);
  ~allocator(&local_418);
  ~allocator(&local_419);
  ~allocator(&local_41a);
  ~allocator(&local_41b);
  ~allocator(&local_41c);
  ~allocator(&local_41d);
  ~allocator(&local_41e);
  ~allocator(&local_41f);
  ~allocator(&local_420);
  ~allocator(&local_421);
  ~allocator(&local_422);
  ~allocator(&local_423);
  ~allocator(&local_424);
  ~allocator(&local_425);
  ~allocator(&local_426);
  ~allocator(&local_427);
  ~allocator(&local_428);
  ~allocator(&local_429);
  ~allocator(&local_42a);
  ~allocator(&local_42b);
  ~allocator(&local_42c);
  ~allocator(&local_42d);
                    /* try { // try from 0010253a to 00102553 has its CatchHandler @ 001029bd */
  this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"Find the Key!");
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  basic_string();
  check = 0;
                    /* try { // try from 0010257e to 00102601 has its CatchHandler @ 001029a9 */
  operator>><char,std--char_traits<char>,std--allocator<char>>((basic_istream *)cin,local_3d8);
  local_400 = local_3f8;
  local_410 = FUN_00102fd8(local_400);
  local_408 = FUN_00103020(local_400);
  while( true ) {
    cVar1 = FUN_0010306c(&local_410,&local_408,&local_408);
    if (cVar1 == '\0') break;
    FUN_001030c8(&local_410);
    basic_string(local_3b8);
                    /* try { // try from 00102616 to 0010261a has its CatchHandler @ 00102995 */
    basic_string((basic_string *)inp0);
                    /* try { // try from 0010262f to 00102633 has its CatchHandler @ 00102981 */
    basic_string(string);
                    /* try { // try from 00102648 to 0010264c has its CatchHandler @ 0010296d */
    _checkOutput = checkFunction((basic_string<char,std--char_traits<char>,std--allocator<char>> *)
                                 string,inp0);
    check = check + (int)_checkOutput;
    ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)string);
    ~basic_string(inp0);
    ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)local_3b8);
    FUN_001030a8(&local_410);
  }
  if ((_checkFunction & 0xff) == 0xcc) {
                    /* try { // try from 001026b3 to 001026de has its CatchHandler @ 001029a9 */
    puts("Rip");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (check == 0x1f9) {
    win();
    FUN_00101c62();
  }
  else {
    loose();
  }
  ~basic_string((basic_string<char,std--char_traits<char>,std--allocator<char>> *)local_3d8);
  FUN_00102f94(local_3f8);
  if (local_30 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So we can see here, it is essentially calling `checkFunction` several times in a loop, and suming up all of it's outputs. If the sum is equal to `0x1f9`, we solve the challenge.

Which the `checkFunction` function looks like this:
```

ulong checkFunction(basic_string<char,std--char_traits<char>,std--allocator<char>> *string,
                   basic_string<char,std--char_traits<char>,std--allocator<char>> *input)

{
  int stringSize;
  int inputSize;
  undefined8 uVar1;
  long x;
  int *piVar2;
  char *output;
  char *pcVar3;
  undefined4 *check;
  undefined4 *checkArray;
  uint *returnPtr;
  uint returnVar;
  long y;
  long in_FS_OFFSET;
  uint local_a8;
  uint isEqual;
  int local_a0;
  int local_9c;
  int j;
  int i;
  int stackVar;
  ulong local_88;
  int output1;
  undefined4 uStack124;
  long inputStack0 [4];
  undefined4 p [8];
  undefined inputString [24];
  long local_20;
  char sOutput0;
 
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  stringSize = size();
  inputSize = size();
  FUN_00102b52(&output1);
  FUN_00102a6c(&local_88);
  p[0] = 0;
                    /* try { // try from 001016d9 to 001016dd has its CatchHandler @ 00101b1a */
  FUN_00102aa4(inputString,(long)(stringSize + 1),p,&local_88);
                    /* try { // try from 001016f9 to 001016fd has its CatchHandler @ 00101b06 */
  FUN_00102b8a(inputStack0,(long)(inputSize + 1),inputString,&output1);
  FUN_00102b0e(inputString);
  FUN_00102a88(&local_88);
  FUN_00102b6e(&output1);
  FUN_00102c38(p);
  FUN_00102c38(inputString);
  if ((stringSize == 0) || (inputSize == 0)) {
    returnVar = 0;
  }
  else {
    local_a0 = 1;
    while (local_a0 < stringSize + 1) {
                    /* try { // try from 0010178a to 001018e5 has its CatchHandler @ 00101b40 */
      uVar1 = operator[](string,(long)(local_a0 + -1));
      func7(p,uVar1,uVar1);
      x = multiply18(inputStack0,0);
      piVar2 = (int *)addMul4(x,(long)local_a0);
      *piVar2 = local_a0;
      local_a0 = local_a0 + 1;
    }
    local_9c = 1;
    while (local_9c < inputSize + 1) {
      uVar1 = operator[](input,(long)(local_9c + -1));
      func7(inputString,uVar1,uVar1);
      x = multiply18(inputStack0,(long)local_9c);
      piVar2 = (int *)addMul4(x,0);
      *piVar2 = local_9c;
      local_9c = local_9c + 1;
    }
    local_a8 = local_a8 & 0xffffff00;
    local_88 = func6(p);
    func5(&output1,&local_88,&local_88);
    func4(p,CONCAT44(uStack124,output1),&local_a8,CONCAT44(uStack124,output1));
    local_a8 = local_a8 & 0xffffff00;
    local_88 = func6(inputString);
    func5(&output1,&local_88,&local_88);
    func4(inputString,CONCAT44(uStack124,output1),&local_a8,CONCAT44(uStack124,output1));
    j = 1;
    while (j < inputSize + 1) {
      i = 1;
      while (i < stringSize + 1) {
        output = (char *)add(p,(long)j,(long)j);
        sOutput0 = *output;
        pcVar3 = (char *)add(inputString,(long)i,(long)i);
        isEqual = (uint)(sOutput0 != *pcVar3);
        x = multiply18(inputStack0,(long)j);
        piVar2 = (int *)addMul4(x,(long)(i + -1));
        output1 = *piVar2 + 1;
        x = multiply18(inputStack0,(long)(j + -1));
        piVar2 = (int *)addMul4(x,(long)i);
        local_88 = local_88 & 0xffffffff00000000 | (ulong)(*piVar2 + 1);
        x = multiply18(inputStack0,(long)(j + -1));
        piVar2 = (int *)addMul4(x,(long)(i + -1));
        local_a8 = isEqual + *piVar2;
        uVar1 = cmp(&local_a8,&local_88,&local_88);
        check = (undefined4 *)cmp(uVar1,&output1,uVar1);
        x = multiply18(inputStack0,(long)j);
        checkArray = (undefined4 *)addMul4(x,(long)i);
        *checkArray = *check;
        i = i + 1;
      }
      j = j + 1;
    }
    y = (long)stringSize;
    x = multiply18(inputStack0,(long)inputSize);
    returnPtr = (uint *)addMul4(x,y);
    returnVar = *returnPtr;
  }
  FUN_00102c54(inputString);
  FUN_00102c54(p);
  FUN_00102bf4(inputStack0);
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (ulong)returnVar;
}
```

Thing is, we don't actually need to understand the internal working of the function, to be able to know what the output will be. We can effectively find out what it does using gdb:

```
$    gdb ./gibberish_check_patched
GNU gdb (Ubuntu 8.2.91.20190405-0ubuntu3) 8.2.91.20190405-git
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
GEF for linux ready, type `gef' to start, `gef config' to configure
75 commands loaded for GDB 8.2.91.20190405-git using Python engine 3.7
[*] 5 commands could not be loaded, run `gef missing` to know why.
Reading symbols from ./gibberish_check_patched...
(No debugging symbols found in ./gibberish_check_patched)
gef➤  pie b *0x2648
gef➤  pie run
Stopped due to shared library event (no libraries added or removed)
Find the Key!
15935728

Breakpoint 1, 0x0000555555556648 in ?? ()
[+] base address 0x555555554000
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffda60  →  0x00005555557700f0  →  "dqzkenxmpsdoe_qkihmd"
$rbx   : 0x00007fffffffda80  →  0x00007fffffffda90  →  "15935728"
$rcx   : 0x000055555575e010  →  0x0000000000000005
$rdx   : 0x00007fffffffda80  →  0x00007fffffffda90  →  "15935728"
$rsp   : 0x00007fffffffd9c0  →  0x0000000000000000
$rbp   : 0x00007fffffffddf0  →  0x0000555555559860  →   push r15
$rsi   : 0x00007fffffffda80  →  0x00007fffffffda90  →  "15935728"
$rdi   : 0x00007fffffffda60  →  0x00005555557700f0  →  "dqzkenxmpsdoe_qkihmd"
$rip   : 0x0000555555556648  →   call 0x55555555564a
$r8    : 0x00005555557700d0  →  "dqzkenxmpsdoe_qkihmd"
$r9    : 0x00007ffff7fa6020  →  0x00007ffff7fa5168  →  0x00007ffff7e75b90  →  <__cxxabiv1::__class_type_info::~__class_type_info()+0> mov rax, QWORD PTR [rip+0x137df9]        # 0x7ffff7fad990
$r10   : 0x6               
$r11   : 0x00007ffff7e890c0  →  <std::locale::locale(std::locale+0> mov rax, QWORD PTR [rsi]
$r12   : 0x00007fffffffda80  →  0x00007fffffffda90  →  "15935728"
$r13   : 0x1a              
$r14   : 0x0               
$r15   : 0x0               
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0033 $ss: 0x002b $ds: 0x0000 $es: 0x0000 $fs: 0x0000 $gs: 0x0000
───────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9c0│+0x0000: 0x0000000000000000     ← $rsp
0x00007fffffffd9c8│+0x0008: 0x0000000000000000
0x00007fffffffd9d0│+0x0010: 0x0000000000000000
0x00007fffffffd9d8│+0x0018: 0x0002ffff00001f80
0x00007fffffffd9e0│+0x0020: 0x0000000000000000
0x00007fffffffd9e8│+0x0028: 0x00005555557701b0  →  0x0000555555770500  →  "dqzkenxmpsdoe_qkihmd"
0x00007fffffffd9f0│+0x0030: 0x00005555557704f0  →  0x0000000000000000
0x00007fffffffd9f8│+0x0038: 0x00007fffffffda00  →  0x00005555557701b0  →  0x0000555555770500  →  "dqzkenxmpsdoe_qkihmd"
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555663b                  lea    rax, [rbp-0x390]
   0x555555556642                  mov    rsi, rdx
   0x555555556645                  mov    rdi, rax
 → 0x555555556648                  call   0x55555555564a
   ↳  0x55555555564a                  push   rbp
      0x55555555564b                  mov    rbp, rsp
      0x55555555564e                  push   r12
      0x555555555650                  push   rbx
      0x555555555651                  sub    rsp, 0xa0
      0x555555555658                  mov    QWORD PTR [rbp-0xa8], rdi
─────────────────────────────────────────────────────── arguments (guessed) ────
0x55555555564a (
   $rdi = 0x00007fffffffda60 → 0x00005555557700f0 → "dqzkenxmpsdoe_qkihmd",
   $rsi = 0x00007fffffffda80 → 0x00007fffffffda90 → "15935728",
   $rdx = 0x00007fffffffda80 → 0x00007fffffffda90 → "15935728"
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "gibberish_check", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555556648 → call 0x55555555564a
[#1] 0x7ffff7bf3b6b → __libc_start_main(main=0x555555555d98, argc=0x1, argv=0x7fffffffded8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdec8)
[#2] 0x55555555556a → hlt
────────────────────────────────────────────────────────────────────────────────
gef➤  
```

Right now we can see that the input to `checkFunction` is the string `dqzkenxmpsdoe_qkihmd"`, and our input `15935728`. In the debugger, we see that this loop runs for `26` times. Each time it runs with a different string, which we can see from running `strings`:

```
$    strings gibberish_check_patched

.    .    .

dqzkenxmpsdoe_qkihmd
jffglzbo_zghqpnqqfjs
kdwx_vl_rnesamuxugap
ozntzohegxagreedxukr
xujaowgbjjhydjmmtapo
pwbzgymqvpmznoanomzx
qaqhrjofhfiuyt_okwxn
a_anqkczwbydtdwwbjwi
zoljafyuxinnvkxsskdu
irdlddjjokwtpbrrr_yj
cecckcvaltzejskg_qrc
vlpwstrhtcpxxnbbcbhv
spirysagnyujbqfhldsk
bcyqbikpuhlwordznpth
_xkiiusddvvicipuzyna
wsxyupdsqatrkzgawzbt
ybg_wmftbdcvlhhidril
ryvmngilaqkbsyojgify
mvefjqtxzmxf_vcyhelf
hjhofxwrk_rpwli_mxv_
enupmannieqqzcyevs_w
uhmvvb_cfgjkggjpavub
gktdphqiswomuwzvjtog
lgoehepwclbaifvtfoeq
nm_uxrukmof_fxsfpcqz
ttsbclzyyuslmutcylcm
```

When we try passing our input as one of the strings, we see something interesting. Here it is as it makes the `checkFunction` call:

```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9c0│+0x0000: 0x0000000000000000     ← $rsp
0x00007fffffffd9c8│+0x0008: 0x0000000000000000
0x00007fffffffd9d0│+0x0010: 0x0000000000000000
0x00007fffffffd9d8│+0x0018: 0x0002ffff00001f80
0x00007fffffffd9e0│+0x0020: 0x0000000000000000
0x00007fffffffd9e8│+0x0028: 0x00005555557701b0  →  0x0000555555770500  →  "dqzkenxmpsdoe_qkihmd"
0x00007fffffffd9f0│+0x0030: 0x00005555557704f0  →  0x0000000000000000
0x00007fffffffd9f8│+0x0038: 0x00007fffffffda00  →  0x00005555557701b0  →  0x0000555555770500  →  "dqzkenxmpsdoe_qkihmd"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x55555555663b                  lea    rax, [rbp-0x390]
   0x555555556642                  mov    rsi, rdx
   0x555555556645                  mov    rdi, rax
 → 0x555555556648                  call   0x55555555564a
   ↳  0x55555555564a                  push   rbp
      0x55555555564b                  mov    rbp, rsp
      0x55555555564e                  push   r12
      0x555555555650                  push   rbx
      0x555555555651                  sub    rsp, 0xa0
      0x555555555658                  mov    QWORD PTR [rbp-0xa8], rdi
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
0x55555555564a (
   $rdi = 0x00007fffffffda60 → 0x0000555555770110 → "dqzkenxmpsdoe_qkihmd",
   $rsi = 0x00007fffffffda80 → 0x00005555557700f0 → "dqzkenxmpsdoe_qkihmd",
   $rdx = 0x00007fffffffda80 → 0x00005555557700f0 → "dqzkenxmpsdoe_qkihmd"
)
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "gibberish_check", stopped, reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555556648 → call 0x55555555564a
[#1] 0x7ffff7bf3b6b → __libc_start_main(main=0x555555555d98, argc=0x1, argv=0x7fffffffded8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdec8)
[#2] 0x55555555556a → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  s
```

This is the output we see:

```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffd9c0│+0x0000: 0x0000000000000000     ← $rsp
0x00007fffffffd9c8│+0x0008: 0x0000000000000000
0x00007fffffffd9d0│+0x0010: 0x0000000000000000
0x00007fffffffd9d8│+0x0018: 0x0002ffff00001f80
0x00007fffffffd9e0│+0x0020: 0x0000000000000000
0x00007fffffffd9e8│+0x0028: 0x00005555557701b0  →  0x0000555555770500  →  "dqzkenxmpsdoe_qkihmd"
0x00007fffffffd9f0│+0x0030: 0x00005555557704f0  →  0x0000000000000000
0x00007fffffffd9f8│+0x0038: 0x00007fffffffda00  →  0x00005555557701b0  →  0x0000555555770500  →  "dqzkenxmpsdoe_qkihmd"
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555556642                  mov    rsi, rdx
   0x555555556645                  mov    rdi, rax
   0x555555556648                  call   0x55555555564a
 → 0x55555555664d                  add    DWORD PTR [rbp-0x40c], eax
   0x555555556653                  lea    rax, [rbp-0x390]
   0x55555555665a                  mov    rdi, rax
   0x55555555665d                  call   0x555555555380 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev@plt>
   0x555555556662                  lea    rax, [rbp-0x370]
   0x555555556669                  mov    rdi, rax
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "gibberish_check", stopped, reason: TEMPORARY BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x55555555664d → add DWORD PTR [rbp-0x40c], eax
[#1] 0x7ffff7bf3b6b → __libc_start_main(main=0x555555555d98, argc=0x1, argv=0x7fffffffded8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdec8)
[#2] 0x55555555556a → hlt
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  p $eax
$1 = 0x0
gef➤
```

So we can see that when our input string matched the other input, the output was `0x0`. This gave me an idea. What if the number return was the number of characters that the two inputs don't share. Doing a bit of trial and error showed that there is slightly more to it. It appears that it starts checking if our input is in the string, at the character that corresponds to the loop. For instance the first time `checkFunction` is called, it will start checking with the first character. After it finds a character from our input that does not match, it moves on to the next check

We need the collective output of all of the `checkFunction` calls to be `0x1f9` (`205`). There are `0x208` (`520`) characters present. That means that our input needs to have `15` matches with the strings provided. When I looked, the closest one I could find was `e` with `16`. So for this, I just swapped out one of the `e` characters for a character that would not overlap with the corresponding string it was being compared to. The string for this had to have one `e`, so the collisions would be decremented from `16` to `15`.

With that, we end up with the string `ee1eeeeeeeeeeeeeeeee`. When we try it:

```
$    ./gibberish_check
Find the Key!
ee1eeeeeeeeeeeeeeeee
Correct!
```

Just like that, we reversed the challenge!
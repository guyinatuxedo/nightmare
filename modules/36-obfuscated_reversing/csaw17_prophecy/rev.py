#First import pwntools
from pwn import *

#Establish the target, either remote connection or local process
target = process('./prophecy')
#target = remote("reversing.chal.csaw.io", 7668)

#Attach gdb
#gdb.attach(target)

#Print out the starting menu, prompt for input from user, then send filename
print target.recvuntil(">>")
raw_input()
target.sendline(".starcraft")

#Prompt for user input to pause
raw_input()

#Form the data to pass the check, then send it
check0 = "\x08\x25\x20\x17"
check1 = "\x4b"*4 + "\x00"  +  "\x4b"*4
check2 = "\x03"*1
check3 = "\x93\xea\xe4\x00"
check4 = "\x5a\x45\x52\x41\x54\x55\x4c"
check5 = "\x00\x53\x41\x56\x45\x44"
check6 = "\x00\x41\x4c\x4c"
target.send(check0 + check1 + check2 + check3 + check4 + check5 + check6)

#Drop to an interactive shell
target.interactive()

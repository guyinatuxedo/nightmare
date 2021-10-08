# Import pwntool utils
from pwn import process, p32

# Establish target process
target = process('just_do_it')

# Print out the starting prompt
print(target.recvuntil(b"password.\n"))

# Semd the password
target.sendline(b"P@SSW0RD\x00")

# Drop to an interactive shell, so we can read everything the binary
target.interactive()

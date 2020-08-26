# https://github.com/p4-team/ctf/blob/master/2018-08-18-whitehat/re06/README.md
# ^ That writeup helped me with unpacking issues

import base64
import struct


def mod(m, e, n):
    numArray = [0]*100
    index1 = 0
    while e > 0:
        numArray[index1] = e % 2
        index1 = index1 + 1
        e = e / 2
    num = 1
    index2 = index1 - 1
    while index2 >= 0:
        num = num * num % n
        if (numArray[index2] == 1):
            num = num * m % n
        index2 = index2 - 1
    return (num )

base64encodeString = "iB6WcuCG3nq+fZkoGgneegMtA5SRRL9yH0vUeN56FgbikZFE1HhTM9R4tZPghhYGFgbUeHB4tEKRRNR4Ymu0OwljQwmRRNR4jWBweOKRRyCRRAljLGQ="
desiredOutput = base64.b64decode(base64encodeString)

flag = ""
for i in range(0, len(desiredOutput), 2):
    # Restrict it to ASCII characters first
    for c in range(33, 128):
        out = mod(c, 9157, 41117)
        check = struct.unpack("H", desiredOutput[i:i+2])[0]
        if (out == check):
            flag += chr(c)

print flag
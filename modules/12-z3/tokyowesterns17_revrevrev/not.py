#Establish the flag after the binary not
flag = [ 0xd5, 0x15, 0x3d, 0xd5, 0x9d, 0x21, 0x71, 0xf1, 0xa1, 0x69, 0x31, 0x61, 0xdd, 0x89, 0xb9, 0x49, 0xb9, 0x09, 0xa1, 0x13, 0x93, 0x09, 0x19, 0xc9, 0xe1, 0xf1, 0xa1, 0x65, 0xd9, 0x29, 0x41]

#Establish the function to execute the binary not
def not_inp(inp):
    output = 0x0
    result = ""
    string = bin(inp).replace("0b", "")
    #Check if there are less than 8 bits, and if so add zeroes to the front to get 8 bits
    if len(string) < 8:
        diff = 8 - len(string)
        string = diff*"0" + string
    print "Binary string is:  " + string
    
    #Swap the ones with zeroes, and vice versa
    for s in string:
        if s == "0":
            result += "1"
        if s == "1":
            result += "0"
    print "Binary inverse is: " + result
    
    #Convert the binary string to an int, and return it
    output = int(result, 2)
    return output

#Establish the array which will hold the output
out = []
#Iterate through each character of the flag, and undo the binary not
for i in flag:
    x = not_inp(i)
    out.append(x)
    print hex(x)

#Print the flag before the binary not
print "alt_flag = " + str(out)
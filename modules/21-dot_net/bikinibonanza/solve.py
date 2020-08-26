# Import hashlib
import hashlib

# Esablish the integer array which will be used for xpromg
x0 = [ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113]

#Define the function which will tun the first loop
def enc(inp):
	#Establish the length of the input, and the for loop to run 24 times
	len_inp = len(inp) 
	for i in range(1, 25):
		#Pass the input to the xor function, and print the output
		out = ""
		c = inp
		out = xor(c, i)
		print out


def xor(inp, c):
	# Establish the output string, and the first for loop which will run for the length of the input
	output = ""
	for i in xrange(len(inp)):
		current_character = inp[i]
		# Run the second for loop, which will run as many times equal to the current hour, and xor the input against the int array
		for j in range(1, c):
			current_character = chr(x0[j] ^ ord(current_character))			
		# Add the output of the previous for loop to the output string
		output += current_character
	#Hash and return the output
	hash = hashlib.md5()
	hash.update(output)
	output = hash.hexdigest()
	return output

# Establish the string "NeEd_MoRe_Bawlz" and run the enc function
enc_input = "NeEd_MoRe_Bawlz"
enc(enc_input)
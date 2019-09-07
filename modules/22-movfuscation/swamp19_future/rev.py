# Import the libraries
from subprocess import *
import string
import sys

#Establish the command to count the number of instructions
command = "perf stat -x : -e instructions:u " + sys.argv[1] + " 1>/dev/null" 
flag = 'flag{'
while True:
	ins_count = 0
	count_chr = ''
	for i in (string.lowercase + string.digits):
		target = Popen(command, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
		target_output, _ = target.communicate(input='%s\n'%(flag + i))
		instructions = int(target_output.split(':')[4])
		#print hex(instructions)
		if instructions > ins_count:
			count_chr = i
			ins_count = instructions
	flag += count_chr
	print flag

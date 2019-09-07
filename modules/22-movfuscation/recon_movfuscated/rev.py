# Import the libraries
from subprocess import *
import string
import sys

# Establish the command to count the number of instructions, pipe output of command to /dev/null
command = "perf stat -x : -e instructions:u " + sys.argv[1] + " 1>/dev/null"

# Establish the empty flag
flag = ''


while True:
    # Reset the highest instruction value and corresponding character
    ins_count = 0
    count_chr = ''
    # Iterate Through all printable characters
    for i in string.printable:
        # Start a new process for the new character
        target = Popen(command, stdout=PIPE, stdin=PIPE, stderr=STDOUT, shell=True)
        # Give the program the new input to test, and grab the store the output of perf-stat in target_output
        target_output, _ = target.communicate(input='%s\n'%(flag + i))
        # Filter out the instruction count
        instructions = int(target_output.split(':')[0])
        # Check if the new character has the highest instruction count, and if so record the instruction count and corresponding character
        if instructions > ins_count:
            count_chr = i
            ins_count = instructions
    # Add the character with the highest instruction count to flag, print it, and restart
    flag += count_chr
    print flag
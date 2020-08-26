import angr
import claripy

# Establish the project

target = angr.Project('icancount', auto_load_libs=False)

# Because PIE is enabled, we have to grab the randomized addresses for various things

# Grab the address of flag_buf which stores our input
flag_buf = target.loader.find_symbol('flag_buf').rebased_addr

# Grab the address of the check_flag function which is where we will start
check_flag = target.loader.find_symbol('check_flag').rebased_addr

# Grab the instruction addresses which indicate either a success or a failure

desired_adr = 0xf9a + target.loader.main_object.min_addr
failed_adr = 0xfae + target.loader.main_object.min_addr

# Establish the entry state
entry_state = target.factory.blank_state(addr = check_flag)

# Establish our input, 0x13 bytes
inp = claripy.BVS('inp', 0x13*8)

# Assign the condition that each byte of our input must be between `0-9` (0x30 - 0x39)
for i in inp.chop(8):
    entry_state.solver.add(entry_state.solver.And(i >= '0', i <= '9'))

# Set the memory region of flag_buf equal to our input
entry_state.memory.store(flag_buf, inp)

# Establish the simulation
simulation = target.factory.simulation_manager(entry_state)

# Setup the simulation with the addresses to specify a success / failure
simulation.use_technique(angr.exploration_techniques.Explorer(find = desired_adr, avoid = failed_adr))

# Run the simulation
simulation.run()

# Parse out the solution, and print it
flag_int = simulation.found[0].solver.eval(inp)

flag = ""
for i in xrange(19):
    flag = chr(flag_int & 0xff) + flag
    flag_int = flag_int >> 8

print "flag: PCTF{" + flag + "}"


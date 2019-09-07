# Import angr and claripy
import angr
import claripy

# Establish the angr
target = angr.Project('./fairlight', load_options={"auto_load_libs": False})

# Establish our input as an array of 0xe bytes
inp = claripy.BVS("inp", 0xe*8)

# Establish the entry state, with our input passed in as an argument
entry_state = target.factory.entry_state(args=["./fairlight", inp])

# Establish the simulation with the entry state
simulation = target.factory.simulation_manager(entry_state)

# Start the symbolic execution, specify the desired instruction address, and the one to avoid
simulation.explore(find = 0x401a6e, avoid = 0x040074d)

# Parse the correct input and print it
solution = simulation.found[0]
print solution.solver.eval(inp, cast_to=bytes)
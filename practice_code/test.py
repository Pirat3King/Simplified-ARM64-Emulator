"""
File: test.py
Authors: William Turner, Omkar Ashish Pednekar
Brief: Simple ARM64 emulator
Date: 2023/10/04
"""


# This sort of does the whole thing
# 
#
# TODO Testing: step through provided code in gdb to verify each instruction, registers, stack, etc

import re
import argparse
import hexdump
from pathlib import Path

#################################################################
#                       Initialization
#################################################################

dash_line = '-' * 80 # For printing 

# Init registers
keys = [f"X{i}" for i in range(31)] + ["SP", "PC"]
registers = {key: 0 for key in keys}

n_bit = 0
z_bit = 0

# Print current register values
def print_reg():
    s = "Registers"
    print(dash_line + "\n" + s.center(80) + "\n" + dash_line)

    for k, v in registers.items():
        v_hex = f'0x{v:016x}'
        print(f"{k}: {v_hex}")
    print(f"N bit: {n_bit}")
    print(f"Z bit: {z_bit}")

# Init stack
stack_mem = [0] * 256

# Init stack pointer
registers["SP"] = len(stack_mem) - 1

# Stack push
def push(value):
    
    sp_value = registers["SP"]
    
    # If stack is not full
    if sp_value >= 0:
        stack_mem[sp_value] = value
        
        sp_value -= 1
        registers["SP"] = sp_value
    else:
        print("Stack overflow")

# Stack pop
def pop():
    sp_value = registers["SP"]
    
    # If stack is not empty
    if sp_value < len(stack_mem) - 1:
        sp_value += 1 # top
        value = stack_mem[sp_value]
        
        registers["SP"] = sp_value
        
        return value
    else:
        print("Stack underflow")

# Print current stack memory
def print_stack():
    s = "Stack"
    print(dash_line + "\n" + s.center(80) + "\n" + dash_line)
    stack_bytes = bytes(stack_mem)
    hexdump.hexdump(stack_bytes)

# Store addrs for branches
addresses = []

code_lines = []












# Read each line of instructions from the file
with open("test_code_to_emulate/advanced/test5/test5.txt", 'r') as file:
    address = 0  # Initialize the address
    for line in file:
        stripped_line = re.sub(r'//.*$', '', line).strip() # strip comments and extra whitespace

        # If line is not empty
        if stripped_line:  
            code_lines.append(stripped_line)
            addresses.append(format(address, 'x'))
            address += 4

# Helper function to parse operand strings into registers
def parse_arg(arg):  
    if arg.startswith("xzr"):
        arg = arg.replace(',', '').strip()
        print(f"Operand: {arg}")
        return 0
    
    elif arg.startswith("x") or arg.startswith("w"):
        arg = arg.replace(',', '').strip()
        print(f"Operand: {arg}")
        return int(arg[1:])
    
    elif arg.startswith("sp"):
        #arg = arg.replace(',', '').strip()
        print(f"Operand: {arg}")
        return 31  # Use index 31 for the stack pointer register
    
    elif arg.startswith("#"):  # Handle immediate values
        print(f"Operand: {arg}")
        arg = arg[1:]  # Remove the '#' prefix
        
        if arg.startswith("0x"):
            return int(arg, 16)
        else:
            return int(arg)
    
    elif arg.startswith("0x"):
        print(f"Operand: {arg}")
        return int(arg, 16)
    
    elif arg.startswith("[") and arg.endswith("]"):
        # Handle pre-index addressing mode, e.g., [sp, #56]
        print(f"Operand: {arg}")
        parts = arg[1:-1].split(',')
        if len(parts) == 2:
            print("Split Operands:")
            base_register = parse_arg(parts[0].strip())
            offset = parse_arg(parts[1].strip())
            return base_register + offset
        elif len(parts) == 1:
            # Handle the case of a single item, e.g., [sp]
            base_register = parse_arg(parts[0].strip())
            return base_register
    else:
        return arg

# Start emulating the instructions
pc = 0  # Program counter
while pc < len(code_lines): 
    line = code_lines[pc].strip()

    print(f"Line: {line}")
    
    # Split the line into tokens based on whitespace
    tokens = line.split()
    
    # Check if the line is not empty
    if len(tokens) > 2:  # Check for at least 3 tokens
        # Get the instruction and arguments
        address = tokens[0].strip(':')
        instruction = tokens[2]
        args = tokens[3:]
        
        address = '0x' + address
        if hex(pc*4) != address:
            raise ValueError(f"Error: stack_mem address error:\nPC: {pc}\nAddr from input: {address}")

        # Combine pre-index operands back into a single operand
        if len(args) >= 3 and args[1].startswith("["):
            args[1] = args[1] + args[2]
            args.pop(2)

        print(f"Mnemonic: {instruction}")
        
        # Emulate the instruction based on the mnemonic
        if instruction == 'sub':
            rd = parse_arg(args[0])
            rn = parse_arg(args[1])
            imm = parse_arg(args[2])
            if rd == 31:
                sp -= imm
            else:
                registers[rd] = registers[rn] - imm
        elif instruction == 'mov':
            rd = parse_arg(args[0])
            imm = parse_arg(args[1])
            if rd == 31:
                sp = imm
            else:
                registers[rd] = imm
        elif instruction == 'strb':
            rt = parse_arg(args[0])
            addr = parse_arg(args[1])
            if rt == 31:
                stack_mem[addr] = 0
            else:
                stack_mem[addr] = registers[rt] & 0xFF
        elif instruction == 'str':
            rt = parse_arg(args[0])
            addr = parse_arg(args[1])
            if rt == 31:
                for i in range(8):
                    stack_mem[addr + i] = 0
            else:
                for i in range(8):
                    stack_mem[addr + i] = (registers[rt] >> (i * 8)) & 0xFF
        elif instruction == 'ldr':
            rt = parse_arg(args[0])
            addr = parse_arg(args[1])
            if rt == 31:
                registers[rt] = 0
            else:
                registers[rt] = 0
                for i in range(8):
                    registers[rt] |= (stack_mem[addr + i] << (i * 8))
        elif instruction == 'b':
            # Calculate the target address based on the specified line number
            target_addr = args[0]
            pc = addresses.index(target_addr)  # Set pc to the index of the target address
            continue
        elif instruction == 'and':
            rd = parse_arg(args[0])
            rn = parse_arg(args[1])
            imm = parse_arg(args[2])
            registers[rd] = registers[rn] & imm
        elif instruction == 'cmp':
            rn = parse_arg(args[0])
            imm = parse_arg(args[1])
            if rn < imm:
                pc += 1  # Skip the next instruction
        elif instruction == 'eor':
            rd = parse_arg(args[0])
            rn = parse_arg(args[1])
            imm = parse_arg(args[2])
            registers[rd] = registers[rn] ^ imm
        elif instruction == 'add':
            rd = parse_arg(args[0])
            rn = parse_arg(args[1])
            imm = parse_arg(args[2])
            if rd == 31:
                sp = sp + imm
            else:
                registers[rd] = registers[rn] + imm
    
    pc += 1

# Print the final state of the registers and stack_mem
# print("Final register values:")
# for i in range(32):
#     print(f"x{i}: {registers[i]}")
# print("stack_mem contents:")
# for i in range(len(stack_mem)):
#     print(f"mem[{i}]: {stack_mem[i]}")


def main():
    print_reg()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help="path to text file containing assembly code", type=Path)
    #TODO Maybe have all the prints from tasks 1-4 only execute in verbose mode. So, emulated code
    # would run by default but all the extra stuff would not print
    #parser.add_argument("-v", "--verbose" help="increase output verbosity", action="store_true")
    args = parser.parse_args()

    main()


if mnemonic == "SUB":
    rd = parse_op(ops[0])
    rn = parse_op(ops[1])
    imm = parse_op(ops[2])
    if rd == 31:
        sp -= imm
    else:
        registers[rd] = registers[rn] - imm

elif mnemonic == "EOR":
    rd = parse_op(ops[0])
    rn = parse_op(ops[1])
    imm = parse_op(ops[2])
    registers[rd] = registers[rn] ^ imm

elif mnemonic == "ADD":
    rd = parse_op(ops[0])
    rn = parse_op(ops[1])
    imm = parse_op(ops[2])
    if rd == 31:
        sp = sp + imm
    else:
        registers[rd] = registers[rn] + imm

elif mnemonic == "AND":
    rd = parse_op(ops[0])
    rn = parse_op(ops[1])
    imm = parse_op(ops[2])
    registers[rd] = registers[rn] & imm

elif mnemonic == "MUL":
    pass

elif mnemonic == "MOV":
    rd = parse_op(ops[0])
    imm = parse_op(ops[1])
    if rd == 31:
        sp = imm
    else:
        registers[rd] = imm

elif mnemonic == "STR":
    rt = parse_op(ops[0])
    addr = parse_op(ops[1])
    if rt == 31:
        for i in range(8):
            stack_mem[addr + i] = 0
    else:
        for i in range(8):
            stack_mem[addr + i] = (registers[rt] >> (i * 8)) & 0xFF

elif mnemonic == "STRB":
    rt = parse_op(ops[0])
    addr = parse_op(ops[1])
    if rt == 31:
        stack_mem[addr] = 0
    else:
        stack_mem[addr] = registers[rt] & 0xFF
"""
File: main.py
Authors: William Turner, Omkar Ashish Pednekar
Brief: Simple ARM64 emulator
Date: 2023/10/04
"""

import re
import sys
import argparse
import hexdump
from pathlib import Path

#################################################################
#                       Utilities
#################################################################

# Task 1 - Print parsed mnemonics
# TODO find where to call this so every line prints (or change)
def print_task1(count, mnemonic, ops):

    print("--------------------------------------")
    print(f"Instruction #: {count}")
    print("--------------------------------------")
    print(f"Mnemonic: {mnemonic}")

    for i, op in enumerate(ops, start=1):
        print(f"Operand #{i}: {op}")
        

# Print current register values
def print_reg():
    # Pretty header
    s = "Registers"
    print(dash_line + "\n" + s.center(80) + "\n" + dash_line)

    for k, v in registers.items():
        v_hex = f'0x{v:016x}'
        print(f"{k}: {v_hex}")
    print(f"N bit: {n_bit}")
    print(f"Z bit: {z_bit}")

# Print current stack memory
def print_stack():
    # Pretty header
    s = "Stack"
    print(dash_line + "\n" + s.center(80) + "\n" + dash_line)

    stack_bytes = bytes(stack_mem)
    hexdump.hexdump(stack_bytes)

# Stack push with SP register
def stack_push(value):
    sp_value = registers["SP"]
    
    # If stack is not full
    if sp_value >= 0:
        stack_mem[sp_value] = value
        
        sp_value -= 1
        registers["SP"] = sp_value
    else:
        print("Stack overflow")

# Stack pop with SP register
def stack_pop():
    sp_value = registers["SP"]
    
    # If stack is not empty
    if sp_value < len(stack_mem) - 1:
        sp_value += 1 # top
        value = stack_mem[sp_value]
        
        registers["SP"] = sp_value
        
        return value
    else:
        print("Stack underflow")

#################################################################
#                           Parsers
#################################################################

# Read assembly code from input file, save each line in a list keep track of addressing
def parse_file():
    input_file = args.input_file

    try:
        with open(input_file, 'r') as f:
            address = 0 
            for line in f:
                stripped_line = re.sub(r'//.*$', '', line).strip() # strip comments and extra whitespace

                # If line is not empty
                if stripped_line:  
                    code_lines.append(stripped_line)
                    addresses.append(format(address, 'x'))
                    address += 4
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)

# Parse the each line from the input file into the address, mnemonic, and operands
def parse_instr():
    line = code_lines[registers["PC"]].strip()

    print(f"Line: {line}")
    
    # Split line into parts based on whitespace
    parts = line.split()
    
    # If line is not empty
    if len(parts) > 2:
        # Get mnemonic and operands
        mnemonic = parts[2].upper()
        ops = [i.upper() for i in parts[3:]]
        
        # Check that PC lines up with address from line
        # TODO do we even need this?
        address = parts[0].strip(':')
        addr_hex = "0x"+address
        pc = registers["PC"] * 4
        if hex(pc) != addr_hex:
            raise ValueError(f"Error: stack_mem address error:\nPC: {pc}\nAddr from input: {address}")

        # Combine pre-index operands back into a single operand because whitespace split
        if len(ops) >= 3 and ops[1].startswith('['):
            ops[1] = ops[1] + ops[2]
            ops.pop(2)

        # Remove commas from non-pre-index operands 
        for i in range(len(ops)):
            if not ops[i].startswith('['):
                ops[i] = ops[i].replace(',', '')

    else:
        pass #empty line TODO ?

    return mnemonic, ops

# Parse operand strings and return values
# TODO Task 1 printing - mnemonics and operands
#   op = op.replace(',', '').strip()
#   print(f"Operand: {op}")
# TODO Task 6 - 32 bit registers
def parse_op(op):  

    print(f"Operand: {op}")

    if op.startswith("XZR"):
        return 0
    
    elif op.startswith("X") or op == "SP":
        return registers[op]
    
    elif op.startswith("W"): 
        pass
    
    elif op.startswith("#"):  # Immediate values
        op = op[1:]
        
        if op.startswith("0X"):
            return int(op, 16)
        else:
            return int(op)
    
    elif op.startswith("[") and op.endswith("]"): # Pre-index addressing
        parts = op[1:-1].split(',')
        base_reg = parse_op(parts[0])
        
        if len(parts) == 2:
            offset = parse_op(parts[1].strip())
            return base_reg + offset
        
        elif len(parts) == 1:
            return base_reg
    else:
        raise ValueError(f"Error: Operand '{op}' not handled by this application")

#################################################################
#                           Logic
#################################################################

# Instruction emulation
# TODO the things
def emulate():
    while registers["PC"] < len(code_lines):
        
        mnemonic, ops = parse_instr()
            
        if mnemonic == "SUB":
            pass

        elif mnemonic == "EOR":
            pass

        elif mnemonic == "ADD":
            pass

        elif mnemonic == "AND":
            pass
        
        elif mnemonic == "MUL":
            pass

        elif mnemonic == "MOV":
            pass

        elif mnemonic == "STR":
            pass

        elif mnemonic == "STRB":
            pass
        
        elif mnemonic == "LDR":
            pass
        
        elif mnemonic == "LDRB":
            pass

        elif mnemonic == "NOP":
            pass
                   
        elif mnemonic == "B":
            target_addr = ops[0]
            registers["PC"] = addresses.index(target_addr)
            continue

        elif mnemonic == "B.GT":
            pass

        elif mnemonic == "B.LE":
            pass
        
        elif mnemonic == "CMP":
            rn = parse_op(ops[0])
            imm = parse_op(ops[1])
            if rn < imm:
                registers["PC"] += 1  # Skip next instruction
        
        elif mnemonic == "RET":
            return
        
        else:
            raise ValueError(f"Error: Mnemonic '{mnemonic}' not handled by this application")
        
        
        registers["PC"] += 1

#################################################################
#                           Main
#################################################################

def main():
    parse_file()
    emulate()


#################################################################
#                       Initialization
#################################################################

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", help="path to text file containing assembly code", type=Path)
    #TODO Maybe have all the prints from tasks 1-4 only execute in verbose mode. So, emulated code
    # would run by default but all the extra stuff would not print
    #parser.add_argument("-v", "--verbose" help="increase output verbosity", action="store_true")
    args = parser.parse_args()

    dash_line = '-' * 80 # For printing 

    # Init registers
    keys = [f"X{i}" for i in range(31)] + ["SP", "PC"]
    registers = {key: 0 for key in keys}

    n_bit = 0
    z_bit = 0

    # Init stack
    stack_mem = [0] * 256

    # Init stack pointer
    registers["SP"] = len(stack_mem) - 1

    # Store addrs for branches
    addresses = []

    # Store each line from input file
    code_lines = []

    main()

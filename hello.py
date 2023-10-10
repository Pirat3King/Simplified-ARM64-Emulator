"""
File: main.py
Authors: William Turner, Omkar Ashish Pednekar
Brief: Simple ARM64 emulator
Date: 2023/10/04
"""

import re
import os
import sys
import argparse
import hexdump
from pathlib import Path

#################################################################
#                       Utilities
#################################################################

# Task 1 - Print parsed instructions
def print_task1(count, mnemonic, ops):

    s = f"Instruction #{count + 1}"
    print(dash_line + "\n" + s.center(80) + "\n" + dash_line)
    print(f"Mnemonic: {mnemonic}")

    for i, op in enumerate(ops, start=1):
        print(f"Operand #{i}: {op}")
        

# Print current register values
def print_reg():
    # Pretty header
    s = "Registers"
    print(dash_line + "\n" + s.center(80) + "\n" + dash_line)

    # Print in 3 columns for easy viewing
    col_width = max(len(k) for k in registers.keys()) + 1
    cols = 3
    rows = len(registers) // cols
    items = list(registers.items())

    for r in range(rows):
        for c in range(cols):
            i = r + c * rows
            if i < len(items):
                key, value = items[i]
                k = f"{key}:"
                v_hex = f"0x{value:016x}"
                print(f'{k:<{col_width}} {v_hex}', end='\t')
        print()

    print(f"N bit: {int(flag_n)}")
    print(f"Z bit: {int(flag_z)}")

# Print current stack memory
def print_stack():
    # Pretty header
    s = "Stack"
    print(dash_line + "\n" + s.center(80) + "\n" + dash_line)

    stack_bytes = bytes(stack_mem)
    hexdump.hexdump(stack_bytes)

#Not sure if we actually need these, but good to have
# Stack push with SP register
def stack_push(value):
    sp_value = registers["SP"]
    
    # If stack is not full
    if sp_value >= 0:
        stack_mem[sp_value] = value
        
        sp_value -= 1
        registers["SP"] = sp_value
    else:
        raise ValueError("Stack overflow")

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
        raise ValueError("Stack underflow")
    
# clear console for dynamic output
def clearConsole():
    command = 'clear'
    if os.name in ('nt', 'dos'):  # If windows
        command = 'cls'
    os.system(command)

#################################################################
#                           Parsers
#################################################################

# Read assembly code from input file, save each line in a list keep track of addressing
def parse_file():
    input_file = args.input_file

    try:
        with open(input_file, 'r') as f:
            for line in f:
                stripped_line = re.sub(r'//.*$', '', line).strip() # strip comments and extra whitespace

                # If line is not empty
                if stripped_line:  
                    code_lines.append(stripped_line)
                    address = int(line.split()[0].strip(':'),16) # Extract address from first field
                    addresses.append(address)
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)

# Parse the line from the input file corresponding to the current PC into the mnemonic and operands
def parse_instr(): 
    line_num = addresses.index(registers["PC"])
    line = code_lines[line_num]
    
    # Split line into parts based on whitespace
    parts = line.split()
    
    # If line is not empty
    if len(parts) > 2:
        
        mnemonic = parts[2].upper()
        ops = [i.upper() for i in parts[3:]]
        
        # Combine pre-index operands back into a single operand because whitespace split
        if len(ops) >= 3 and ops[1].startswith('['):
            ops[1] = ops[1] + ops[2]
            ops.pop(2)

        # Remove commas from non-pre-index operands 
        for i in range(len(ops)):
            if not ops[i].startswith('['):
                ops[i] = ops[i].strip(',')

    else:
        pass #empty line TODO ?

    return mnemonic, ops

# Parse operand strings and return values
# TODO Task 6 - 32 bit registers
def parse_op(op):  
    if op.startswith("XZR"):
        return 0
    
    elif op.startswith("X") or op == "SP":
        return registers[op]
    
    elif op.startswith("W"): 
        reg_name = op[1:]        
        if reg_name in registers:
            # Read 64-bit register and zero-extend it to 32 bits
            value = registers[reg_name] & 0xFFFFFFFF
            return value
    
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
        
        else:
            return base_reg

    else:
        raise ValueError(f"Error: Operand '{op}' not handled by this application")

#################################################################
#                           Logic
#################################################################

# Instruction emulation
# TODO the things
def emulate():
    while True:
        mnemonic, ops = parse_instr()

        clearConsole()
        print_task1((registers["PC"] // 4), mnemonic, ops)
            
        if mnemonic == "SUB":
            rd = ops[0]
            rn = ops[1]
            op2 = parse_op(ops[2])
               
            registers[rd] = registers[rn] - op2

            flag_z= registers[rd] == 0
            flag_n = (registers[rd] & (1 << 31)) != 0
    
        elif mnemonic == "EOR":
            rd = ops[0]
            rn = ops[1]
            op2 = parse_op(ops[2])
            registers[rd] = registers[rn] ^ op2

            flag_z= registers[rd] == 0
            flag_n = (registers[rd] & (1 << 31)) != 0

        elif mnemonic == "ADD":
            rd = ops[0]
            rn = ops[1]
            op2 = parse_op(ops[2])
            registers[rd] = registers[rn] + op2

            flag_z= registers[rd] == 0
            flag_n = (registers[rd] & (1 << 31)) != 0

        elif mnemonic == "AND":
            rd = ops[0]
            rn = ops[1]
            op2 = parse_op(ops[2])
            registers[rd] = registers[rn] & op2
        
        elif mnemonic == "MUL":
            rd = ops[0]
            rn = ops[1]
            rm = ops[2]
            registers[rd] = registers[rn] * registers[rm]

        elif mnemonic == "MOV":
            rd = ops[0]
            op2 = parse_op(ops[1])
            
            registers[rd] = op2

        elif mnemonic == "STR":          
            rt = ops[0]  # Source register
            addr = parse_op(ops[1])  # Memory address

            if rt == "XZR":
                for i in range(8):
                    stack_mem[addr + i] = 0
            else:
                val = registers[rt]

                for i in range(8):
                    stack_mem[addr + i] = (val >> (i * 8))

        elif mnemonic == "STRB":
            rt = ops[0]
            addr = parse_op(ops[1])

            stack_mem[addr] = registers[rt]
        
        elif mnemonic == "LDR":
            rt = ops[0]
            addr = parse_op(ops[1])

            if addr < 0 or addr + 7 >= len(stack_mem):
                #print("Error: Memory access out of bounds")
                raise ValueError("Error: Memory access out of bounds")

            val = 0
            for i in range(8):
                val |= (stack_mem[addr + i] << (i * 8)) # Read 8 "bytes" of memory and merge into 1 

            registers[rt] = val
        
        elif mnemonic == "LDRB":
            rt = ops[0]
            addr = parse_op(ops[1])
            
            if addr < 0 or addr >= len(stack_mem):
                #print("Error: Memory access out of bounds")
                raise ValueError("Error: Memory access out of bounds")  

            registers[rt] = stack_mem[addr]

        elif mnemonic == "NOP":
            pass
                   
        elif mnemonic == "B":
            registers["PC"] = int(ops[0],16)
            print_reg()
            print_stack()
            continue

        elif mnemonic == "B.GT":
            if not flag_n and not flag_z:
                registers["PC"] = int(ops[0],16)
                print_reg()
                print_stack()
                continue

        elif mnemonic == "B.LE":
            if flag_n or flag_z:
                registers["PC"] = int(ops[0],16)
                print_reg()
                print_stack()
                continue
        
        elif mnemonic == "CMP":
            rd = parse_op(ops[0])
            imm = parse_op(ops[1])
            
            res = rd - imm

            flag_z = res == 0
            flag_n = res < 0
        
        elif mnemonic == "RET":
            print_reg()
            print_stack()
            return
        
        else:
            raise ValueError(f"Error: Mnemonic '{mnemonic}' not handled by this application")
        
        print_reg()
        print_stack()
        input("\nPress ENTER to continue: \n")

        registers["PC"] += 4

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
    registers = {key: 0x0 for key in keys}

    flag_n = False
    flag_z = False

    # Init stack
    stack_mem = [0] * 256

    # Init stack pointer
    registers["SP"] = len(stack_mem) - 1

    # Store addrs for branching
    addresses = []

    # Store each line from input file
    code_lines = []

    main()

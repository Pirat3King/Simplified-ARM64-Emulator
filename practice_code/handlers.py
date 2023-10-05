"""
File: handlers.py
Authors: William Turner, Omkar Ashish Pednekar
Brief: Implementation of select ARM64 instructions
Date: 2023/10/03
"""

#TODO Need to implement register dict
#TODO Probably need to pass the stack too

# Call instruction handlers based on provided mnemonic
def switch(mnemonic, reg, ops):
    match mnemonic:
        case "sub":
            sub(reg, ops)
        case "eor":
            eor(reg, ops)
        case "add":
            add(reg, ops)
        case "and":
            log_and(reg, ops)
        case "mul":
            mul(reg, ops)
        case "mov":
            mov(reg, ops)
        case "str":
            str(reg, ops)
        case "strb":
            strb(reg, ops)
        case "ldr":
            ldr(reg, ops)
        case "ldrb":
            ldrb(reg, ops)
        case "nop":
            nop(reg, ops)
        case "b":
            b(reg, ops)
        case "b.gt":
            bgt(reg, ops)
        case "b.le":
            ble(reg, ops)
        case "cmp":
            cmp(reg, ops)
        case "ret":
            ret(reg, ops)
        case _:
            raise ValueError(f"Error: Mnemonic '{mnemonic}' not handled by this application")

# This is just an experiment to test if my logic works. Change whatever you want.
def sub(reg, ops):
    dst_reg, src1, src2 = ops

    if src2.startswith('#'):
        # src2 is an immediate value
        val = int(src2[1:],16)
        reg[dst_reg] = reg[src1] - val
    else:
        # src2 is a register
        reg[dst_reg] = reg[src1] - reg[src2]

def eor(reg, ops):
    pass

def add(reg, ops):
    pass

def log_and(reg, ops):
    pass

def mul(reg, ops):
    pass

def mov(reg, ops):
    pass

def str(reg, ops):
    pass

def strb(reg, ops):
    pass

def ldr(reg, ops):
    pass

def ldrb(reg, ops):
    pass

def nop(reg, ops):
    pass

def b(reg, ops):
    pass

def bgt(reg, ops):
    pass

def ble(reg, ops):
    pass

def cmp(reg, ops):
    pass

def ret(reg, ops):
    pass

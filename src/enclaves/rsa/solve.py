from z3 import *

leaked_r8 = 0xda0bffbc85f60f8e
leaked_r9 = 0x8756bd1b #missing
leaked_r10 = 0x4988af5e43d7690c


rsi_8 = leaked_r10 // leaked_r8

print(hex(rsi_8))
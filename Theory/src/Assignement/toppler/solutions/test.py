#!/usr/bin/env python3
from pwn import *

orig_elf = 'toppler_basc/toppler32'
out_elf  = 'toppler_basc/toppler32_nocollisions'

# Load the ELF file
elf = ELF(orig_elf)

# walking function address
walking_fun = 0x0805bd9c

# Calculate and print the offset
offset = walking_fun - elf.address
print(f"Base address: {hex(elf.address)}")
print(f"Virtual address: {hex(walking_fun)}")
print(f"Offset: {hex(offset)}")

elf.save(out_elf)



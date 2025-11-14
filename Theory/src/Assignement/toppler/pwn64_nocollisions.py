#!/usr/bin/env python3
from pwn import *

orig_elf = 'toppler_basc/toppler64'
out_elf  = 'toppler_basc/toppler64_nocollisions'

# walking function address
walking_fun = 0x0041d0bc

# list of CALL sites to be modified in top_testcollision()
call_sites = [
    0x0041e2bf,
    0x0041e248,
    0x0041e25b,
    0x041e1b2,
    0x0041e1c3
]

elf = ELF(orig_elf)

for symbol, addr in elf.symbols.items():
    if addr == walking_fun:
        print(f"Check walking function in {hex(walking_fun)}: {symbol}")
        break
else:
    print(f"No symbol found at {hex(walking_fun)}")

print("\nDisassembly walking function:")
print(disasm(elf.read(walking_fun, 21)))


# Patching CALL toppler() instruction in top_testcollision() to point to walking() 
for call_site in call_sites:
    # offset: target - (source + 5)
    offset = walking_fun - (call_site + 5)
    
    elf.write(call_site, b'\xE8' + p32(offset,signed=True))
    
    print(f"\nPatched CALL at {hex(call_site)}:")
    print(f"New offset: {hex(offset)}")
    print(disasm(elf.read(call_site, 5)))


elf.save(out_elf)




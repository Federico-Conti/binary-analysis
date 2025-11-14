from pwn import *
elf = ELF('toppler_basc/toppler64')
elf.write(0x00414007, b'\x00')  
elf.save('toppler_basc/toppler64_infinitelife')
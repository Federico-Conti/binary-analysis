from pwn import *
elf = ELF('toppler_basc/toppler32')
elf.write(0x0805641d, b'\x00')
elf.save('toppler_basc/toppler32_infinitelife')

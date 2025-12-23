# Ghidra User Guide

## Installation
For installation instructions, refer to this [YouTube video](https://www.youtube.com/watch?v=Es3ebWUBiqc).


## Practical Rules for Instruction Replacement

When replacing instructions in Ghidra, follow these practical rules:

- If the original instruction is 5 bytes long, do not overwrite it with a longer instruction, as this would overwrite the next instruction and disrupt the flow.
- If the new instruction is shorter, it is acceptable to fill the remaining bytes with `nop` (1 byte).
- Ghidra displays multiple possible encodings for the same instruction. Be careful to choose an encoding of the same length or shorter that is compatible. Choosing the wrong encoding could overwrite the subsequent `pop ebp` and cause a crash at `ret` (because the `pop ebp` was overwritten).

## Persistent Patches in Ghidra

When you make changes to the disassembly or decompilation in Ghidra, these changes are stored in the project database. However, if you want to export the modified binary with your patches applied, you can do so by following these steps:

1. Go to `File` -> `Export Program`.
2. Choose the format you want to export (e.g., Original File).
3. Choose the destination and export the file.

## Syncronizing Base Address in Ghidra with GDB

GDB and Ghidra synchronize and load memory addresses in different ways.
SO to synchronize Ghidra with GDB, follow these steps:

1. In GDB  `vmm` -> take note of the base address of the executable. For example, `0x56555000`. 
2. Use the same base address in Ghidra:
   - Go to `Window` -> `Memory Map`
   - Click on `Image Base`
   -  Change it to `0x56555000`


## Finding `main` on Stripped Executables in Ghidra and GDB

When analyzing an executable, identifying the `main` function is a crucial step. If the executable contains symbols, tools like GDB or Ghidra can easily locate `main` because its address is explicitly named. However, in most cases, symbols are stripped, making it impossible for these tools to find `main` automatically.

In such cases, you can start by examining the entry point of the executable. However, the entry point is not the actual `main` function. Instead, it is a piece of code added by the compiler to initialize the C runtime library. After this initialization, the program eventually calls `main`.

Typically, the initial code:

1. Sets up necessary structures.
2. Calls `main`.
3. Terminates with the return value of `main`.


On Linux, the standard defines that `main` is called by the function `__libc_start_main`, which is always present. This function takes several arguments, and the first argument is the address of `main`. The process to locate `main` is as follows:

1. Find a call to `__libc_start_main`.
2. Inspect its first argument, which contains the address of `main`.

**Using GDB**

- Set a breakpoint on `__libc_start_main`.
- When execution reaches this function, its first parameter will hold the address of `main`.

- **For 32-bit executables**:  
    The value can be read from the stack at the address `esp + 4` (since the return address is at the top of the stack, followed by the first argument).

- **For 64-bit executables**:  
    Arguments are passed via registers. The first six parameters are stored in registers, with the first parameter in `rdi`. Simply read the content of `rdi` to get the address of `main`.

**Using Ghidra**

- Navigate to the entry point of the executable.
- Locate the call to `__libc_start_main`.
- Double-click on the first argument of the call. This will take you directly to the address of `main`.



## Commenting Code in Ghidra

When analyzing code in Ghidra, adding comments is essential for understanding and documenting your findings.

In Ghidra, esistono diversi tipi di commenti che possono essere utilizzati per annotare il codice:

- **Plate Comment**: Un commento molto visibile nella vista del disassemblatore (*disassembler view*).
- **Pre-Comment**: Mostrato prima dell'istruzione e visibile anche nella vista decompilata (*decompiler view*).
- **Post-Comment**: Mostrato dopo l'istruzione.
- **End-of-Line Comment**: Inserito alla fine della riga.
- **Repeatable Comment**: Ripetuto automaticamente ogni volta che l'indirizzo associato è referenziato altrove.

Il **pre-comment** è particolarmente utile perché appare anche nella vista decompilata, rendendolo ideale per annotare il codice leggibile.

Ad esempio, un **repeatable comment** aggiunto all'inizio di `main` verrà mostrato automaticamente in ogni altro punto del codice in cui quell'indirizzo è referenziato, come in chiamate o cross-reference.



## Code Coverage: Dynamic Analysis

Code coverage is a dynamic analysis that allows you to:  

- Run a program and observe which parts are actually executed.  
- Identify unexecuted code areas, useful for complex programs.  

How It Works  

1. Program Execution: Use tracking tools like **Dr.Cov (DynamoRIO)** or **Delphin** to record executed basic blocks.  
2. Log Analysis: The generated log files can be viewed with Ghidra plugins or similar tools.  
3. Visualization: Plugins color code blocks based on execution frequency:  
    - Red: Executed many times.  
    - Yellow: Executed only once.  
4. Advanced Queries: Ability to compare multiple execution traces to find intersections or unions.  

Applications  

- Identify controls or critical areas in complex programs.  
- Not recommended for small programs.  

## Patching Binaries

Introduction to **[PawnTools](https://github.com/Gallopsled/pwntools)**

PawnTools is a Python library designed for:  

- Exploit development: Scripts that leverage vulnerabilities to gain unauthorized access or read sensitive data.  
- Reverse engineering: Also useful for program analysis.  

Convertire tra interi e sequenze di byte, rispettando l’endianness.

| Funzione | Cosa fa                     | Input               | Output          |
|----------|-----------------------------|---------------------|-----------------|
| p32(n)   | Pack int 32-bit → bytes     | 0xdeadbeef          | b'\xef\xbe\xad\xde' |
| p64(n)   | Pack int 64-bit → bytes     | 0xdeadbeefcafebabe  | 8 byte          |
| u32(b)   | Unpack 4 byte → int         | b'\xef\xbe\xad\xde' | 0xdeadbeef      |
| u64(b)   | Unpack 8 byte → int         | 8 byte              | Intero          |


With Pwntools, you can also assemble/disassemble, which can be useful; you can parse ELF, search inside files, disassemble them and, for example, patch an ELF.


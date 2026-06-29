.code

wcsncmp_asm proc
la: mov ax, word ptr [rcx]
    mov r9w, word ptr [rdx]
    cmp ax, r9w
    jne lb
    add rcx, 2
    add rdx, 2
    dec r8
    jnz la
    xor eax, eax
    ret
lb: movzx eax, ax
    movzx ecx, r9w
    sub eax, ecx
    ret
wcsncmp_asm endp

end

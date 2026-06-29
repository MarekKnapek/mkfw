.model flat

.code

_wcsncmp_asm proc
    push esi
    push edi
    mov esi, [esp + 3 * 4]
    mov edi, [esp + 4 * 4]
    mov ecx, [esp + 5 * 4]
la: mov ax, word ptr [esi]
    mov dx, word ptr [edi]
    cmp ax, dx
    jne lb
    add esi, 2
    add edi, 2
    dec ecx
    jnz la
    xor eax, eax
    jmp lc
lb: movzx eax, ax
    movzx edx, dx
    sub eax, edx
lc: pop edi
    pop esi
    ret
_wcsncmp_asm endp

end

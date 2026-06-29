.code

mk_memcpy_asm proc
	mov r10, rdi
	mov r11, rsi
	mov rax, rcx
	mov rdi, rcx
	mov rsi, rdx
	mov rcx, r8
	cld
	rep movsb
	mov rdi, r10
	mov rsi, r11
	ret
mk_memcpy_asm endp

memcpy proc
	jmp mk_memcpy_asm
memcpy endp

end

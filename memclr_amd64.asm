.code

mk_memclr_asm proc
	mov r10, rdi
	mov rdi, rcx
	mov rcx, rdx
	xor eax, eax
	cld
	rep stosb
	mov rdi, r10
	ret
mk_memclr_asm endp

end

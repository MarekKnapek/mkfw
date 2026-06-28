.code

mk_memclr proc
	mov rdi, rcx
	mov rcx, rdx
	xor eax, eax
	cld
	rep stosb
	ret
mk_memclr endp

end

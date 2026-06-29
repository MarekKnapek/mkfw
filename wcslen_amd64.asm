.code

mk_wcslen_asm proc
	mov r10, rdi
	mov rdi, rcx
	xor eax, eax
	mov rcx, -1
	cld
	repne scasw
	not rcx
	dec rcx
	mov rax, rcx
	mov rdi, r10
	ret
mk_wcslen_asm endp

end

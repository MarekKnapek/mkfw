.code

mk_memclr proc
	mov r10, rdi
	mov rdi, rcx ; dst
	mov rcx, rdx ; cnt
	xor eax, eax ; val
	cld          ; fwd
	rep stosb    ; sto
	mov rdi, r10
	ret
mk_memclr endp

end

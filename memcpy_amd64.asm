.code

memcpy proc
	mov rdi, rcx
	mov rsi, rdx
	mov rcx, r8
	rep movsb
	ret
memcpy endp

end

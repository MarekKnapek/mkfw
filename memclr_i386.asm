.model flat

.code

_mk_memclr proc
	mov edi, [esp + 1 * 4]
	mov ecx, [esp + 2 * 4]
	xor eax, eax
	cld
	rep stosb
	ret
_mk_memclr endp

end

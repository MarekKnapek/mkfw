.model flat

.code

_mk_memclr proc
	mov edx, edi
	mov edi, [esp + 1 * 4] ; dst
	mov ecx, [esp + 2 * 4] ; cnt
	xor eax, eax           ; val
	cld                    ; fwd
	rep stosb              ; sto
	mov edi, edx
	ret
_mk_memclr endp

end

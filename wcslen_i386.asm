.model flat

.code

_mk_wcslen_asm proc
	mov edx, edi
	mov edi, [esp + 1 * 4]
	xor eax, eax
	mov ecx, -1
	cld
	repne scasw
	not ecx
	dec ecx
	mov eax, ecx
	mov edi, edx
	ret
_mk_wcslen_asm endp

end

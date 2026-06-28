.model flat

.code

_memcpy proc
	mov eax, edi
	mov edx, esi
	mov edi, dword ptr ss:[esp + 1 * 4]
	mov esi, dword ptr ss:[esp + 2 * 4]
	mov ecx, dword ptr ss:[esp + 3 * 4]
	cld
	rep movsb byte ptr es:[edi], byte ptr ds:[esi]
	mov edi, eax
	mov esi, edx
	ret
_memcpy endp

end

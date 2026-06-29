.model flat

.code

_mk_memcpy_asm proc
	mov eax, edi
	mov edx, esi
	mov edi, dword ptr [esp + 1 * 4]
	mov esi, dword ptr [esp + 2 * 4]
	mov ecx, dword ptr [esp + 3 * 4]
	cld
	rep movsb
	mov edi, eax
	mov esi, edx
	mov eax, dword ptr [esp + 1 * 4]
	ret
_mk_memcpy_asm endp

_memcpy proc
	jmp _mk_memcpy_asm
_memcpy endp

end

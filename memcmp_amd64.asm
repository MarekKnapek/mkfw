.code

memcmp proc
         test r8, r8
         jz mk_eq
mk_loop: movzx eax, byte ptr [rcx]
         movzx r9d, byte ptr [rdx]
         cmp eax, r9d
         jne mk_dif
         inc rcx
         inc rdx
         dec r8
         jnz mk_loop
mk_eq:   xor eax, eax
         ret
mk_dif:  sub eax, r9d
         ret
memcmp endp

end

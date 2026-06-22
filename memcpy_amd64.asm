.code

memcpy proc
         mov rax, rcx
         test r8, r8
         jz mk_done
mk_loop: mov r9b, byte ptr [rdx]
         mov byte ptr [rcx], r9b
         inc rdx
         inc rcx
         dec r8
         jnz mk_loop
mk_done: ret
memcpy endp

end

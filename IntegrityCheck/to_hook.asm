.code
	va$ = 32
	format$ = 64

	extern vprintf :proc
	to_hook proc EXPORT
		mov qword ptr [rsp+8], rcx
		mov qword ptr [rsp+16], rdx
		mov qword ptr [rsp+24], r8
		mov qword ptr [rsp+32], r9
		sub rsp, 56
		lea rax, qword ptr format$[rsp+8]
		mov qword ptr va$[rsp], rax
		mov rdx, qword ptr va$[rsp]
		mov rcx, qword ptr format$[rsp]
		call vprintf
		mov qword ptr va$[rsp], 0
		add rsp, 56
		ret 0
	to_hook endp

end
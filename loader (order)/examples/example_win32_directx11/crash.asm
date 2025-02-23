PUBLIC crash_asm
EXTERN puts:PROC

.code

crash_asm PROC
	 xor rbp, rbp;
     xor rcx, rcx;
	 jmp rbx;
crash_asm ENDP

END
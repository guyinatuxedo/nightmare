[SECTION .text]
global _start
_start:
	mov al, 0x3b
	lea rdi, [rel $ +0xffffffffffffffff ] 
	mov rcx, 0x68732f6e69622f
	mov [rdi], rcx
	xor rsi, rsi
	xor rdx, rdx
	syscall


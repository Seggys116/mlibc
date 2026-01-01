	.section .init,"ax",@progbits
	.global _init
_init:
	push %rbp
	mov %rsp, %rbp

	.section .fini,"ax",@progbits
	.global _fini
_fini:
	push %rbp
	mov %rsp, %rbp

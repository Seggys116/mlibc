	.text
	.globl	_start
_start:
	mov	%rsp, %rbp
	sub	$16, %rsp
	and	$-16, %rsp
	mov	%rbp, (%rsp)
	mov	%rsi, 8(%rsp)
	mov	%rdx, 16(%rsp)
	call	__mlibc_entry
	hlt

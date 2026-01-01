	.text
	.globl	_start
_start:
	/* Set up stack frame */
	mov	%rsp, %rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	/* Align stack to 16 bytes */
	and	$-16, %rsp

	/* Call _start to set up libucrt stuff */
	call	__cstart

	/* Should never reach here */
	hlt

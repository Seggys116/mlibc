.global __mlibcTlsdescStatic
.hidden __mlibcTlsdescStatic
.type __mlibcTlsdescStatic, @function
__mlibcTlsdescStatic:
	mov 8(%rax), %rax
	ret

.global __mlibcTlsdescDynamic
.hidden __mlibcTlsdescDynamic
.type __mlibcTlsdescDynamic, @function
__mlibcTlsdescDynamic:
	push %rbx
	push %rcx

	mov 8(%rax), %rax

	mov (%rax), %rbx // index
	mov 8(%rax), %rcx // addend

	mov %fs:16, %rax // *tp->dtvPointers
	mov (%rax, %rbx, 8), %rax // dtvPointers[0][index]
	add %rcx, %rax // + addend
	sub %fs:0, %rax

	pop %rcx
	pop %rbx
	ret

.global pltRelocateStub
pltRelocateStub:
	# we need to save / restore all registers than can hold function arguments
	# The resolver is entered transparently from the caller's PLT path. Preserve
	# the SysV callee-saved set as well: lazyRelocate is ordinary C++ and may use
	# those registers internally, while the final target function has not yet had
	# a chance to establish its own ABI boundary.
	# TODO: save floating point argument registers

	push %rsi
	push %rdi
	mov 16(%rsp), %rdi
	mov 24(%rsp), %rsi

	push %rbx
	push %rbp
	push %r12
	push %r13
	push %r14
	push %r15

	push %rax
	push %rcx
	push %rdx
	push %r8
	push %r9
	push %r10

	call lazyRelocate
	mov %rax, %r11

	pop %r10
	pop %r9
	pop %r8
	pop %rdx
	pop %rcx
	pop %rax

	pop %r15
	pop %r14
	pop %r13
	pop %r12
	pop %rbp
	pop %rbx
	
	pop %rdi
	pop %rsi
	add $16, %rsp
	jmp *%r11

.section .note.GNU-stack,"",%progbits

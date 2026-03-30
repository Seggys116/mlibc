.section .text
.global __mlibc_start_thread
.type __mlibc_start_thread, "function"
.cfi_startproc
__mlibc_start_thread:
	.cfi_undefined %rip
	.cfi_undefined %rbp

	pop %rdi
	.cfi_adjust_cfa_offset -8
	.cfi_undefined %rdi
	pop %rsi
	.cfi_adjust_cfa_offset -8
	.cfi_undefined %rsi
	pop %rdx
	.cfi_adjust_cfa_offset -8
	.cfi_undefined %rdx
	call __mlibc_enter_thread
	ud2
.cfi_endproc

.global __mlibc_raw_clone_entry
.type __mlibc_raw_clone_entry, "function"
.cfi_startproc
__mlibc_raw_clone_entry:
	.cfi_undefined %rip
	.cfi_undefined %rbp

	pop %rdi
	.cfi_adjust_cfa_offset -8
	.cfi_undefined %rdi
	pop %rsi
	.cfi_adjust_cfa_offset -8
	.cfi_undefined %rsi
	pop %rdx
	.cfi_adjust_cfa_offset -8
	.cfi_undefined %rdx
	call __mlibc_enter_raw_clone
	ud2
.cfi_endproc

.section .note.GNU-stack,"",%progbits

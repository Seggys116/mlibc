#include "mlibc-asm/helpers.h"

PROC_START(_start)
.cfi_undefined rip
	mov %rsp, %r12
	andq $-16, %rsp
	call relocateSelf

	mov %r12, %rdi
	andq $-16, %rsp
	call interpreterMain

	jmp *%rax
PROC_END(_start)

GNU_STACK_NOTE()

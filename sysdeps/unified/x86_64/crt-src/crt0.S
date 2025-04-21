
.section .text
.global _start
_start:
	mov $0x1B, %ax
    mov %ax, %ds
    mov %ax, %es

	mov %rsp, %rdi
	mov $main, %rsi
	call __mlibc_entry

	mov %rax, %rdi      # Move exit code to the first argument register
    mov $1, %rax        # Syscall number for SYS_EXIT
    int $0x69           # Trigger syscall

.section .note.GNU-stack,"",%progbits


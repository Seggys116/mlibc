
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
    mov $231, %rax      # Linux x86_64 SYS_exit_group
    int $0x69           # Trigger syscall

.section .note.GNU-stack,"",%progbits

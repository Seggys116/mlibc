/* POSIX-compatible syscall() fallback for user-space programs.
 *
 * Exact-arity call sites should come through <sys/syscall.h>, which dispatches
 * to the raw syscalln* inlines without inventing unused trailing arguments.
 *
 * This file is compiled into libc.so only - NOT into ld.so (the rtld).
 * The rtld cannot use errno because errno is TLS-based (__mlibc_errno)
 * and TLS is not available during early rtld startup.
 *
 * This symbol remains for compatibility with code that expects a function
 * named syscall() and converts raw negative errno returns to the POSIX
 * convention used by glibc: return -1 and set errno on failure.
 */
#include <unified/syscall.h>
#include <stdarg.h>
#include <errno.h>

extern "C" long __mlibc_posix_syscall_ret_helper(long ret) {
    if (ret < 0) {
        errno = (int)(-ret);
        return -1L;
    }
    return ret;
}

#if defined(__x86_64__)
extern "C" __attribute__((naked)) long syscall(long number, ...) {
    /* C-callable variadic syscall(). The SysV variadic ABI does not preserve
     * unused argument registers — for syscall(N, x) the compiler sets %rdi
     * (number) and %rsi (x), leaving %rdx/%rcx/%r8/%r9 with unspecified
     * (residual) values. We can't tell the actual arity at runtime, so this
     * function necessarily passes those residuals to the kernel.
     *
     * The C++ macro in <sys/syscall.h> dispatches to fixed-arity helpers
     * (__mlibc_posix_syscall1 → syscalln1) which DO zero unused argument
     * slots and is the recommended call path for syscalls that multiplex on
     * arg1 (e.g. SYS_SETTIDID / set_tid_address). C-only callers must use
     * the dedicated POSIX wrappers (e.g. set_tid_address(p)) rather than
     * variadic syscall() for the same reason. */
    __asm__ volatile(
        // Keep the stack 16-byte aligned across the helper call. Our extended
        // kernel ABI also accepts a 7th syscall argument in r12.
        "push %r12\n\t"
        "mov %rdi, %rax\n\t"
        "mov 16(%rsp), %r11\n\t"
        "mov 24(%rsp), %r12\n\t"
        "mov %rsi, %rdi\n\t"
        "mov %rdx, %rsi\n\t"
        "mov %rcx, %rdx\n\t"
        "mov %r8, %r10\n\t"
        "mov %r11, %r8\n\t"
        "int $0x69\n\t"
        "mov %rax, %rdi\n\t"
        "call __mlibc_posix_syscall_ret_helper\n\t"
        "pop %r12\n\t"
        "ret\n\t");
}
#else
extern "C" long syscall(long number, ...) {
    va_list ap;
    va_start(ap, number);
    /* Compatibility fallback: callers that need precise syscall arity should
     * use the header-level dispatch in <sys/syscall.h>. */
    long a0 = va_arg(ap, long);
    long a1 = va_arg(ap, long);
    long a2 = va_arg(ap, long);
    long a3 = va_arg(ap, long);
    long a4 = va_arg(ap, long);
    long a5 = va_arg(ap, long);
    va_end(ap);

    return __mlibc_posix_syscall_ret_helper(syscalln6((uint64_t)number,
                         (uint64_t)a0, (uint64_t)a1, (uint64_t)a2,
                         (uint64_t)a3, (uint64_t)a4, (uint64_t)a5));
}
#endif

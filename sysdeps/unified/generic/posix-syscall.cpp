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

    long ret = syscalln6((uint64_t)number,
                         (uint64_t)a0, (uint64_t)a1, (uint64_t)a2,
                         (uint64_t)a3, (uint64_t)a4, (uint64_t)a5);
    if (ret < 0) {
        errno = (int)(-ret);
        return -1L;
    }
    return ret;
}

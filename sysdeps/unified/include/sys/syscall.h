#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

#include <errno.h>

/* Include syscall number definitions but suppress the raw syscall() macro.
 * User-space programs (libuv, Node.js, etc.) must use the POSIX-compatible
 * syscall() function declared below, which properly sets errno on failure. */
#define UNIFIED_NO_SYSCALL_MACRO
#include <unified/syscall.h>
#undef UNIFIED_NO_SYSCALL_MACRO

/* Linux-style __NR_* and SYS_lowercase names come from <unified/syscall.h>. */

/* POSIX-compatible syscall(): returns -1 and sets errno on failure, like glibc */
#ifdef __cplusplus
extern "C" long syscall(long number, ...);
#else
extern long syscall(long number, ...);
#endif

static inline long __mlibc_posix_syscall_ret(long ret) {
    if(ret < 0) {
        errno = (int)(-ret);
        return -1L;
    }
    return ret;
}

static inline long __mlibc_posix_syscall0(long number) {
    return __mlibc_posix_syscall_ret(syscalln0((uint64_t)number));
}

#ifdef __cplusplus
static inline uint64_t __mlibc_posix_syscall_arg(decltype(nullptr)) {
    return 0;
}

template<typename T>
static inline uint64_t __mlibc_posix_syscall_arg(T *arg) {
    return (uint64_t)arg;
}

template<typename T>
static inline uint64_t __mlibc_posix_syscall_arg(T arg) {
    return (uint64_t)arg;
}

template<typename A0>
static inline long __mlibc_posix_syscall1(long number, A0 arg0) {
    return __mlibc_posix_syscall_ret(syscalln1((uint64_t)number,
            __mlibc_posix_syscall_arg(arg0)));
}

template<typename A0, typename A1>
static inline long __mlibc_posix_syscall2(long number, A0 arg0, A1 arg1) {
    return __mlibc_posix_syscall_ret(syscalln2((uint64_t)number,
            __mlibc_posix_syscall_arg(arg0), __mlibc_posix_syscall_arg(arg1)));
}

template<typename A0, typename A1, typename A2>
static inline long __mlibc_posix_syscall3(long number, A0 arg0, A1 arg1, A2 arg2) {
    return __mlibc_posix_syscall_ret(syscalln3((uint64_t)number,
            __mlibc_posix_syscall_arg(arg0), __mlibc_posix_syscall_arg(arg1),
            __mlibc_posix_syscall_arg(arg2)));
}

template<typename A0, typename A1, typename A2, typename A3>
static inline long __mlibc_posix_syscall4(long number, A0 arg0, A1 arg1, A2 arg2, A3 arg3) {
    return __mlibc_posix_syscall_ret(syscalln4((uint64_t)number,
            __mlibc_posix_syscall_arg(arg0), __mlibc_posix_syscall_arg(arg1),
            __mlibc_posix_syscall_arg(arg2), __mlibc_posix_syscall_arg(arg3)));
}

template<typename A0, typename A1, typename A2, typename A3, typename A4>
static inline long __mlibc_posix_syscall5(long number, A0 arg0, A1 arg1, A2 arg2, A3 arg3, A4 arg4) {
    return __mlibc_posix_syscall_ret(syscalln5((uint64_t)number,
            __mlibc_posix_syscall_arg(arg0), __mlibc_posix_syscall_arg(arg1),
            __mlibc_posix_syscall_arg(arg2), __mlibc_posix_syscall_arg(arg3),
            __mlibc_posix_syscall_arg(arg4)));
}

template<typename A0, typename A1, typename A2, typename A3, typename A4, typename A5>
static inline long __mlibc_posix_syscall6(long number, A0 arg0, A1 arg1, A2 arg2, A3 arg3, A4 arg4, A5 arg5) {
    return __mlibc_posix_syscall_ret(syscalln6((uint64_t)number,
            __mlibc_posix_syscall_arg(arg0), __mlibc_posix_syscall_arg(arg1),
            __mlibc_posix_syscall_arg(arg2), __mlibc_posix_syscall_arg(arg3),
            __mlibc_posix_syscall_arg(arg4), __mlibc_posix_syscall_arg(arg5)));
}

template<typename A0, typename A1, typename A2, typename A3, typename A4, typename A5, typename A6>
static inline long __mlibc_posix_syscall7(long number, A0 arg0, A1 arg1, A2 arg2, A3 arg3, A4 arg4, A5 arg5, A6 arg6) {
    return __mlibc_posix_syscall_ret(syscalln7((uint64_t)number,
            __mlibc_posix_syscall_arg(arg0), __mlibc_posix_syscall_arg(arg1),
            __mlibc_posix_syscall_arg(arg2), __mlibc_posix_syscall_arg(arg3),
            __mlibc_posix_syscall_arg(arg4), __mlibc_posix_syscall_arg(arg5),
            __mlibc_posix_syscall_arg(arg6)));
}
#else
static inline long __mlibc_posix_syscall1(long number, long arg0) {
    return __mlibc_posix_syscall_ret(syscalln1((uint64_t)number, (uint64_t)arg0));
}

static inline long __mlibc_posix_syscall2(long number, long arg0, long arg1) {
    return __mlibc_posix_syscall_ret(syscalln2((uint64_t)number,
            (uint64_t)arg0, (uint64_t)arg1));
}

static inline long __mlibc_posix_syscall3(long number, long arg0, long arg1, long arg2) {
    return __mlibc_posix_syscall_ret(syscalln3((uint64_t)number,
            (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2));
}

static inline long __mlibc_posix_syscall4(long number, long arg0, long arg1, long arg2, long arg3) {
    return __mlibc_posix_syscall_ret(syscalln4((uint64_t)number,
            (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3));
}

static inline long __mlibc_posix_syscall5(long number, long arg0, long arg1, long arg2, long arg3, long arg4) {
    return __mlibc_posix_syscall_ret(syscalln5((uint64_t)number,
            (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
            (uint64_t)arg4));
}

static inline long __mlibc_posix_syscall6(long number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5) {
    return __mlibc_posix_syscall_ret(syscalln6((uint64_t)number,
            (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
            (uint64_t)arg4, (uint64_t)arg5));
}

static inline long __mlibc_posix_syscall7(long number, long arg0, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    return __mlibc_posix_syscall_ret(syscalln7((uint64_t)number,
            (uint64_t)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
            (uint64_t)arg4, (uint64_t)arg5, (uint64_t)arg6));
}
#endif

#ifndef MLIBC_NO_POSIX_SYSCALL_MACRO
#ifdef __cplusplus
/* C++ path: use template-based inlines that accept any argument type safely. */
#define __MLIBC_GET_POSIX_SYSCALL(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define syscall(...) __MLIBC_GET_POSIX_SYSCALL(__VA_ARGS__, \
        __mlibc_posix_syscall7, __mlibc_posix_syscall6, \
        __mlibc_posix_syscall5, __mlibc_posix_syscall4, \
        __mlibc_posix_syscall3, __mlibc_posix_syscall2, \
        __mlibc_posix_syscall1, __mlibc_posix_syscall0)(__VA_ARGS__)
#endif /* __cplusplus */
/* C path: let C code use the real variadic syscall() function declared above.
 * The C inline helpers use long-typed parameters, which reject pointer
 * arguments (e.g. struct epoll_event *) with -Wint-conversion errors.
 * The actual syscall() function is variadic and accepts any type safely. */
#endif

#endif /* _SYS_SYSCALL_H */

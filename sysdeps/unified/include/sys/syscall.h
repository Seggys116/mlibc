#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

#include <errno.h>

/* Include syscall number definitions but suppress the raw syscall() macro.
 * User-space programs (libuv, Node.js, etc.) must use the POSIX-compatible
 * syscall() function declared below, which properly sets errno on failure. */
#define UNIFIED_NO_SYSCALL_MACRO
#include <unified/syscall.h>
#undef UNIFIED_NO_SYSCALL_MACRO

/* Map Linux syscall names (lowercase) to Unified syscall numbers (uppercase) */
#define SYS_gettid SYS_GETTID
#define SYS_futex SYS_FUTEX_WAIT
#define SYS_get_mempolicy SYS_GET_MEMPOLICY
#define SYS_membarrier SYS_MEMBARRIER
#define SYS_getcpu SYS_GETCPU
#define SYS_memfd_create SYS_MEMFD_CREATE
#define SYS_fallocate SYS_FALLOCATE
#define SYS_fadvise64 SYS_FADVISE
#define SYS_fdatasync SYS_FDATASYNC
#define SYS_mincore SYS_MINCORE
#define SYS_futex_time64 SYS_FUTEX_WAIT
#define SYS_set_tid_address SYS_SETTIDID
#define SYS_set_robust_list SYS_SETTIDID

/* SYS_* lowercase aliases for Linux-compatible code */                                                                                      
#define SYS_epoll_create SYS_EPOLL_CREATE                                                                                             
#define SYS_epoll_ctl    SYS_EPOLL_CTL                                                                                                       
#define SYS_epoll_wait   SYS_EPOLL_WAIT                                                                                               
#define SYS_tgkill       SYS_TGKILL                                                                                                   
                                                                                                                                      
/* __NR_* aliases for code that uses the Linux syscall-number naming convention.
 * These map to the Unified OS kernel's actual syscall numbers. */
#define __NR_gettid        SYS_GETTID
#define __NR_futex         SYS_FUTEX_WAIT
#define __NR_futex_time64  SYS_FUTEX_WAIT
#define __NR_membarrier    SYS_MEMBARRIER
#define __NR_getcpu        SYS_GETCPU
#define __NR_set_tid_address SYS_SETTIDID
#define __NR_set_robust_list SYS_SETTIDID
#define __NR_tgkill        SYS_TGKILL
#define __NR_clone         SYS_CLONE
#define __NR_fadvise64     SYS_FADVISE
#define __NR_fdatasync     SYS_FDATASYNC
#define __NR_mincore       SYS_MINCORE
#define __NR_epoll_create  SYS_EPOLL_CREATE
#define __NR_epoll_create1 SYS_EPOLL_CREATE
#define __NR_epoll_ctl     SYS_EPOLL_CTL
#define __NR_epoll_wait    SYS_EPOLL_WAIT
#define __NR_epoll_pwait   SYS_EPOLL_WAIT

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

#ifndef MLIBC_NO_POSIX_SYSCALL_MACRO
#define __MLIBC_GET_POSIX_SYSCALL(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME
#define syscall(...) __MLIBC_GET_POSIX_SYSCALL(__VA_ARGS__, \
        __mlibc_posix_syscall7, __mlibc_posix_syscall6, \
        __mlibc_posix_syscall5, __mlibc_posix_syscall4, \
        __mlibc_posix_syscall3, __mlibc_posix_syscall2, \
        __mlibc_posix_syscall1, __mlibc_posix_syscall0)(__VA_ARGS__)
#endif

#endif /* _SYS_SYSCALL_H */

#ifndef SYSCALL_H
#define SYSCALL_H

#include <stdint.h>
#include <unified/syscallnos.h>

#define SYS_READ __NR_read
#define SYS_WRITE __NR_write
#define SYS_OPEN __NR_open
#define SYS_CLOSE __NR_close
#define SYS_STAT __NR_stat
#define SYS_FSTAT __NR_fstat
#define SYS_LSTAT __NR_lstat
#define SYS_POLL __NR_poll
#define SYS_LSEEK __NR_lseek
#define SYS_MMAP __NR_mmap
#define SYS_MPROTECT __NR_mprotect
#define SYS_MUNMAP __NR_munmap
#define SYS_BRK __NR_brk
#define SYS_SIGNAL_ACTION __NR_rt_sigaction
#define SYS_SIGPROCMASK __NR_rt_sigprocmask
#define SYS_SIGNAL_RETURN __NR_rt_sigreturn
#define SYS_IOCTL __NR_ioctl
#define SYS_PREAD __NR_pread64
#define SYS_PWRITE __NR_pwrite64
#define SYS_READV __NR_readv
#define SYS_WRITEV __NR_writev
#define SYS_ACCESS __NR_access
#define SYS_PIPE __NR_pipe
#define SYS_YIELD __NR_sched_yield
#define SYS_MREMAP __NR_mremap
#define SYS_MSYNC __NR_msync
#define SYS_MINCORE __NR_mincore
#define SYS_MADVISE __NR_madvise
#define SYS_DUP __NR_dup
#define SYS_DUP2 __NR_dup2
#define SYS_PAUSE __NR_pause
#define SYS_NANO_SLEEP __NR_nanosleep
#define SYS_GETITIMER __NR_getitimer
#define SYS_ALARM __NR_alarm
#define SYS_SETITIMER __NR_setitimer
#define SYS_GETPID __NR_getpid
#define SYS_SENDFILE __NR_sendfile
#define SYS_SOCKET __NR_socket
#define SYS_CONNECT __NR_connect
#define SYS_ACCEPT __NR_accept
#define SYS_SENDTO __NR_sendto
#define SYS_RECEIVEFROM __NR_recvfrom
#define SYS_SENDMSG __NR_sendmsg
#define SYS_RECVMSG __NR_recvmsg
#define SYS_SHUTDOWN __NR_shutdown
#define SYS_BIND __NR_bind
#define SYS_LISTEN __NR_listen
#define SYS_SOCKNAME __NR_getsockname
#define SYS_PEERNAME __NR_getpeername
#define SYS_SOCKETPAIR __NR_socketpair
#define SYS_SET_SOCKET_OPTIONS __NR_setsockopt
#define SYS_GET_SOCKET_OPTIONS __NR_getsockopt
#define SYS_FORK __NR_fork
#define SYS_EXECVE __NR_execve
#define SYS_EXIT __NR_exit
#define SYS_WAIT4 __NR_wait4
#define SYS_KILL __NR_kill
#define SYS_UNAME __NR_uname
#define SYS_FCNTL __NR_fcntl
#define SYS_FLOCK __NR_flock
#define SYS_FSYNC __NR_fsync
#define SYS_FDATASYNC __NR_fdatasync
#define SYS_TRUNCATE __NR_truncate
#define SYS_FTRUNCATE __NR_ftruncate
#define SYS_GET_CWD __NR_getcwd
#define SYS_CHDIR __NR_chdir
#define SYS_FCHDIR __NR_fchdir
#define SYS_RENAME __NR_rename
#define SYS_MKDIR __NR_mkdir
#define SYS_RMDIR __NR_rmdir
#define SYS_LINK __NR_link
#define SYS_UNLINK __NR_unlink
#define SYS_SYMLINK __NR_symlink
#define SYS_READLINK __NR_readlink
#define SYS_CHMOD __NR_chmod
#define SYS_FCHMOD __NR_fchmod
#define SYS_CHOWN __NR_chown
#define SYS_FCHOWN __NR_fchown
#define SYS_LCHOWN __NR_lchown
#define SYS_UMASK __NR_umask
#define SYS_GETTIMEOFDAY __NR_gettimeofday
#define SYS_GET_RESOURCE_LIMIT __NR_getrlimit
#define SYS_GETRUSAGE __NR_getrusage
#define SYS_INFO __NR_sysinfo
#define SYS_GETUID __NR_getuid
#define SYS_GETGID __NR_getgid
#define SYS_SETUID __NR_setuid
#define SYS_SETGID __NR_setgid
#define SYS_GETEUID __NR_geteuid
#define SYS_GETEGID __NR_getegid
#define SYS_SETPGID __NR_setpgid
#define SYS_GETPPID __NR_getppid
#define SYS_GETPGRP __NR_getpgrp
#define SYS_SETSID __NR_setsid
#define SYS_SETREUID __NR_setreuid
#define SYS_SETREGID __NR_setregid
#define SYS_GETGROUPS __NR_getgroups
#define SYS_SETGROUPS __NR_setgroups
#define SYS_SETRESUID __NR_setresuid
#define SYS_GETRESUID __NR_getresuid
#define SYS_SETRESGID __NR_setresgid
#define SYS_GETRESGID __NR_getresgid
#define SYS_GETPGID __NR_getpgid
#define SYS_GETSID __NR_getsid
#define SYS_SIGPENDING __NR_rt_sigpending
#define SYS_SIGTIMEDWAIT __NR_rt_sigtimedwait
#define SYS_SIGQUEUE __NR_rt_sigqueueinfo
#define SYS_SIGSUSPEND __NR_rt_sigsuspend
#define SYS_SIGALTSTACK __NR_sigaltstack
#define SYS_STATFS __NR_statfs
#define SYS_FSTATFS __NR_fstatfs
#define SYS_GETPRIORITY __NR_getpriority
#define SYS_SETPRIORITY __NR_setpriority
#define SYS_SCHED_SETPARAM __NR_sched_setparam
#define SYS_SCHED_GETPARAM __NR_sched_getparam
#define SYS_SCHED_SETSCHEDULER __NR_sched_setscheduler
#define SYS_SCHED_GETSCHEDULER __NR_sched_getscheduler
#define SYS_SCHED_GET_PRIORITY_MAX __NR_sched_get_priority_max
#define SYS_SCHED_GET_PRIORITY_MIN __NR_sched_get_priority_min
#define SYS_PRCTL __NR_prctl
#define SYS_ARCH_PRCTL __NR_arch_prctl
#define SYS_SET_RESOURCE_LIMIT __NR_setrlimit
#define SYS_SYNC __NR_sync
#define SYS_MOUNT __NR_mount
#define SYS_UNMOUNT __NR_umount2
#define SYS_REBOOT __NR_reboot
#define SYS_GETTID __NR_gettid
#define SYS_TKILL __NR_tkill
#define SYS_TIME __NR_time
#define SYS_FUTEX_WAIT __NR_futex
#define SYS_SCHED_SETAFFINITY __NR_sched_setaffinity
#define SYS_SCHED_GETAFFINITY __NR_sched_getaffinity
#define SYS_EPOLL_CREATE __NR_epoll_create
#define SYS_GETDENTS64 __NR_getdents64
#define SYS_SET_TID_ADDRESS __NR_set_tid_address
#define SYS_GET_ROBUST_LIST __NR_get_robust_list
#define SYS_FADVISE __NR_fadvise64
#define SYS_CLOCK_NANOSLEEP __NR_clock_nanosleep
#define SYS_CLOCK_GETTIME __NR_clock_gettime
#define SYS_CLOCK_GETRES __NR_clock_getres
#define SYS_EXIT_GROUP __NR_exit_group
#define SYS_EPOLL_WAIT __NR_epoll_wait
#define SYS_EPOLL_CTL __NR_epoll_ctl
#define SYS_TGKILL __NR_tgkill
#define SYS_GET_MEMPOLICY __NR_get_mempolicy
#define SYS_WAITID __NR_waitid
#define SYS_OPENAT __NR_openat
#define SYS_MKDIRAT __NR_mkdirat
#define SYS_FCHOWNAT __NR_fchownat
#define SYS_FSTATAT __NR_newfstatat
#define SYS_UNLINKAT __NR_unlinkat
#define SYS_RENAME_AT __NR_renameat
#define SYS_LINKAT __NR_linkat
#define SYS_SYMLINKAT __NR_symlinkat
#define SYS_READLINKAT __NR_readlinkat
#define SYS_FCHMODAT __NR_fchmodat
#define SYS_FACCESSAT __NR_faccessat
#define SYS_PSELECT6 __NR_pselect6
#define SYS_PPOLL __NR_ppoll
#define SYS_SET_ROBUST_LIST __NR_set_robust_list
#define SYS_UTIMENSAT __NR_utimensat
#define SYS_EPOLL_PWAIT __NR_epoll_pwait
#define SYS_SIGNALFD __NR_signalfd
#define SYS_TIMERFD_CREATE __NR_timerfd_create
#define SYS_EVENTFD __NR_eventfd
#define SYS_FALLOCATE __NR_fallocate
#define SYS_TIMERFD_SETTIME __NR_timerfd_settime
#define SYS_TIMERFD_GETTIME __NR_timerfd_gettime
#define SYS_ACCEPT4 __NR_accept4
#define SYS_SIGNALFD4 __NR_signalfd4
#define SYS_EVENTFD2 __NR_eventfd2
#define SYS_EPOLL_CREATE1 __NR_epoll_create1
#define SYS_DUP3 __NR_dup3
#define SYS_PIPE2 __NR_pipe2
#define SYS_PREADV __NR_preadv
#define SYS_PWRITEV __NR_pwritev
#define SYS_TGSIGQUEUE __NR_rt_tgsigqueueinfo
#define SYS_PRLIMIT64 __NR_prlimit64
#define SYS_NAME_TO_HANDLE_AT __NR_name_to_handle_at
#define SYS_OPEN_BY_HANDLE_AT __NR_open_by_handle_at
#define SYS_SYNCFS __NR_syncfs
#define SYS_GETCPU __NR_getcpu
#define SYS_RENAMEAT2 __NR_renameat2
#define SYS_GETRANDOM __NR_getrandom
#define SYS_MEMFD_CREATE __NR_memfd_create
#define SYS_MEMBARRIER __NR_membarrier
#define SYS_COPY_FILE_RANGE __NR_copy_file_range
#define SYS_PREADV2 __NR_preadv2
#define SYS_PWRITEV2 __NR_pwritev2
#define SYS_STATX __NR_statx
#define SYS_PIDFD_SEND_SIGNAL __NR_pidfd_send_signal
#define SYS_PIDFD_OPEN __NR_pidfd_open
#define SYS_CLONE3 __NR_clone3
#define SYS_CLOSE_RANGE __NR_close_range
#define SYS_OPENAT2 __NR_openat2
#define SYS_PIDFD_GETFD __NR_pidfd_getfd
#define SYS_FACCESSAT2 __NR_faccessat2
#define SYS_FCHMODAT2 __NR_fchmodat2

#define SYS_UNIFIED_BASE 512
#define SYS_DEBUG 512
#define SYS_SLEEP 513
#define SYS_MAP_FB 514
#define SYS_GET_VIDEO_MODE 515
#define SYS_EXEC 516
#define SYS_CREATE 517
#define SYS_READDIR_NEXT 518
#define SYS_READDIR 519
#define SYS_SEND_MESSAGE 520
#define SYS_RECEIVE_MESSAGE 521
#define SYS_UPTIME 522
#define SYS_SET_FS_BASE 523
#define SYS_CREATE_SHARED_MEMORY 524
#define SYS_MAP_SHARED_MEMORY 525
#define SYS_UNMAP_SHARED_MEMORY 526
#define SYS_DESTROY_SHARED_MEMORY 527
#define SYS_SEND 528
#define SYS_RECEIVE 529
#define SYS_GET_PROCESS_INFO 530
#define SYS_GET_NEXT_PROCESS_INFO 531
#define SYS_SPAWN_THREAD 532
#define SYS_EXIT_THREAD 533
#define SYS_FUTEX_WAKE 534
#define SYS_GET_FILE_STATUS_FLAGS 535
#define SYS_SET_FILE_STATUS_FLAGS 536
#define SYS_CREATE_SERVICE 537
#define SYS_CREATE_INTERFACE 538
#define SYS_INTERFACE_ACCEPT 539
#define SYS_INTERFACE_CONNECT 540
#define SYS_ENDPOINT_QUEUE 541
#define SYS_ENDPOINT_DEQUEUE 542
#define SYS_ENDPOINT_CALL 543
#define SYS_ENDPOINT_INFO 544
#define SYS_KERNELOBJECT_WAIT_ONE 545
#define SYS_KERNELOBJECT_WAIT 546
#define SYS_KERNELOBJECT_DESTROY 547
#define SYS_DEVICE_MANAGEMENT 548
#define SYS_INTERRUPT_THREAD 549
#define SYS_LOAD_KERNEL_MODULE 550
#define SYS_UNLOAD_KERNEL_MODULE 551
#define SYS_MKFIFO 552
#define SYS_STATVFS 553
#define SYS_FSTATVFS 554
#define SYS_PIDFD_GETPID 555
#define SYS_GETTIDID 556
#define SYS_SETTIDID 557
#define SYS_SYSCONF 558
#define SYS_SELECT 559
#define SYS_GETSCHEDPARAM 560
#define SYS_SETSCHEDPARAM 561
#define SYS_GETPRIORITYMAX 562
#define SYS_GETPRIORITYMIN 563
#define SYS_GETENTROPY 564
#define SYS_CLONE 565
#define SYS_SETEUID 566
#define SYS_SETEGID 567
#define SYS_SIGWAIT 568
#define SYS_WAIT_PID 569
#define SYS_UNIFIED_INFO 570

#ifdef __cplusplus
extern "C"{
#endif

__attribute__((__always_inline__))
static inline long syscalln0(uint64_t call) {
    volatile long ret;
    /* Zero unused arg registers — see syscalln1 for rationale. */
    register uint64_t r10z __asm__("r10") = 0;
    register uint64_t r9z  __asm__("r9")  = 0;
    register uint64_t r8z  __asm__("r8")  = 0;
    __asm__ volatile("int $0x69"
                     : "=a"(ret)
                     : "a"(call), "D"(0ULL), "S"(0ULL), "d"(0ULL),
                       "r"(r10z), "r"(r9z), "r"(r8z)
                     : "memory", "cc");
    return ret;
}

__attribute__((__always_inline__))
static long syscalln1(uint64_t call, uint64_t arg0) {
    volatile long ret;
    /* Explicitly zero the unused argument registers (rsi/rdx/r10/r9/r8).
     * The kernel-side syscall ABI does not document register liveness for
     * unused argument slots, but several multiplexed Linux-compat syscalls
     * (notably SYS_set_tid_address aliased onto SYS_SETTIDID) inspect arg1
     * to disambiguate between length-prefixed thread-name vs single-arg
     * Linux ABI. If the C compiler leaves unrelated values in those
     * registers, multiplex dispatch routes deterministically wrong. Zeroing
     * here makes one-arg syscalls pass arg1..arg4 = 0 by contract. */
    register uint64_t r10z __asm__("r10") = 0;
    register uint64_t r9z  __asm__("r9")  = 0;
    register uint64_t r8z  __asm__("r8")  = 0;
    __asm__ volatile("int $0x69"
                     : "=a"(ret)
                     : "a"(call), "D"(arg0), "S"(0ULL), "d"(0ULL),
                       "r"(r10z), "r"(r9z), "r"(r8z)
                     : "memory", "cc");
    return ret;
}

__attribute__((__always_inline__))
static long syscalln2(uint64_t call, uint64_t arg0, uint64_t arg1) {
    volatile long ret;
    register uint64_t r10z __asm__("r10") = 0;
    register uint64_t r8z  __asm__("r8")  = 0;
    register uint64_t r9z  __asm__("r9")  = 0;
    __asm__ volatile("int $0x69"
                     : "=a"(ret)
                     : "a"(call), "D"(arg0), "S"(arg1), "d"(0ULL),
                       "r"(r10z), "r"(r8z), "r"(r9z)
                     : "memory", "cc");
    return ret;
}

__attribute__((__always_inline__))
static long syscalln3(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2) {
    volatile long ret;
    register uint64_t r10z __asm__("r10") = 0;
    register uint64_t r8z  __asm__("r8")  = 0;
    register uint64_t r9z  __asm__("r9")  = 0;
    __asm__ volatile("int $0x69"
                     : "=a"(ret)
                     : "a"(call), "D"(arg0), "S"(arg1), "d"(arg2),
                       "r"(r10z), "r"(r8z), "r"(r9z)
                     : "memory", "cc");
    return ret;
}

__attribute__((__always_inline__))
static long syscalln4(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    volatile long ret;
	register uint64_t arg3r __asm__("r10") = arg3; /* put arg3 in r10 */
    register uint64_t r8z __asm__("r8") = 0;
    register uint64_t r9z __asm__("r9") = 0;
    __asm__ volatile("int $0x69"
                     : "=a"(ret)
                     : "a"(call), "D"(arg0), "S"(arg1), "d"(arg2),
                       "r"(arg3r), "r"(r8z), "r"(r9z)
                     : "memory", "cc");
    return ret;
}

__attribute__((__always_inline__))
static long syscalln5(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    volatile long ret;
	register uint64_t arg3r __asm__("r10") = arg3; /* put arg3 in r10 */
	register uint64_t arg4r __asm__("r8") = arg4; /* put arg4 in r8 */
	register uint64_t r9z __asm__("r9") = 0;
    __asm__ volatile("int $0x69" : "=a"(ret) : "a"(call), "D"(arg0), "S"(arg1), "d"(arg2), "r"(arg3r), "r"(arg4r), "r"(r9z) : "memory", "cc");
    return ret;
}

__attribute__((__always_inline__))
static long syscalln6(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    volatile long ret;
	register uint64_t arg3r __asm__("r10") = arg3; /* put arg3 in r10 */
	register uint64_t arg4r __asm__("r8") = arg4; /* put arg4 in r8 */
	register uint64_t arg5r __asm__("r9") = arg5; /* put arg5 in r9 */
    __asm__ volatile("int $0x69" : "=a"(ret) : "a"(call), "D"(arg0), "S"(arg1), "d"(arg2), "r"(arg3r), "r"(arg4r), "r"(arg5r) : "memory", "cc");
    return ret;
}

// Non-Linux Unified extension: a seventh argument is passed in r12.
__attribute__((__always_inline__))
static long syscalln7(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    volatile long ret;
	register uint64_t arg3r __asm__("r10") = arg3; /* put arg3 in r10 */
	register uint64_t arg4r __asm__("r8") = arg4; /* put arg4 in r8 */
	register uint64_t arg5r __asm__("r9") = arg5; /* put arg5 in r9 */
	register uint64_t arg6r __asm__("r12") = arg6; /* put arg6 in r12 */
    __asm__ volatile("int $0x69" : "=a"(ret) : "a"(call), "D"(arg0), "S"(arg1), "d"(arg2), "r"(arg3r), "r"(arg4r), "r"(arg5r), "r"(arg6r) : "memory", "cc");
    return ret;
}

#ifdef __cplusplus
}
    __attribute__((__always_inline__)) static inline long _syscall(uint64_t call) { return syscalln0(call); }
    __attribute__((__always_inline__)) static inline long _syscall(uint64_t call, uint64_t arg0) { return syscalln1(call, arg0); }
    __attribute__((__always_inline__)) static inline long _syscall(uint64_t call, uint64_t arg0, uint64_t arg1) { return syscalln2(call, arg0, arg1); }
    __attribute__((__always_inline__)) static inline long _syscall(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2) { return syscalln3(call, arg0, arg1, arg2); }
    __attribute__((__always_inline__)) static inline long _syscall(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) { return syscalln4(call, arg0, arg1, arg2, arg3); }
    __attribute__((__always_inline__)) static inline long _syscall(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4)  { return syscalln5(call, arg0, arg1, arg2, arg3, arg4); }
    __attribute__((__always_inline__)) static inline long _syscall(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5)  { return syscalln6(call, arg0, arg1, arg2, arg3, arg4, arg5); }
    __attribute__((__always_inline__)) static inline long _syscall(uint64_t call, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6)  { return syscalln7(call, arg0, arg1, arg2, arg3, arg4, arg5, arg6); }

#ifndef UNIFIED_NO_SYSCALL_MACRO
    template<typename... T>
    __attribute__((__always_inline__)) static inline long syscall(uint64_t call, T... args){
        return _syscall(call, (uint64_t)(args)...);
    }
#endif /* UNIFIED_NO_SYSCALL_MACRO */
#else
#ifndef UNIFIED_NO_SYSCALL_MACRO
    #define GET_SYSCALL(a0, a1, a2, a3, a4, a5, a6, a7, name, ...) name
    #define syscall(...) GET_SYSCALL(__VA_ARGS__, syscalln7, syscalln6, syscalln5, syscalln4, syscalln3, syscalln2, syscalln1, syscalln0)(__VA_ARGS__)
#endif /* UNIFIED_NO_SYSCALL_MACRO */
#endif

#endif

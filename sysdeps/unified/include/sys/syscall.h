#ifndef _SYS_SYSCALL_H
#define _SYS_SYSCALL_H

#include <unified/syscall.h>

// Map Linux syscall names (lowercase) to Unified syscall numbers (uppercase)
#define SYS_gettid SYS_GETTID
#define SYS_futex SYS_FUTEX_WAIT
#define SYS_get_mempolicy SYS_GET_MEMPOLICY
#define SYS_membarrier SYS_MEMBARRIER
#define SYS_getcpu SYS_GETCPU
#define SYS_memfd_create SYS_MEMFD_CREATE
#define SYS_fallocate SYS_FALLOCATE
#define SYS_futex_time64 SYS_FUTEX_WAIT

#endif /* _SYS_SYSCALL_H */

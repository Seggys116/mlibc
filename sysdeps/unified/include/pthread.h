#pragma once

#include_next <pthread.h>

#if defined(__MLIBC_BUILDING_MLIBC) && !defined(MLIBC_UNIFIED_IMPLEMENTING_ABI_OVERRIDES)
#pragma weak pthread_cond_timedwait
#pragma weak pthread_getattr_np
#pragma weak pthread_getspecific
#endif

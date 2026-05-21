#pragma once

#include_next <semaphore.h>

#if defined(__MLIBC_BUILDING_MLIBC) && !defined(MLIBC_UNIFIED_IMPLEMENTING_ABI_OVERRIDES)
#pragma weak sem_getvalue
#endif

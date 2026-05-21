#pragma once

#include_next <sched.h>

#if defined(__MLIBC_BUILDING_MLIBC) && !defined(MLIBC_UNIFIED_IMPLEMENTING_ABI_OVERRIDES)
#pragma weak sched_setaffinity
#pragma weak clone
#endif

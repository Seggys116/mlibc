#pragma once

#include_next <sys/mman.h>

#if defined(__MLIBC_BUILDING_MLIBC) && !defined(MLIBC_UNIFIED_IMPLEMENTING_ABI_OVERRIDES)
#pragma weak mremap
#endif

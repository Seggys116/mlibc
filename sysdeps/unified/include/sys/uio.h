#pragma once

#include_next <sys/uio.h>

#if defined(__MLIBC_BUILDING_MLIBC) && !defined(MLIBC_UNIFIED_IMPLEMENTING_ABI_OVERRIDES)
#pragma weak preadv
#pragma weak pwritev
#endif

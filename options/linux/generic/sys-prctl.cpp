
#include <stdarg.h>
#include <errno.h>
#include <bits/ensure.h>
#include <sys/prctl.h>

#include <mlibc/debug.hpp>

#include "mlibc/linux-sysdeps.hpp"

int prctl(int op, ...) {
#if defined(__x86_64__)
	register unsigned long raw_arg2 asm("rsi");
	register unsigned long raw_arg3 asm("rdx");
	register unsigned long raw_arg4 asm("rcx");
	register unsigned long raw_arg5 asm("r8");
	unsigned long arg2 = raw_arg2;
	unsigned long arg3 = raw_arg3;
	unsigned long arg4 = raw_arg4;
	unsigned long arg5 = raw_arg5;

	if(mlibc::sys_prctl_args) {
		int val;
		if(int e = mlibc::sys_prctl_args(op, arg2, arg3, arg4, arg5, &val); e) {
			errno = e;
			return -1;
		}
		return val;
	}
#endif

	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_prctl, -1);

	int val;
	va_list ap;
	va_start(ap, op);
	if(int e = mlibc::sys_prctl(op, ap, &val); e) {
		errno = e;
		return -1;
	}
	va_end(ap);

	return val;
}

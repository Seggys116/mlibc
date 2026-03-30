
#include <bits/ensure.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>

#include <mlibc/debug.hpp>
#include <mlibc/posix-sysdeps.hpp>

int sched_yield(void) {
	if(mlibc::sys_yield) {
		mlibc::sys_yield();
	}else{
		// Missing sched_yield() is not an error.
		MLIBC_MISSING_SYSDEP();
	}
	return 0;
}

int sched_get_priority_max(int policy) {
	int res = 0;

	auto sysdep = MLIBC_CHECK_OR_ENOSYS(mlibc::sys_get_max_priority, -1);
	if(int e = sysdep(policy, &res); e) {
		errno = e;
		return -1;
	}
	return res;
}

int sched_get_priority_min(int policy) {
	int res = 0;

	auto sysdep = MLIBC_CHECK_OR_ENOSYS(mlibc::sys_get_min_priority, -1);
	if(int e = sysdep(policy, &res); e) {
		errno = e;
		return -1;
	}
	return res;
}

int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param) {
	if(pid < 0 || !param) {
		errno = EINVAL;
		return -1;
	}

	auto set_sysdep = MLIBC_CHECK_OR_ENOSYS(mlibc::sys_setscheduler, -1);
	if(int e = set_sysdep(pid, policy, param); e) {
		errno = e;
		return -1;
	}

	return 0;
}

int sched_getparam(pid_t pid, struct sched_param *param) {
	if(pid < 0 || !param) {
		errno = EINVAL;
		return -1;
	}
	auto sysdep = MLIBC_CHECK_OR_ENOSYS(mlibc::sys_getparam, -1);
	if(int e = sysdep(pid, param); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int sched_setparam(pid_t pid, const struct sched_param *param) {
	if(pid < 0 || !param) {
		errno = EINVAL;
		return -1;
	}
	auto sysdep = MLIBC_CHECK_OR_ENOSYS(mlibc::sys_setparam, -1);
	if(int e = sysdep(pid, param); e) {
		errno = e;
		return -1;
	}
	return 0;
}

#include <bits/ensure.h>
#include <bits/linux/linux_sched.h>
#include <errno.h>
#include <sched.h>
#include <stdarg.h>

#include <mlibc/linux-sysdeps.hpp>
#include <mlibc/posix-sysdeps.hpp>

int sched_getcpu(void) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_getcpu, -1);
	int cpu;
	if(int e = mlibc::sys_getcpu(&cpu); e) {
		errno = e;
		return -1;
	}
	return cpu;
}

int setns(int fd, int nstype) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_setns, -1);
	if(int e = mlibc::sys_setns(fd, nstype); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int sched_getscheduler(pid_t pid) {
	if(pid < 0) {
		errno = EINVAL;
		return -1;
	}
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_getscheduler, -1);
	int policy;
	if(int e = mlibc::sys_getscheduler(pid, &policy); e) {
		errno = e;
		return -1;
	}
	return policy;
}

int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_getaffinity, -1);
	if(int e = mlibc::sys_getaffinity(pid, cpusetsize, mask); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int unshare(int flags) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_unshare, -1);
	if(int e = mlibc::sys_unshare(flags); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_setaffinity, -1);
	if(int e = mlibc::sys_setaffinity(pid, cpusetsize, mask); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_clone_linux, -1);

	if(!fn || !stack) {
		errno = EINVAL;
		return -1;
	}

	va_list ap;
	va_start(ap, arg);

	pid_t *parent_tid = nullptr;
	void *tls = nullptr;
	pid_t *child_tid = nullptr;

	if((flags & CLONE_PIDFD) && (flags & CLONE_PARENT_SETTID)) {
		va_end(ap);
		errno = EINVAL;
		return -1;
	}

	if(flags & (CLONE_PARENT_SETTID | CLONE_PIDFD))
		parent_tid = va_arg(ap, pid_t *);
	if(flags & CLONE_SETTLS)
		tls = va_arg(ap, void *);
	if(flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID))
		child_tid = va_arg(ap, pid_t *);

	va_end(ap);

	int ret = -1;
	if(int e = mlibc::sys_clone_linux(fn, stack, flags, arg, parent_tid, tls, child_tid, &ret); e) {
		errno = e;
		return -1;
	}

	return ret;
}

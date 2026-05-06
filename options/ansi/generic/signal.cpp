
#include <bits/ensure.h>
#include <errno.h>
#include <signal.h>

#include <mlibc/debug.hpp>
#include <mlibc/ansi-sysdeps.hpp>
#include <mlibc/posix-sysdeps.hpp>

__sighandler signal(int sn, __sighandler handler) {
	struct sigaction sa;
	sa.sa_handler = handler;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	struct sigaction old;
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_sigaction, SIG_ERR);
	if(int e = mlibc::sys_sigaction(sn, &sa, &old)){
		errno = e;
		return SIG_ERR;
	}
	return old.sa_handler;
}

int raise(int sig) {
	// POSIX: in a multithreaded program, raise(sig) is equivalent to
	// pthread_kill(pthread_self(), sig), not kill(getpid(), sig). Using
	// sys_kill here routes signal to ANY eligible thread in the process and
	// can escape a per-thread signal mask that the caller set on itself only.
	// Prefer sys_tgkill on the calling thread; fall back to sys_kill only when
	// the tgkill sysdep is missing.
	if (mlibc::sys_tgkill && mlibc::sys_gettid && mlibc::sys_getpid) {
		pid_t tgid = mlibc::sys_getpid();
		pid_t tid = mlibc::sys_gettid();
		if (int e = mlibc::sys_tgkill(tgid, tid, sig)) {
			errno = e;
			return -1;
		}
		return 0;
	}
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_getpid && mlibc::sys_kill, -1);
	pid_t pid = mlibc::sys_getpid();

	if (int e = mlibc::sys_kill(pid, sig)) {
		errno = e;
		return -1;
	}

	return 0;
}

// This is a POSIX extension, but we have it in here for sigsetjmp
int sigprocmask(int how, const sigset_t *__restrict set, sigset_t *__restrict retrieve) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_sigprocmask, -1);
	if(int e = mlibc::sys_sigprocmask(how, set, retrieve); e) {
		errno = e;
		return -1;
	}
	return 0;
}


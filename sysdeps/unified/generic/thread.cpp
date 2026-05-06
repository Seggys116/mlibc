#include <bits/ensure.h>
#include <errno.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/tcb.hpp>
#include <mlibc/thread.hpp>
#include <mlibc/thread-entry.hpp>
#include <mlibc/debug.hpp>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unified/syscall.h>

static constexpr uintptr_t kCloneThreadFlag = 0x00010000;

extern "C" [[gnu::visibility("hidden")]] void __mlibc_enter_thread(void *entry, void *user_arg, Tcb *tcb) {
	(void)entry;
	(void)user_arg;

	if (!tcb) {
		mlibc::sys_libc_log("__mlibc_enter_thread: null tcb");
		__ensure(tcb);
	}
	if (!tcb->threadEntry) {
		mlibc::sys_libc_log("__mlibc_enter_thread: null stored thread entry before start gate");
		__ensure(tcb->threadEntry);
	}

	// Keep new pthreads parked until the parent completes post-clone setup
	// (signal mask restoration, attr-driven scheduler state, etc.).
	// Parent-side startup failures are reported through startupError.
	while (!__atomic_load_n(&tcb->startGate, __ATOMIC_ACQUIRE)) {
		mlibc::sys_futex_wait(&tcb->startGate, 0, nullptr);
	}

	int startupError = __atomic_load_n(&tcb->startupError, __ATOMIC_ACQUIRE);
	if(startupError) {
		__atomic_store_n(&tcb->didExit, 1, __ATOMIC_RELEASE);
#ifndef SYS_SETTIDID
		mlibc::sys_futex_wake(&tcb->didExit);
#endif
		mlibc::sys_thread_exit();
	}

	// Wait until our parent sets up the TID.
	while (!__atomic_load_n(&tcb->tid, __ATOMIC_ACQUIRE)) {
		mlibc::sys_futex_wait(&tcb->tid, 0, nullptr);
	}

	if (mlibc::sys_tcb_set(tcb)) {
		mlibc::sys_libc_log("__mlibc_enter_thread: sys_tcb_set failed");
		__ensure(!"sys_tcb_set() failed");
	}

	if (!tcb->threadEntry) {
		mlibc::sys_libc_log("__mlibc_enter_thread: null stored thread entry after start gate");
		__ensure(tcb->threadEntry);
	}

	tcb->invokeThreadFunc(tcb->threadEntry, tcb->threadUserArg);

	auto self = mlibc::get_current_tcb();

	__atomic_store_n(&self->didExit, 1, __ATOMIC_RELEASE);
#ifndef SYS_SETTIDID
	mlibc::sys_futex_wake(&self->didExit);
#endif

	mlibc::sys_thread_exit();
}

extern "C" [[noreturn, gnu::visibility("hidden")]] void __mlibc_enter_raw_clone(int (*fn)(void *), void *arg, uintptr_t flags) {
	int ret = fn(arg);

	if(flags & kCloneThreadFlag)
		mlibc::sys_thread_exit();

	mlibc::sys_exit(ret);
	__builtin_unreachable();
}

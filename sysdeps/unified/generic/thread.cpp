#include <bits/ensure.h>
#include <errno.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/tcb.hpp>
#include <mlibc/thread-entry.hpp>
#include <mlibc/debug.hpp>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

static constexpr uintptr_t kCloneThreadFlag = 0x00010000;

extern "C" void __mlibc_enter_thread(void *entry, void *user_arg, Tcb *tcb) {
	// Keep new pthreads parked until the parent completes post-clone setup
	// (signal mask restoration, attr-driven scheduler state, etc.).
	// Parent-side startup failures are reported through startupError.
	while (!__atomic_load_n(&tcb->startGate, __ATOMIC_ACQUIRE)) {
		mlibc::sys_futex_wait(&tcb->startGate, 0, nullptr);
	}

	int startupError = __atomic_load_n(&tcb->startupError, __ATOMIC_ACQUIRE);
	if(startupError) {
		__atomic_store_n(&tcb->didExit, 1, __ATOMIC_RELEASE);
		mlibc::sys_futex_wake(&tcb->didExit);
		mlibc::sys_thread_exit();
	}

	// Wait until our parent sets up the TID.
	while (!__atomic_load_n(&tcb->tid, __ATOMIC_ACQUIRE)) {
		mlibc::sys_futex_wait(&tcb->tid, 0, nullptr);
	}

	if (mlibc::sys_tcb_set(tcb))
		__ensure(!"sys_tcb_set() failed");

	tcb->invokeThreadFunc(entry, user_arg);

	auto self = reinterpret_cast<Tcb *>(tcb);

	__atomic_store_n(&self->didExit, 1, __ATOMIC_RELEASE);
	mlibc::sys_futex_wake(&self->didExit);

	mlibc::sys_thread_exit();
}

extern "C" [[noreturn]] void __mlibc_enter_raw_clone(int (*fn)(void *), void *arg, uintptr_t flags) {
	int ret = fn(arg);

	if(flags & kCloneThreadFlag)
		mlibc::sys_thread_exit();

	mlibc::sys_exit(ret);
	__builtin_unreachable();
}

#include <bits/ensure.h>
#include <errno.h>
#include <mlibc/all-sysdeps.hpp>
#include "../include/mlibc/tcb.hpp"
#include <mlibc/thread-entry.hpp>
#include <mlibc/debug.hpp>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unified/syscall.h>

static constexpr uintptr_t kCloneThreadFlag = 0x00010000;

namespace mlibc {

static inline Tcb *get_current_tcb() {
	uintptr_t ptr;
	asm volatile ("movq %%fs:0, %0" : "=r"(ptr));
	return reinterpret_cast<Tcb *>(ptr);
}

} // namespace mlibc

extern "C" [[gnu::visibility("hidden")]] void __mlibc_enter_thread(void *entry, void *user_arg, Tcb *tcb) {
	(void)entry;
	(void)user_arg;

	if (!tcb) {
		mlibc::Sysdeps<LibcLog>::operator()("__mlibc_enter_thread: null tcb");
		__ensure(tcb);
	}
	if (!tcb->threadEntry) {
		mlibc::Sysdeps<LibcLog>::operator()("__mlibc_enter_thread: null stored thread entry before start gate");
		__ensure(tcb->threadEntry);
	}

	// Keep new pthreads parked until the parent completes post-clone setup
	// (signal mask restoration, attr-driven scheduler state, etc.).
	// Parent-side startup failures are reported through startupError.
	while (!__atomic_load_n(&tcb->startGate, __ATOMIC_ACQUIRE)) {
		mlibc::Sysdeps<FutexWait>::operator()(&tcb->startGate, 0, nullptr);
	}

	int startupError = __atomic_load_n(&tcb->startupError, __ATOMIC_ACQUIRE);
	if(startupError) {
		__atomic_store_n(&tcb->didExit, 1, __ATOMIC_RELEASE);
#ifndef SYS_SETTIDID
		mlibc::Sysdeps<FutexWake>::operator()(&tcb->didExit, false);
#endif
		mlibc::Sysdeps<ThreadExit>::operator()();
	}

	// Wait until our parent sets up the TID.
	while (!__atomic_load_n(&tcb->tid, __ATOMIC_ACQUIRE)) {
		mlibc::Sysdeps<FutexWait>::operator()(&tcb->tid, 0, nullptr);
	}

	if (mlibc::Sysdeps<TcbSet>::operator()(tcb)) {
		mlibc::Sysdeps<LibcLog>::operator()("__mlibc_enter_thread: sys_tcb_set failed");
		__ensure(!"Sysdeps<TcbSet>::operator()() failed");
	}

	if (!tcb->threadEntry) {
		mlibc::Sysdeps<LibcLog>::operator()("__mlibc_enter_thread: null stored thread entry after start gate");
		__ensure(tcb->threadEntry);
	}

	tcb->invokeThreadFunc(tcb->threadEntry, tcb->threadUserArg);

	auto self = mlibc::get_current_tcb();

	__atomic_store_n(&self->didExit, 1, __ATOMIC_RELEASE);
#ifndef SYS_SETTIDID
	mlibc::Sysdeps<FutexWake>::operator()(&self->didExit, false);
#endif

	mlibc::Sysdeps<ThreadExit>::operator()();
}

extern "C" [[noreturn, gnu::visibility("hidden")]] void __mlibc_enter_raw_clone(int (*fn)(void *), void *arg, uintptr_t flags) {
	int ret = fn(arg);

	if(flags & kCloneThreadFlag)
		mlibc::Sysdeps<ThreadExit>::operator()();

	mlibc::Sysdeps<Exit>::operator()(ret);
	__builtin_unreachable();
}

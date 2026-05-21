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
	if (!tcb) {
		mlibc::Sysdeps<LibcLog>::operator()("__mlibc_enter_thread: null tcb");
		__ensure(tcb);
	}

	if (mlibc::Sysdeps<TcbSet>::operator()(tcb)) {
		mlibc::Sysdeps<LibcLog>::operator()("__mlibc_enter_thread: sys_tcb_set failed");
		__ensure(!"Sysdeps<TcbSet>::operator()() failed");
	}

	// Wait until our parent publishes the TID after clone returns.
	while (!__atomic_load_n(&tcb->tid, __ATOMIC_ACQUIRE)) {
		mlibc::Sysdeps<FutexWait>::operator()(&tcb->tid, 0, nullptr);
	}

	tcb->invokeThreadFunc(entry, user_arg);

	auto self = mlibc::get_current_tcb();

	__atomic_store_n(&self->didExit, 1, __ATOMIC_RELEASE);
	mlibc::Sysdeps<FutexWake>::operator()(&self->didExit, false);

	mlibc::Sysdeps<ThreadExit>::operator()();
}

extern "C" [[noreturn, gnu::visibility("hidden")]] void __mlibc_enter_raw_clone(int (*fn)(void *), void *arg, uintptr_t flags) {
	int ret = fn(arg);

	if(flags & kCloneThreadFlag)
		mlibc::Sysdeps<ThreadExit>::operator()();

	mlibc::Sysdeps<Exit>::operator()(ret);
	__builtin_unreachable();
}

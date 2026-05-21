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

	__atomic_fetch_or(&tcb->cancelBits, tcbCancelEnableBit, __ATOMIC_RELAXED);

	tcb->invokeThreadFunc(entry, user_arg);

	mlibc::thread_exit(tcb->returnValue);
}

extern "C" [[noreturn, gnu::visibility("hidden")]] void __mlibc_enter_raw_clone(int (*fn)(void *), void *arg, uintptr_t flags) {
	int ret = fn(arg);

	if(flags & kCloneThreadFlag)
		mlibc::Sysdeps<ThreadExit>::operator()();

	mlibc::Sysdeps<Exit>::operator()(ret);
	__builtin_unreachable();
}

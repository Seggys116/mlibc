#pragma once

#include <mlibc/thread.hpp>
#include <mlibc/internal-sysdeps.hpp>
#include <limits.h>
#include <stdint.h>

namespace mlibc {
	inline unsigned int sanitize_tid(long raw_tid) {
		constexpr unsigned int max_tid = (1u << 30) - 1;
		if(raw_tid <= 0)
			return 0;
		if(static_cast<unsigned long>(raw_tid) > max_tid)
			return 0;
		return static_cast<unsigned int>(raw_tid);
	}

	inline unsigned int fallback_tid_from_tcb(Tcb *tcb) {
		constexpr unsigned int max_tid = (1u << 30) - 1;
		uintptr_t key = reinterpret_cast<uintptr_t>(tcb);
		if(tcb && tcb->selfPointer)
			key = reinterpret_cast<uintptr_t>(tcb->selfPointer);
		unsigned int pseudo = static_cast<unsigned int>(((key >> 4) ^ (key >> 17) ^ (key >> 31)) & max_tid);
		if(!pseudo)
			pseudo = 1;
		return pseudo;
	}

	inline unsigned int load_cached_tid(Tcb *tcb) {
		if(!tcb)
			return 0;
		return sanitize_tid(__atomic_load_n(&tcb->futexTidCache, __ATOMIC_ACQUIRE));
	}

	inline unsigned int cache_tid_identity(Tcb *tcb, unsigned int tid) {
		if(!tcb || !tid)
			return tid;
		int expected = 0;
		int desired = static_cast<int>(tid);
		(void)__atomic_compare_exchange_n(&tcb->futexTidCache, &expected, desired,
				false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
		unsigned int cached = load_cached_tid(tcb);
		return cached ? cached : tid;
	}

	inline unsigned int this_tid() {
		// During RTLD initialization, we don't have a TCB.
		if (mlibc::tcb_available_flag) {
			auto tcb = get_current_tcb();
			// Keep lock-owner identity stable for the thread once we have ever
			// observed a usable value.
			if(unsigned int cached = load_cached_tid(tcb))
				return cached;

			// Be defensive against early thread-start races: some callers acquire
			// futex-backed locks immediately after TLS becomes available.
			unsigned int tid = tcb ? sanitize_tid(__atomic_load_n(&tcb->tid, __ATOMIC_ACQUIRE)) : 0;
			if (tid)
				return cache_tid_identity(tcb, tid);

			// Fall back to the kernel TID if the TCB has not been populated yet.
			if (mlibc::sys_futex_tid) {
				unsigned int fallback = sanitize_tid(mlibc::sys_futex_tid());
				if(fallback)
					return cache_tid_identity(tcb, fallback);
			}

			// Keep mutex owner identity stable even if gettid() is transiently
			// unavailable, but never poison tcb->tid itself since that word is also
			// used by CLONE_CHILD_CLEARTID / pthread_join waiters.
			return cache_tid_identity(tcb, fallback_tid_from_tcb(tcb));
		} else if (mlibc::sys_futex_tid) {
			unsigned int fallback = sanitize_tid(mlibc::sys_futex_tid());
			if(fallback)
				return fallback;
			return 1;
		} else {
			return 1;
		}
	}
}

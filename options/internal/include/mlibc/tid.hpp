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

	inline unsigned int this_tid() {
		// During RTLD initialization, we don't have a TCB.
		if (mlibc::tcb_available_flag) {
			auto tcb = get_current_tcb();
			// Be defensive against early thread-start races: some callers acquire
			// futex-backed locks immediately after TLS becomes available.
			unsigned int tid = __atomic_load_n(&tcb->tid, __ATOMIC_ACQUIRE);
			constexpr unsigned int max_tid = (1u << 30) - 1;
			if (tid > 0 && tid <= max_tid)
				return tid;

			// Fall back to the kernel TID if the TCB has not been populated yet.
			if (mlibc::sys_futex_tid) {
				unsigned int fallback = sanitize_tid(mlibc::sys_futex_tid());
				if(fallback)
					return fallback;
			}

			// Keep mutex owner identity stable even if gettid() is transiently
			// unavailable: derive a per-thread fallback from the TCB address.
			unsigned int pseudo = fallback_tid_from_tcb(tcb);
			if(tcb) {
				int expected = 0;
				(void)__atomic_compare_exchange_n(&tcb->tid, &expected, static_cast<int>(pseudo),
						false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
			}
			return pseudo;
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

#include <semaphore.h>
#include <errno.h>
#include <time.h>

#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <mlibc/ansi-sysdeps.hpp>
#include <mlibc/posix-sysdeps.hpp>

static constexpr unsigned int semaphoreHasWaiters = static_cast<uint32_t>(1 << 31);
static constexpr unsigned int semaphoreCountMask = static_cast<uint32_t>(1 << 31) - 1;

int sem_init(sem_t *sem, int pshared, unsigned int initial_count) {
	if (pshared) {
		mlibc::infoLogger() << "mlibc: shared semaphores are unsuppored" << frg::endlog;
		errno = ENOSYS;
		return -1;
	}

	if (initial_count > SEM_VALUE_MAX) {
		errno = EINVAL;
		return -1;
	}

	sem->__mlibc_count = initial_count;

	return 0;
}

int sem_destroy(sem_t *) {
	return 0;
}

int sem_wait(sem_t *sem) {
	while (1) {
		unsigned int state = __atomic_load_n(&sem->__mlibc_count, __ATOMIC_ACQUIRE);
		unsigned int count = state & semaphoreCountMask;

		if (count) {
			unsigned int desired = (state & semaphoreHasWaiters) | (count - 1);
			if (__atomic_compare_exchange_n(&sem->__mlibc_count, &state, desired, false,
						__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
				return 0;
			continue;
		}

		unsigned int wait_state = state | semaphoreHasWaiters;
		if (!__atomic_compare_exchange_n(&sem->__mlibc_count, &state, wait_state,
					false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
			continue;

		int e = mlibc::sys_futex_wait((int *)&sem->__mlibc_count, wait_state, nullptr);
		if (e == 0 || e == EAGAIN) {
			continue;
		} else if (e == EINTR) {
			errno = EINTR;
			return -1;
		} else {
			mlibc::panicLogger() << "sys_futex_wait() failed with error code " << e << frg::endlog;
		}
	}
}

int sem_timedwait(sem_t *sem, const struct timespec *abs_timeout) {
	while (1) {
		unsigned int state = __atomic_load_n(&sem->__mlibc_count, __ATOMIC_ACQUIRE);
		unsigned int count = state & semaphoreCountMask;

		if (count) {
			// Count > 0: try to decrement
			unsigned int desired = (state & semaphoreHasWaiters) | (count - 1);
			if (__atomic_compare_exchange_n(&sem->__mlibc_count, &state, desired, false,
						__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
				return 0;
			continue; // CAS failed, reload state and retry
		}

		// Count is 0: compute relative timeout from absolute CLOCK_REALTIME deadline
		struct timespec now;
		clock_gettime(CLOCK_REALTIME, &now);

		struct timespec rel;
		rel.tv_sec  = abs_timeout->tv_sec  - now.tv_sec;
		rel.tv_nsec = abs_timeout->tv_nsec - now.tv_nsec;
		if (rel.tv_nsec < 0) {
			rel.tv_sec--;
			rel.tv_nsec += 1000000000L;
		}
		if (rel.tv_sec < 0 || (rel.tv_sec == 0 && rel.tv_nsec <= 0)) {
			errno = ETIMEDOUT;
			return -1;
		}

		// Set hasWaiters flag so sem_post knows to call futex_wake.
		unsigned int wait_state = state | semaphoreHasWaiters;
		if (!__atomic_compare_exchange_n(&sem->__mlibc_count, &state, wait_state,
					false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
			continue;

		int e = mlibc::sys_futex_wait((int *)&sem->__mlibc_count, wait_state, &rel);
		if (e == ETIMEDOUT) {
			errno = ETIMEDOUT;
			return -1;
		}
		if (e == 0 || e == EAGAIN || e == EINTR)
			continue;

		mlibc::panicLogger() << "sys_futex_wait() failed with error code " << e << frg::endlog;
	}
}

int sem_post(sem_t *sem) {
	while (1) {
		// Keep waiter-bit state intact while incrementing count.
		unsigned int state = __atomic_load_n(&sem->__mlibc_count, __ATOMIC_RELAXED);
		unsigned int count = state & semaphoreCountMask;
		if (count + 1 > SEM_VALUE_MAX) {
			errno = EOVERFLOW;
			return -1;
		}

		unsigned int desired = (state & semaphoreHasWaiters) | (count + 1);
		if (!__atomic_compare_exchange_n(&sem->__mlibc_count, &state, desired,
					false, __ATOMIC_RELEASE, __ATOMIC_RELAXED))
			continue;

		if (state & semaphoreHasWaiters) {
			int e = mlibc::sys_futex_wake((int *)&sem->__mlibc_count);
			__ensure(e >= 0);
		}

		return 0;
	}
}

sem_t *sem_open(const char *, int, ...) {
	__ensure(!"Not implemented");
	__builtin_unreachable();
}

int sem_close(sem_t *) {
	__ensure(!"Not implemented");
	__builtin_unreachable();
}

int sem_getvalue(sem_t *sem, int *sval) {
	auto count = __atomic_load_n(&sem->__mlibc_count, __ATOMIC_RELAXED) & semaphoreCountMask;
	*sval = static_cast<int>(count);
	return 0;
}

int sem_unlink(const char *) {
	__ensure(!"Not implemented");
	__builtin_unreachable();
}

int sem_trywait(sem_t *sem) {
	while (true) {
		auto state = __atomic_load_n(&sem->__mlibc_count, __ATOMIC_ACQUIRE);
		auto count = state & semaphoreCountMask;

		if (!count) {
			errno = EAGAIN;
			return -1;
		}

		auto desired = (state & semaphoreHasWaiters) | (count - 1);
		if (__atomic_compare_exchange_n(&sem->__mlibc_count, &state, desired, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED)) {
			return 0;
		}
	}
}

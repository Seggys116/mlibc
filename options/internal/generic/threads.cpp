#include <abi-bits/errno.h>
#include <bits/threads.h>
#include <bits/ensure.h>
#include <limits.h>
#include <frg/allocation.hpp>
#include <frg/mutex.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/allocator.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/lock.hpp>
#include <mlibc/threads.hpp>
#include <mlibc/tcb.hpp>
#include <mlibc/time-helpers.hpp>
#include <sched.h>
#include <unistd.h>

extern "C" Tcb *__rtld_allocateTcb();

namespace {
static constexpr int kJoinableBit = 1;
static constexpr int kStackOwnedBit = 2;

struct key_global_info {
	bool in_use;

	void (*dtor)(void *);
	uint64_t generation;
};

constinit frg::array<
	key_global_info,
	PTHREAD_KEYS_MAX
> key_globals_{};

FutexLock key_mutex_;

} // namespace

namespace mlibc {

static constexpr unsigned int onceComplete = 1;
static constexpr unsigned int onceLocked = 2;
static constexpr int explicitSched = 1;

static int validate_explicit_sched_attr(const __mlibc_threadattr &attr) {
	if(attr.__mlibc_inheritsched != explicitSched)
		return 0;

	int policy = attr.__mlibc_schedpolicy;
	int priority = attr.__mlibc_schedparam.__sched_priority;

	if(policy != SCHED_OTHER && policy != SCHED_FIFO && policy != SCHED_RR)
		return EINVAL;

	if(policy == SCHED_OTHER) {
		if(priority != 0)
			return EINVAL;
	} else {
		if(priority < 1 || priority > 99)
			return EINVAL;
		if(geteuid() != 0)
			return EPERM;
	}

	if(!mlibc::sys_setschedparam)
		return ENOSYS;

	return 0;
}

static void cleanup_failed_thread_create(Tcb *tcb) {
	if(!tcb)
		return;

	if((tcb->isJoinable & kStackOwnedBit) && tcb->stackAddr && tcb->stackSize) {
		size_t map_size = tcb->stackSize + tcb->guardSize;
		(void)mlibc::sys_vm_unmap(tcb->stackAddr, map_size);
		tcb->stackAddr = nullptr;
		tcb->stackSize = 0;
		tcb->guardSize = 0;
	}
	if(tcb->localKeys) {
		frg::destruct(getAllocator(), tcb->localKeys);
		tcb->localKeys = nullptr;
	}
	if(tcb->dtvPointers) {
		frg::destruct_n(getAllocator(), tcb->dtvPointers, tcb->dtvSize);
		tcb->dtvPointers = nullptr;
		tcb->dtvSize = 0;
	}
}

static void abort_cloned_thread_start(Tcb *tcb, int error) {
	if(!tcb || error <= 0)
		return;

	__atomic_store_n(&tcb->startupError, error, __ATOMIC_RELEASE);
	__atomic_store_n(&tcb->startGate, 1, __ATOMIC_RELEASE);
	mlibc::sys_futex_wake(&tcb->startGate);

	for(;;) {
		int observedTid = __atomic_load_n(&tcb->tid, __ATOMIC_ACQUIRE);
		if(!observedTid)
			break;
		int e = mlibc::sys_futex_wait(&tcb->tid, observedTid, nullptr);
		if(e && e != EINTR && e != EAGAIN)
			break;
	}
}

int thread_once(__mlibc_once *once, void (*func) (void)) {
	auto expected = __atomic_load_n(&once->__mlibc_done, __ATOMIC_ACQUIRE);

	// fast path: the function was already run.
	while(!(expected & onceComplete)) {
		if(!expected) {
			// try to acquire the mutex.
			if(!__atomic_compare_exchange_n(&once->__mlibc_done,
					&expected, onceLocked, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE))
				continue;

			func();

			// unlock the mutex.
			__atomic_exchange_n(&once->__mlibc_done, onceComplete, __ATOMIC_RELEASE);
			if(int e = mlibc::sys_futex_wake((int *)&once->__mlibc_done, INT_MAX); e)
				__ensure(!"sys_futex_wake() failed");
			return 0;
		}else{
			// a different thread is currently running the initializer.
			__ensure(expected == onceLocked);
			// if the wait gets interrupted by a signal, check again.
			// EAGAIN will also be a retry, as it means the other thread completed
			// and changed the __mlibc_done variable to signal it before we actually went to sleep.
			if(int e = mlibc::sys_futex_wait((int *)&once->__mlibc_done, onceLocked, nullptr); e && e != EINTR && e != EAGAIN)
				__ensure(!"sys_futex_wait() failed");
			expected =  __atomic_load_n(&once->__mlibc_done, __ATOMIC_ACQUIRE);
		}
	}

	return 0;
}

int thread_create(struct __mlibc_thread_data **__restrict thread, const struct __mlibc_threadattr *__restrict attrp, void *entry, void *__restrict user_arg, bool returns_int) {
	pid_t tid = 0;
	struct __mlibc_threadattr attr = {};
	if (!attrp)
		thread_attr_init(&attr);
	else
		attr = *attrp;

	int explicit_sched_error = validate_explicit_sched_attr(attr);
	if(explicit_sched_error)
		return explicit_sched_error;

	auto new_tcb = __rtld_allocateTcb();

	// TODO: due to alignment guarantees, the stackaddr and stacksize might change
	// when the stack is allocated. Currently this isn't propagated to the TCB,
	// but it should be.
	void *stack = attr.__mlibc_stackaddr;
	if (!mlibc::sys_prepare_stack) {
		MLIBC_MISSING_SYSDEP();
		cleanup_failed_thread_create(new_tcb);
		return ENOSYS;
	}
	int ret = mlibc::sys_prepare_stack(&stack, entry,
			user_arg, new_tcb, &attr.__mlibc_stacksize, &attr.__mlibc_guardsize, &new_tcb->stackAddr);
	if (ret) {
		cleanup_failed_thread_create(new_tcb);
		return ret;
	}

	new_tcb->stackSize = attr.__mlibc_stacksize;
	new_tcb->guardSize = attr.__mlibc_guardsize;
	new_tcb->returnValueType = (returns_int) ? TcbThreadReturnValue::Integer : TcbThreadReturnValue::Pointer;
	new_tcb->isJoinable = 0;
	new_tcb->startGate = 0;
	new_tcb->startupError = 0;
	if (attr.__mlibc_detachstate == __MLIBC_THREAD_CREATE_JOINABLE)
		new_tcb->isJoinable |= kJoinableBit;
	if (!attr.__mlibc_stackaddr)
		new_tcb->isJoinable |= kStackOwnedBit;

	if (!mlibc::sys_clone) {
		MLIBC_MISSING_SYSDEP();
		cleanup_failed_thread_create(new_tcb);
		return ENOSYS;
	}

	sigset_t restore_mask = {};
	bool restore_sigmask = false;
	if (attr.__mlibc_sigmaskset) {
		if (!mlibc::sys_sigprocmask) {
			cleanup_failed_thread_create(new_tcb);
			return ENOSYS;
		}
		int mask_error = mlibc::sys_sigprocmask(SIG_SETMASK, &attr.__mlibc_sigmask, &restore_mask);
		if (mask_error) {
			cleanup_failed_thread_create(new_tcb);
			return mask_error;
		}
		restore_sigmask = true;
	}

	int clone_error = mlibc::sys_clone(new_tcb, &tid, stack);
	if(!clone_error) {
		__atomic_store_n(&new_tcb->tid, tid, __ATOMIC_RELEASE);
		mlibc::sys_futex_wake(&new_tcb->tid);
	}
	if (restore_sigmask) {
		int restore_error = mlibc::sys_sigprocmask(SIG_SETMASK, &restore_mask, nullptr);
		if (!clone_error && restore_error)
			clone_error = restore_error;
	}

	if(!clone_error && attr.__mlibc_inheritsched == explicitSched) {
		clone_error = mlibc::sys_setschedparam(new_tcb,
				attr.__mlibc_schedpolicy,
				reinterpret_cast<const struct sched_param *>(&attr.__mlibc_schedparam));
	}

	if(!clone_error && attr.__mlibc_cpuset) {
		if(!mlibc::sys_setthreadaffinity) {
			clone_error = ENOSYS;
		} else {
			clone_error = mlibc::sys_setthreadaffinity(tid,
					attr.__mlibc_cpusetsize, attr.__mlibc_cpuset);
		}
	}

	if(clone_error && tid > 0)
		abort_cloned_thread_start(new_tcb, clone_error);

	if(!clone_error) {
		*thread = reinterpret_cast<struct __mlibc_thread_data *>(new_tcb);
		__atomic_store_n(&new_tcb->startGate, 1, __ATOMIC_RELEASE);
		mlibc::sys_futex_wake(&new_tcb->startGate);
	}
	if (clone_error) {
		cleanup_failed_thread_create(new_tcb);
		return clone_error;
	}

	return 0;
}

int thread_join(struct __mlibc_thread_data *thread, void *ret) {
	auto tcb = reinterpret_cast<Tcb *>(thread);

	int observedFlags = __atomic_load_n(&tcb->isJoinable, __ATOMIC_ACQUIRE);
	if(!(observedFlags & kJoinableBit)) {
		mlibc::infoLogger() << "mlibc: pthread_join() called on a detached thread" << frg::endlog;
		return EINVAL;
	}

	for(;;) {
		int expected = observedFlags;
		if(!(expected & kJoinableBit))
			return EINVAL;
		int desired = expected & ~kJoinableBit;
		if(__atomic_compare_exchange_n(&tcb->isJoinable, &expected, desired, false,
				__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
			observedFlags = expected;
			break;
		}
		observedFlags = expected;
	}

	// Wait for userspace exit publication first when available.
	// Then wait for kernel thread teardown via CLONE_CHILD_CLEARTID (tid -> 0)
	// so stack reclamation cannot race with a still-running thread.
	while (!__atomic_load_n(&tcb->didExit, __ATOMIC_ACQUIRE)) {
		mlibc::sys_futex_wait(&tcb->didExit, 0, nullptr);
	}
	for(;;) {
		int observedTid = __atomic_load_n(&tcb->tid, __ATOMIC_ACQUIRE);
		if(!observedTid)
			break;
		mlibc::sys_futex_wait(&tcb->tid, observedTid, nullptr);
	}

	if(ret && tcb->returnValueType == TcbThreadReturnValue::Pointer)
		*reinterpret_cast<void **>(ret) = tcb->returnValue.voidPtr;
	else if(ret && tcb->returnValueType == TcbThreadReturnValue::Integer)
		*reinterpret_cast<int *>(ret) = tcb->returnValue.intVal;

	// Free the joined thread stack when mlibc allocated it.
	if ((observedFlags & kStackOwnedBit) && tcb->stackAddr && tcb->stackSize) {
		size_t map_size = tcb->stackSize + tcb->guardSize;
		if (int e = mlibc::sys_vm_unmap(tcb->stackAddr, map_size); e) {
			mlibc::infoLogger() << "mlibc: thread_join() failed to unmap stack, errno="
					<< e << frg::endlog;
		} else {
			tcb->stackAddr = nullptr;
			tcb->stackSize = 0;
			tcb->guardSize = 0;
		}
	}

	// Release per-thread key storage and DTV pointer table.
	if (tcb->localKeys) {
		frg::destruct(getAllocator(), tcb->localKeys);
		tcb->localKeys = nullptr;
	}
	if (tcb->dtvPointers) {
		frg::destruct_n(getAllocator(), tcb->dtvPointers, tcb->dtvSize);
		tcb->dtvPointers = nullptr;
		tcb->dtvSize = 0;
	}

	return 0;
}

int thread_detach(struct __mlibc_thread_data *thread) {
	auto tcb = reinterpret_cast<Tcb *>(thread);

	int observedFlags = __atomic_load_n(&tcb->isJoinable, __ATOMIC_ACQUIRE);
	for(;;) {
		int expected = observedFlags;
		if(!(expected & kJoinableBit))
			return EINVAL;
		int desired = expected & ~kJoinableBit;
		if(__atomic_compare_exchange_n(&tcb->isJoinable, &expected, desired, false,
				__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
			break;
		observedFlags = expected;
	}

	return 0;
}

namespace {

__attribute__ ((__noreturn__)) void do_exit() {
	sys_thread_exit();
	__builtin_unreachable();
}

} // namespace

__attribute__ ((__noreturn__)) void thread_exit(thread_exit_return ret_val) {
	auto self = get_current_tcb();

	if (__atomic_load_n(&self->cancelBits, __ATOMIC_RELAXED) & tcbExitingBit)
		mlibc::do_exit();

	__atomic_fetch_or(&self->cancelBits, tcbExitingBit, __ATOMIC_RELAXED);

	auto hand = self->cleanupEnd;
	while (hand) {
		auto old = hand;
		hand->func(hand->arg);
		hand = hand->prev;
		frg::destruct(getAllocator(), old);
	}

	if (self->localKeys) {
		for (size_t j = 0; j < __MLIBC_THREAD_DESTRUCTOR_ITERATIONS; j++) {
			for (size_t i = 0; i < PTHREAD_KEYS_MAX; i++) {
				if (auto v = thread_key_get(i)) {
					key_mutex_.lock();
					auto dtor = key_globals_[i].dtor;
					key_mutex_.unlock();

					if (dtor) {
						dtor(v);
						(*self->localKeys)[i].value = nullptr;
					}
				}
			}
		}
	}

	if(self->returnValueType == TcbThreadReturnValue::Pointer)
		self->returnValue.voidPtr = ret_val.voidPtr;
	else if(self->returnValueType == TcbThreadReturnValue::Integer)
		self->returnValue.intVal = ret_val.integer;

	__atomic_store_n(&self->didExit, 1, __ATOMIC_RELEASE);
	sys_futex_wake(&self->didExit);

	// TODO: clean up thread resources when we are detached.

	// TODO: do exit(0) when we're the only thread instead
	mlibc::do_exit();
}

// Keep defaults moderate for constrained kernels.
static constexpr size_t default_stacksize = 0x200000;
static constexpr size_t default_guardsize = 4096;

int thread_attr_init(struct __mlibc_threadattr *attr) {
	*attr = __mlibc_threadattr{};
	attr->__mlibc_stacksize = default_stacksize;
	attr->__mlibc_guardsize = default_guardsize;
	attr->__mlibc_detachstate = __MLIBC_THREAD_CREATE_JOINABLE;
	return 0;
}

static constexpr unsigned int mutexRecursive = 1;
static constexpr unsigned int mutexErrorCheck = 2;

// TODO: either use uint32_t or determine the bit based on sizeof(int).
static constexpr unsigned int mutex_owner_mask = (static_cast<uint32_t>(1) << 30) - 1;
static constexpr unsigned int mutex_waiters_bit = static_cast<uint32_t>(1) << 31;

static inline struct __mlibc_mutex *resolve_mutex_ptr(struct __mlibc_mutex *mutex, const char *fn) {
	(void)fn;
	if (mutex)
		return mutex;

	// Some third-party binaries call into pthread mutex entry points with a null
	// pointer during early startup. Returning EINVAL here tends to cascade into
	// immediate userspace crashes before they can recover. Route these calls to
	// a single emergency recursive mutex instead.
	static struct __mlibc_mutex emergency_mutex = {};
	static bool emergency_mutex_initialized = false;
	if (!__atomic_exchange_n(&emergency_mutex_initialized, true, __ATOMIC_ACQ_REL)) {
		emergency_mutex.__mlibc_state = 0;
		emergency_mutex.__mlibc_recursion = 0;
		emergency_mutex.__mlibc_flags = mutexRecursive;
		emergency_mutex.__mlibc_prioceiling = 0;
	}

	return &emergency_mutex;
}

int thread_mutex_init(struct __mlibc_mutex *__restrict mutex,
		const struct __mlibc_mutexattr *__restrict attr) {
	auto type = attr ? attr->__mlibc_type : __MLIBC_THREAD_MUTEX_DEFAULT;
	auto robust = attr ? attr->__mlibc_robust : __MLIBC_THREAD_MUTEX_STALLED;
	auto protocol = attr ? attr->__mlibc_protocol : __MLIBC_THREAD_PRIO_NONE;
	auto pshared = attr ? attr->__mlibc_pshared : __MLIBC_THREAD_PROCESS_PRIVATE;

	mutex->__mlibc_state = 0;
	mutex->__mlibc_recursion = 0;
	mutex->__mlibc_flags = 0;
	mutex->__mlibc_prioceiling = 0; // TODO: We don't implement this.

	if(type == __MLIBC_THREAD_MUTEX_RECURSIVE) {
		mutex->__mlibc_flags |= mutexRecursive;
	}else if(type == __MLIBC_THREAD_MUTEX_ERRORCHECK) {
		mutex->__mlibc_flags |= mutexErrorCheck;
	}else{
		__ensure(type == __MLIBC_THREAD_MUTEX_NORMAL);
	}

	// TODO: Other values aren't supported yet.
	__ensure(robust == __MLIBC_THREAD_MUTEX_STALLED);
	__ensure(protocol == __MLIBC_THREAD_PRIO_NONE);
	__ensure(pshared == __MLIBC_THREAD_PROCESS_PRIVATE);

	return 0;
}

int thread_mutex_destroy(struct __mlibc_mutex *mutex) {
	if (!mutex)
		return 0;
	__ensure(!mutex->__mlibc_state);
	return 0;
}

int thread_mutex_timedlock(struct __mlibc_mutex *mutex, const struct timespec *__restrict abstime, clockid_t clockid) {
	mutex = resolve_mutex_ptr(mutex, "thread_mutex_timedlock");

	unsigned int this_tid = mlibc::this_tid();
	unsigned int expected = 0;
	while(true) {
		if(!expected) {
			// Try to take the mutex here.
			if(__atomic_compare_exchange_n(&mutex->__mlibc_state,
					&expected, this_tid, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)) {
				__ensure(!mutex->__mlibc_recursion);
				mutex->__mlibc_recursion = 1;
				return 0;
			}
		}else{
			// If this (recursive) mutex is already owned by us, increment the recursion level.
			if((expected & mutex_owner_mask) == this_tid) {
				if(!(mutex->__mlibc_flags & mutexRecursive)) {
					if (!abstime)
						return EDEADLK;
				} else {
					++mutex->__mlibc_recursion;
					return 0;
				}
			}

			// Wait on the futex if the waiters flag is set.
			if(expected & mutex_waiters_bit) {
				int e;
				if (abstime) {
					// Adjust for the fact that sys_futex_wait accepts a *timeout*, but
					// we accept an *absolute time*.
					struct timespec timeout;
					if (!mlibc::time_absolute_to_relative(clockid, abstime, &timeout))
						return EINVAL;

					if (timeout.tv_sec == 0 && timeout.tv_nsec == 0)
						return ETIMEDOUT;

					e = mlibc::sys_futex_wait((int *)&mutex->__mlibc_state, expected, &timeout);

					if (e == ETIMEDOUT)
						return e;
				} else {
					e = mlibc::sys_futex_wait((int *)&mutex->__mlibc_state, expected, nullptr);
				}

				// If the wait returns EAGAIN, that means that the mutex_waiters_bit was just unset by
				// some other thread. In this case, we should loop back around.
				// Also do so in case of a signal being caught.
				if (e && e != EAGAIN && e != EINTR)
					mlibc::panicLogger() << "sys_futex_wait() failed with error code " << e << frg::endlog;

				// Opportunistically try to take the lock after we wake up.
				expected = 0;
			}else{
				// Otherwise we have to set the waiters flag first.
				unsigned int desired = expected | mutex_waiters_bit;
				if(__atomic_compare_exchange_n((int *)&mutex->__mlibc_state,
						reinterpret_cast<int*>(&expected), desired, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
					expected = desired;
			}
		}
	}
}

int thread_mutex_lock(struct __mlibc_mutex *mutex) {
	return thread_mutex_timedlock(mutex, nullptr, 0);
}

int thread_mutex_trylock(struct __mlibc_mutex *mutex) {
	mutex = resolve_mutex_ptr(mutex, "thread_mutex_trylock");
	unsigned int this_tid = mlibc::this_tid();
	unsigned int expected = __atomic_load_n(&mutex->__mlibc_state, __ATOMIC_RELAXED);
	if(!expected) {
		// Try to take the mutex here.
		if(__atomic_compare_exchange_n(&mutex->__mlibc_state,
						&expected, this_tid, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE)) {
			__ensure(!mutex->__mlibc_recursion);
			mutex->__mlibc_recursion = 1;
			return 0;
		}
	} else {
		// If this (recursive) mutex is already owned by us, increment the recursion level.
		if((expected & mutex_owner_mask) == this_tid) {
			if(!(mutex->__mlibc_flags & mutexRecursive)) {
				return EBUSY;
			}
			++mutex->__mlibc_recursion;
			return 0;
		}
	}

	return EBUSY;
}

int thread_mutex_unlock(struct __mlibc_mutex *mutex) {
	mutex = resolve_mutex_ptr(mutex, "thread_mutex_unlock");
	// Decrement the recursion level and unlock if we hit zero.
	__ensure(mutex->__mlibc_recursion);
	if(--mutex->__mlibc_recursion)
		return 0;

	auto flags = mutex->__mlibc_flags;

	// Reset the mutex to the unlocked state.
	auto state = __atomic_exchange_n(&mutex->__mlibc_state, 0, __ATOMIC_RELEASE);

	// After this point the mutex is unlocked, and therefore we cannot access its contents as it
	// may have been destroyed by another thread.

	unsigned int this_tid = mlibc::this_tid();
	if ((flags & mutexErrorCheck) && (state & mutex_owner_mask) != this_tid)
		return EPERM;

	if ((flags & mutexErrorCheck) && !(state & mutex_owner_mask))
		return EINVAL;

	__ensure((state & mutex_owner_mask) == this_tid);

	if(state & mutex_waiters_bit) {
		// Wake the futex if there were waiters. Since the mutex might not exist at this location
		// anymore, we must conservatively ignore EACCES and EINVAL which may occur as a result.
		int e = mlibc::sys_futex_wake((int *)&mutex->__mlibc_state);
		__ensure(e >= 0 || e == EACCES || e == EINVAL);
	}

	return 0;
}

int thread_mutexattr_init(struct __mlibc_mutexattr *attr) {
	attr->__mlibc_type = __MLIBC_THREAD_MUTEX_DEFAULT;
	attr->__mlibc_robust = __MLIBC_THREAD_MUTEX_STALLED;
	attr->__mlibc_pshared = __MLIBC_THREAD_PROCESS_PRIVATE;
	attr->__mlibc_protocol = __MLIBC_THREAD_PRIO_NONE;
	return 0;
}

int thread_mutexattr_destroy(struct __mlibc_mutexattr *attr) {
	memset(attr, 0, sizeof(*attr));
	return 0;
}

int thread_mutexattr_gettype(const struct __mlibc_mutexattr *__restrict attr, int *__restrict type) {
	*type = attr->__mlibc_type;
	return 0;
}

int thread_mutexattr_settype(struct __mlibc_mutexattr *attr, int type) {
	if (type != __MLIBC_THREAD_MUTEX_NORMAL && type != __MLIBC_THREAD_MUTEX_ERRORCHECK
			&& type != __MLIBC_THREAD_MUTEX_RECURSIVE)
		return EINVAL;

	attr->__mlibc_type = type;
	return 0;
}

int thread_cond_init(struct __mlibc_cond *__restrict cond, const struct __mlibc_condattr *__restrict attr) {
	auto clock = attr ? attr->__mlibc_clock : CLOCK_REALTIME;
	auto pshared = attr ? attr->__mlibc_pshared : __MLIBC_THREAD_PROCESS_PRIVATE;

	cond->__mlibc_clock = clock;
	cond->__mlibc_flags = pshared;

	__atomic_store_n(&cond->__mlibc_seq, 1, __ATOMIC_RELAXED);

	return 0;
}

int thread_cond_destroy(struct __mlibc_cond *) {
	return 0;
}

int thread_cond_signal(struct __mlibc_cond *cond) {
	__atomic_fetch_add(&cond->__mlibc_seq, 1, __ATOMIC_RELEASE);
	if(int e = mlibc::sys_futex_wake((int *)&cond->__mlibc_seq, 1); e)
		__ensure(!"sys_futex_wake() failed");

	return 0;
}

int thread_cond_broadcast(struct __mlibc_cond *cond) {
	__atomic_fetch_add(&cond->__mlibc_seq, 1, __ATOMIC_RELEASE);
	if(int e = mlibc::sys_futex_wake((int *)&cond->__mlibc_seq, INT_MAX); e)
		__ensure(!"sys_futex_wake() failed");

	return 0;
}

int thread_cond_timedwait(struct __mlibc_cond *__restrict cond, __mlibc_mutex *__restrict mutex,
		const struct timespec *__restrict abstime, clockid_t clockid) {
	// TODO: pshared isn't supported yet.
	__ensure(cond->__mlibc_flags == 0);

	constexpr long nanos_per_second = 1'000'000'000;
	if (abstime && (abstime->tv_nsec < 0 || abstime->tv_nsec >= nanos_per_second))
		return EINVAL;

	auto seq = __atomic_load_n(&cond->__mlibc_seq, __ATOMIC_ACQUIRE);

	// TODO: handle locking errors and cancellation properly.
	while (true) {
		if (thread_mutex_unlock(mutex))
			__ensure(!"Failed to unlock the mutex");

		int e;
		if (abstime) {
			// Adjust for the fact that sys_futex_wait accepts a *timeout*, but
			// pthread_cond_timedwait accepts an *absolute time*.
			struct timespec timeout;
			if (!mlibc::time_absolute_to_relative(clockid, abstime, &timeout)) {
				if (thread_mutex_lock(mutex))
					__ensure(!"Failed to lock the mutex");
				return EINVAL;
			} else if (timeout.tv_sec == 0 && timeout.tv_nsec == 0) {
				if (thread_mutex_lock(mutex))
					__ensure(!"Failed to lock the mutex");
				return ETIMEDOUT;
			}

			e = mlibc::sys_futex_wait((int *)&cond->__mlibc_seq, seq, &timeout);
		} else {
			e = mlibc::sys_futex_wait((int *)&cond->__mlibc_seq, seq, nullptr);
		}

		if (thread_mutex_lock(mutex))
			__ensure(!"Failed to lock the mutex");

		// There are four cases to handle:
		//   1. e == 0: this indicates a (potentially spurious) wakeup. The value of
		//      seq *must* be checked to distinguish these two cases.
		//   2. e == EAGAIN: this indicates that the value of seq changed before we
		//      went to sleep. We don't need to check seq in this case.
		//   3. e == EINTR: a signal was delivered. The man page allows us to choose
		//      whether to go to sleep again or to return 0, but we do the former
		//      to match other libcs.
		//   4. e == ETIMEDOUT: this should only happen if abstime is set.
		if (e == 0) {
			auto cur_seq = __atomic_load_n(&cond->__mlibc_seq, __ATOMIC_ACQUIRE);
			if (cur_seq > seq)
				return 0;
		} else if (e == EAGAIN) {
			// EAGAIN means the futex value didn't match expected when we tried
			// to sleep — either the cond was signaled before we slept (seq
			// already advanced, return 0) or a spurious kernel EAGAIN (e.g.
			// old 2-arg ABI left a garbage val in rdx). In the spurious case
			// seq hasn't changed, so we retry instead of asserting.
			if (__atomic_load_n(&cond->__mlibc_seq, __ATOMIC_ACQUIRE) > seq)
				return 0;
			continue;
		} else if (e == EINTR) {
			continue;
		} else if (e == ETIMEDOUT) {
			__ensure(abstime);
			return ETIMEDOUT;
		} else {
			mlibc::panicLogger() << "sys_futex_wait() failed with error " << e << frg::endlog;
		}
	}
}

int thread_key_create(__mlibc_uintptr *out, void (*destructor)(void *)) {
	auto g = frg::guard(&key_mutex_);

	__mlibc_uintptr key = PTHREAD_KEYS_MAX;
	for (size_t i = 0; i < PTHREAD_KEYS_MAX; i++) {
		if (!key_globals_[i].in_use) {
			key = i;
			break;
		}
	}

	if (key == PTHREAD_KEYS_MAX)
		return EAGAIN;

	key_globals_[key].in_use = true;
	key_globals_[key].dtor = destructor;

	*out = key;

	return 0;
}

int thread_key_delete(__mlibc_uintptr key) {
	auto g = frg::guard(&key_mutex_);

	if (key >= PTHREAD_KEYS_MAX || !key_globals_[key].in_use)
		return EINVAL;

	key_globals_[key].in_use = false;
	key_globals_[key].dtor = nullptr;
	key_globals_[key].generation++;

	return 0;
}

void *thread_key_get(__mlibc_uintptr key) {
	auto self = mlibc::get_current_tcb();
	if (!self || !self->localKeys)
		return nullptr;
	auto g = frg::guard(&key_mutex_);

	if (key >= PTHREAD_KEYS_MAX || !key_globals_[key].in_use)
		return nullptr;

	if (key_globals_[key].generation > (*self->localKeys)[key].generation) {
		(*self->localKeys)[key].value = nullptr;
		(*self->localKeys)[key].generation = key_globals_[key].generation;
	}

	return (*self->localKeys)[key].value;
}

int thread_key_set(__mlibc_uintptr key, const void *value) {
	auto self = mlibc::get_current_tcb();
	if (!self || !self->localKeys)
		return EINVAL;
	auto g = frg::guard(&key_mutex_);

	if (key >= PTHREAD_KEYS_MAX || !key_globals_[key].in_use)
		return EINVAL;

	(*self->localKeys)[key].value = const_cast<void *>(value);
	(*self->localKeys)[key].generation = key_globals_[key].generation;

	return 0;
}

} // namespace mlibc

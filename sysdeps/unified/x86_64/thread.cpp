#include <bits/ensure.h>
#include <errno.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/tcb.hpp>
#include <mlibc/thread-entry.hpp>
#include <mlibc/debug.hpp>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

namespace mlibc {

// Keep default stack size moderate for constrained kernels.
static constexpr size_t default_stacksize = 0x200000;
static constexpr size_t page_size = 0x1000;

static inline size_t align_up(size_t value) {
	return (value + (page_size - 1)) & ~(page_size - 1);
}

int sys_prepare_stack(
    void **stack,
    void *entry,
    void *user_arg,
    void *tcb,
    size_t *stack_size,
    size_t *guard_size,
    void **stack_base
) {
	if (!*stack_size)
		*stack_size = default_stacksize;
	*stack_size = align_up(*stack_size);

	size_t effective_guard = align_up(*guard_size);

	if (*stack) {
		*stack_base = *stack;
		*guard_size = 0;
	} else {
		size_t map_size = *stack_size + effective_guard;
		*stack_base =
		    mmap(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (*stack_base == MAP_FAILED) {
			return errno;
		}
		if (effective_guard) {
			if (mprotect(*stack_base, effective_guard, PROT_NONE)) {
				int e = errno;
				munmap(*stack_base, map_size);
				*stack_base = nullptr;
				return e;
			}
		}
		*guard_size = effective_guard;
	}

	uintptr_t *sp =
	    reinterpret_cast<uintptr_t *>(reinterpret_cast<uintptr_t>(*stack_base) + *guard_size + *stack_size);

	*--sp = reinterpret_cast<uintptr_t>(tcb);
	*--sp = reinterpret_cast<uintptr_t>(user_arg);
	*--sp = reinterpret_cast<uintptr_t>(entry);
	*stack = reinterpret_cast<void *>(sp);
	return 0;
}

} // namespace mlibc

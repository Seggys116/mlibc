
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <bits/ensure.h>

#include <mlibc-config.h>
#include <mlibc/debug.hpp>
#include <mlibc/posix-sysdeps.hpp>

#if __has_include(<unified/syscall.h>)
#define UNIFIED_NO_SYSCALL_MACRO
#include <unified/syscall.h>
#undef UNIFIED_NO_SYSCALL_MACRO
#define MLIBC_HAS_UNIFIED_MINCORE_FALLBACK 1
#endif

namespace {
	static inline bool mincore_fallback_syscall(void *addr, size_t length,
			unsigned char *vec, int *out_errno) {
#if defined(SYS_mincore)
		long ret = _syscall(SYS_mincore, reinterpret_cast<uintptr_t>(addr),
				length, reinterpret_cast<uintptr_t>(vec));
#elif defined(SYS_MINCORE)
		long ret = _syscall(SYS_MINCORE, reinterpret_cast<uintptr_t>(addr),
				length, reinterpret_cast<uintptr_t>(vec));
#elif defined(__NR_mincore)
		long ret = _syscall(__NR_mincore, reinterpret_cast<uintptr_t>(addr),
				length, reinterpret_cast<uintptr_t>(vec));
#else
		(void)addr;
		(void)length;
		(void)vec;
		if(out_errno)
			*out_errno = ENOSYS;
		return false;
#endif

		if(ret < 0) {
			if(out_errno)
				*out_errno = static_cast<int>(-ret);
			return false;
		}
		return true;
	}
} // namespace

int mprotect(void *pointer, size_t size, int prot) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_vm_protect, -1);
	if(int e = mlibc::sys_vm_protect(pointer, size, prot); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int mlock(const void *addr, size_t len) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_mlock, -1);
	if(int e = mlibc::sys_mlock(addr, len); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int mlockall(int flags) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_mlockall, -1);
	if(int e = mlibc::sys_mlockall(flags); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int munlock(const void *addr, size_t len) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_munlock, -1);
	if(int e = mlibc::sys_munlock(addr, len); e) {
		errno = e;
		return -1;
	}
	return 0;
}

int munlockall(void) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_munlockall, -1);
	if(int e = mlibc::sys_munlockall(); e) {
		errno = e;
		return -1;
	}
	return 0;
}


int posix_madvise(void *addr, size_t length, int advice) {
	if(!mlibc::sys_posix_madvise) {
		MLIBC_MISSING_SYSDEP();
		return ENOSYS;
	}
	return mlibc::sys_posix_madvise(addr, length, advice);
}

int msync(void *addr, size_t length, int flags) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_msync, -1);
	if(int e = mlibc::sys_msync(addr, length, flags); e) {
		errno = e;
		return -1;
	}
	return 0;
}

void *mmap(void *hint, size_t size, int prot, int flags, int fd, off_t offset) {
	void *window;
	if(int e = mlibc::sys_vm_map(hint, size, prot, flags, fd, offset, &window); e) {
		errno = e;
		return (void *)-1;
	}
	return window;
}

#if __MLIBC_LINUX_OPTION
[[gnu::alias("mmap")]] void *mmap64(void *hint, size_t size, int prot, int flags, int fd, off64_t offset);
#endif /* !__MLIBC_LINUX_OPTION */

int munmap(void *pointer, size_t size) {
	if(int e = mlibc::sys_vm_unmap(pointer, size); e) {
		errno = e;
		return -1;
	}
	return 0;
}

// The implementation of shm_open and shm_unlink is taken from musl.
namespace {
	char *shm_mapname(const char *name, char *buf) {
		char *p;
		while(*name == '/')
			name++;
		if(*(p = strchrnul(name, '/')) || p == name ||
			(p - name <= 2 && name[0] == '.' && p[-1] == '.')) {
			errno = EINVAL;
			return nullptr;
		}
		if(p - name > NAME_MAX) {
			errno = ENAMETOOLONG;
			return nullptr;
		}
		memcpy(buf, "/dev/shm/", 9);
		memcpy(buf + 9, name, p - name + 1);
		return buf;
	}
} // namespace

int shm_open(const char *name, int flags, mode_t mode) {
	int cs;
	char buf[NAME_MAX + 10];
	if(!(name = shm_mapname(name, buf)))
		return -1;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	int fd = open(name, flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, mode);
	pthread_setcancelstate(cs, nullptr);
	return fd;
}

int shm_unlink(const char *name) {
	char buf[NAME_MAX + 10];
	if(!(name = shm_mapname(name, buf)))
		return -1;
	return unlink(name);
}

#if __MLIBC_LINUX_OPTION
void *mremap(void *pointer, size_t size, size_t new_size, int flags, ...) {
	void *window;
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_vm_remap, (void *)-1);
	if(int e = mlibc::sys_vm_remap(pointer, size, new_size, flags, &window); e) {
		errno = e;
		return (void *)-1;
	}
	return window;
}

int remap_file_pages(void *, size_t, int, size_t, int) {
	__ensure(!"Not implemented");
	__builtin_unreachable();
}

int memfd_create(const char *name, unsigned int flags) {
	int ret = -1;

	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_memfd_create, -1);
	if(int e = mlibc::sys_memfd_create(name, flags, &ret)) {
		errno = e;
		return -1;
	}

	return ret;
}

int madvise(void *addr, size_t length, int advice) {
	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_madvise, -1);
	if(int e = mlibc::sys_madvise(addr, length, advice)) {
		errno = e;
		return -1;
	}

	return 0;
}

int mincore(void *addr, size_t length, unsigned char *vec) {
	if(!mlibc::sys_mincore) {
		int sys_errno = 0;
		if(mincore_fallback_syscall(addr, length, vec, &sys_errno))
			return 0;
		if(sys_errno != 0) {
			errno = sys_errno;
			return -1;
		}
		errno = ENOSYS;
		return -1;
	}

	if(int e = mlibc::sys_mincore(addr, length, vec); e) {
		errno = e;
		return -1;
	}
	return 0;
}
#endif /* __MLIBC_LINUX_OPTION */

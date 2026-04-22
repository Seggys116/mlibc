#include <mlibc/allocator.hpp>
#include <mlibc/linux-sysdeps.hpp>
#include <ifaddrs.h>
#include <errno.h>

int getifaddrs(struct ifaddrs **ifap) {
	if(!ifap) {
		errno = EFAULT;
		return -1;
	}

	if(!mlibc::sys_getifaddrs) {
		// Some userland tools treat missing interface enumeration as optional.
		// Return an empty list rather than tripping the ensure path.
		*ifap = nullptr;
		return 0;
	}

	auto sysdep = mlibc::sys_getifaddrs;
	if(int e = sysdep(ifap); e) {
		errno = e;
		return -1;
	}

	return 0;
}

void freeifaddrs(struct ifaddrs *ifa) {
	while (ifa != nullptr) {
		ifaddrs *current = ifa;
		ifa = ifa->ifa_next;
		getAllocator().free(current);
	}
}

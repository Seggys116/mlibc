
#include <string.h>
#include <sys/utsname.h>
#include <errno.h>

#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <internal-config.h>
#include <mlibc/posix-sysdeps.hpp>

namespace {

struct legacy_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
};

static void copy_legacy_utsname(legacy_utsname *dst, const struct utsname *src) {
	memcpy(dst->sysname, src->sysname, sizeof(dst->sysname));
	memcpy(dst->nodename, src->nodename, sizeof(dst->nodename));
	memcpy(dst->release, src->release, sizeof(dst->release));
	memcpy(dst->version, src->version, sizeof(dst->version));
	memcpy(dst->machine, src->machine, sizeof(dst->machine));
}

} // namespace

int uname(struct utsname *p) {
	if (p == nullptr) {
		errno = EFAULT;
		return -1;
	}

	MLIBC_CHECK_OR_ENOSYS(mlibc::sys_uname, -1);
	struct utsname kernel_uts = {};
	if(int e = mlibc::sys_uname(&kernel_uts); e) {
		errno = e;
		return -1;
	}

	/*
	 * Older binaries still pass the pre-domainname Linux layout here. Copy only
	 * the stable five-field prefix so uname() stays compatible across both ABIs.
	 */
	copy_legacy_utsname(reinterpret_cast<legacy_utsname *>(p), &kernel_uts);
	return 0;
}

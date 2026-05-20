#include <abi-bits/errno.h>
#include <abi-bits/fcntl.h>
#include <abi-bits/stat.h>
#include <bits/ensure.h>
#include <mlibc/ansi-sysdeps.hpp>
#include <mlibc/stdlib.hpp>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

namespace [[gnu::visibility("hidden")]] mlibc {
[[gnu::weak]] int sys_getentropy(void *buffer, size_t length);
}

namespace {

constexpr char tempnameAlphabet[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

uint64_t mixTempnameSeed(uint64_t value) {
	value += 0x9E3779B97F4A7C15ull;
	value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
	value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
	return value ^ (value >> 31);
}

uint64_t nextTempnameSeed(size_t attempt) {
	static uint64_t counter;
	uint64_t sequence = __atomic_add_fetch(&counter, 1ULL, __ATOMIC_ACQ_REL);
	uint64_t seed = sequence ^ (attempt * 0xD1B54A32D192ED03ull);

	uint64_t entropy = 0;
	if(mlibc::sys_getentropy && !mlibc::sys_getentropy(&entropy, sizeof(entropy)))
		seed ^= entropy;

	time_t secs = 0;
	long nanos = 0;
	if(!mlibc::sys_clock_get(CLOCK_REALTIME, &secs, &nanos))
		seed ^= (static_cast<uint64_t>(secs) << 32) ^ static_cast<uint64_t>(nanos);

	if(mlibc::sys_getpid)
		seed ^= static_cast<uint64_t>(mlibc::sys_getpid()) << 17;

	seed ^= reinterpret_cast<uintptr_t>(&counter);
	return mixTempnameSeed(seed);
}

void fillTempnameSuffix(char *suffix, uint64_t seed) {
	for(size_t i = 0; i < 6; i++) {
		suffix[i] = tempnameAlphabet[seed % (sizeof(tempnameAlphabet) - 1)];
		seed /= (sizeof(tempnameAlphabet) - 1);
	}
}

} // namespace

namespace mlibc {

int mkostemps(char *pattern, int suffixlen, int flags, int *fd) {
	auto n = strlen(pattern);
	if(n < (6 + static_cast<size_t>(suffixlen))) {
		return EINVAL;
	}

	flags &= ~O_WRONLY;

	for(size_t i = 0; i < 6; i++) {
		if(pattern[n - (6 + suffixlen) + i] == 'X')
			continue;
		return EINVAL;
	}

	for(size_t i = 0; i < 999999; i++) {
		char sfx = pattern[n - suffixlen];
		fillTempnameSuffix(pattern + (n - (6 + suffixlen)), nextTempnameSeed(i));
		pattern[n - suffixlen] = sfx;

		if(int e = mlibc::sys_open(pattern, O_RDWR | O_CREAT | O_EXCL | flags, S_IRUSR | S_IWUSR, fd); !e) {
			return 0;
		}else if(e != EEXIST) {
			return e;
		}
	}

	return EEXIST;
}

} // namespace mlibc

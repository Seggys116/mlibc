#include <stdlib.h>
#include <string.h>
#include <atomic>
#include <mlibc/global-config.hpp>

namespace mlibc {

namespace {

// 0 = not initialized, 1 = currently constructing, 2 = ready.
std::atomic<int> globalConfigState{0};

}

struct GlobalConfigGuard {
	GlobalConfigGuard();
};

GlobalConfigGuard guard;

GlobalConfigGuard::GlobalConfigGuard() {
	// Force the config to be created during initialization of libc.so.
	mlibc::globalConfig();
}

static bool envEnabled(const char *env) {
	auto value = getenv(env);
	return value && *value && *value != '0';
}

bool globalConfigIsInitializing() {
	return globalConfigState.load(std::memory_order_acquire) == 1;
}

bool globalConfigIsReady() {
	return globalConfigState.load(std::memory_order_acquire) == 2;
}

GlobalConfig::GlobalConfig() {
	globalConfigState.store(1, std::memory_order_release);

	debugMalloc = envEnabled("MLIBC_DEBUG_MALLOC");
	debugPrintf = envEnabled("MLIBC_DEBUG_PRINTF");
	debugLocale = envEnabled("MLIBC_DEBUG_LOCALE");
	debugPthreadTrace = envEnabled("MLIBC_DEBUG_PTHREAD_TRACE");
	debugPathResolution = envEnabled("MLIBC_DEBUG_PATH_RESOLUTION");
	debugMonetaryLengths = envEnabled("MLIBC_DEBUG_MONETARY_LENGTHS");

	globalConfigState.store(2, std::memory_order_release);
}

} // namespace mlibc

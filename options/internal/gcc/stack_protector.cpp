#include <stdint.h>
#include <string.h>
#if !defined(MLIBC_BUILDING_RTLD)
#include <dlfcn.h>
#endif
#include <mlibc/stack_protector.hpp>
#include <mlibc/internal-sysdeps.hpp>

extern uintptr_t __stack_chk_guard;

namespace {

struct StackFrame {
	StackFrame *next;
	void *ret_addr;
};

static void appendLiteral(char *dst, size_t cap, size_t &len, const char *text) {
	while(text && *text && len + 1 < cap) {
		dst[len++] = *text++;
	}
}

static void appendUnsigned(char *dst, size_t cap, size_t &len, size_t value) {
	char rev[32];
	size_t n = 0;
	do {
		rev[n++] = '0' + (value % 10);
		value /= 10;
	} while(value && n < sizeof(rev));
	while(n && len + 1 < cap) {
		dst[len++] = rev[--n];
	}
}

static void appendHex(char *dst, size_t cap, size_t &len, uintptr_t value) {
	static const char *digits = "0123456789abcdef";
	if(len + 2 >= cap)
		return;
	dst[len++] = '0';
	dst[len++] = 'x';

	bool started = false;
	for(int i = static_cast<int>(sizeof(uintptr_t) * 2) - 1; i >= 0; i--) {
		unsigned nibble = static_cast<unsigned>((value >> (i * 4)) & 0xFu);
		if(!started) {
			if(nibble == 0 && i != 0)
				continue;
			started = true;
		}
		if(len + 1 >= cap)
			return;
		dst[len++] = digits[nibble];
	}
}

static void logAddress(size_t index, void *ret) {
	char line[128];
	size_t len = 0;
	appendLiteral(line, sizeof(line), len, "  #");
	appendUnsigned(line, sizeof(line), len, index);
	appendLiteral(line, sizeof(line), len, " ");
	appendHex(line, sizeof(line), len, reinterpret_cast<uintptr_t>(ret));
	line[len] = '\0';
	mlibc::sys_libc_log(line);
}

static void logGuardDiagnostics(uintptr_t callerRet) {
	char line[320];
	size_t len = 0;

	uintptr_t rsp = 0;
	uintptr_t rbp = 0;
	asm volatile ("mov %%rsp, %0" : "=r"(rsp));
	asm volatile ("mov %%rbp, %0" : "=r"(rbp));

	uintptr_t fs0 = 0;
	uintptr_t fsCanary = 0;
#if defined(__x86_64__)
	asm volatile ("movq %%fs:0, %0" : "=r"(fs0));
	asm volatile ("movq %%fs:0x28, %0" : "=r"(fsCanary));
#endif

	appendLiteral(line, sizeof(line), len, "stackchk: caller_ret=");
	appendHex(line, sizeof(line), len, callerRet);
	appendLiteral(line, sizeof(line), len, " rsp=");
	appendHex(line, sizeof(line), len, rsp);
	appendLiteral(line, sizeof(line), len, " rbp=");
	appendHex(line, sizeof(line), len, rbp);
	appendLiteral(line, sizeof(line), len, " guard@=");
	appendHex(line, sizeof(line), len, reinterpret_cast<uintptr_t>(&__stack_chk_guard));
	appendLiteral(line, sizeof(line), len, " guard=");
	appendHex(line, sizeof(line), len, __stack_chk_guard);
#if defined(__x86_64__)
	appendLiteral(line, sizeof(line), len, " fs:0=");
	appendHex(line, sizeof(line), len, fs0);
	appendLiteral(line, sizeof(line), len, " fs:0x28=");
	appendHex(line, sizeof(line), len, fsCanary);
#endif
	line[len] = '\0';
	mlibc::sys_libc_log(line);
}

static void logResolvedAddress(const char *tag, uintptr_t addr) {
#if defined(MLIBC_BUILDING_RTLD)
	(void)tag;
	(void)addr;
	return;
#else
	Dl_info info = {};
	if(!dladdr(reinterpret_cast<void *>(addr), &info)) {
		char line[160];
		size_t len = 0;
		appendLiteral(line, sizeof(line), len, "stackchk: ");
		appendLiteral(line, sizeof(line), len, tag);
		appendLiteral(line, sizeof(line), len, " unresolved addr=");
		appendHex(line, sizeof(line), len, addr);
		line[len] = '\0';
		mlibc::sys_libc_log(line);
		return;
	}

	char line[640];
	size_t len = 0;
	appendLiteral(line, sizeof(line), len, "stackchk: ");
	appendLiteral(line, sizeof(line), len, tag);
	appendLiteral(line, sizeof(line), len, " module=");
	appendLiteral(line, sizeof(line), len, info.dli_fname ? info.dli_fname : "<null>");
	appendLiteral(line, sizeof(line), len, " base=");
	auto base = reinterpret_cast<uintptr_t>(info.dli_fbase);
	appendHex(line, sizeof(line), len, base);
	appendLiteral(line, sizeof(line), len, " +");
	appendHex(line, sizeof(line), len, (addr >= base) ? (addr - base) : 0);
	if(info.dli_sname) {
		appendLiteral(line, sizeof(line), len, " symbol=");
		appendLiteral(line, sizeof(line), len, info.dli_sname);
		auto sym = reinterpret_cast<uintptr_t>(info.dli_saddr);
		appendLiteral(line, sizeof(line), len, " +");
		appendHex(line, sizeof(line), len, (addr >= sym) ? (addr - sym) : 0);
	}
	line[len] = '\0';
	mlibc::sys_libc_log(line);
#endif
}

static void dumpStackTrace() {
#if defined(__x86_64__)
	constexpr size_t kMaxFrames = 32;
	constexpr uintptr_t kMaxFrameGap = 1 << 20; // 1 MiB sanity cap.

	auto frame = reinterpret_cast<StackFrame *>(__builtin_frame_address(0));
	mlibc::sys_libc_log("Backtrace (raw return addresses):");
	for(size_t i = 0; i < kMaxFrames && frame; i++) {
		void *ret = __builtin_extract_return_addr(frame->ret_addr);
		if(!ret)
			break;

		logAddress(i, ret);

		auto next = frame->next;
		if(!next)
			break;

		uintptr_t current_addr = reinterpret_cast<uintptr_t>(frame);
		uintptr_t next_addr = reinterpret_cast<uintptr_t>(next);
		// x86_64 stacks grow downward; caller frames should have larger addresses.
		if(next_addr <= current_addr)
			break;
		if((next_addr - current_addr) > kMaxFrameGap)
			break;
		if(next_addr & (alignof(void *) - 1))
			break;

		frame = next;
	}
#else
	mlibc::sys_libc_log("Backtrace unavailable on this architecture.");
#endif
}

} // namespace

uintptr_t __stack_chk_guard = 0;

namespace mlibc {

void initStackGuard(void *entropy) {
	if(entropy != nullptr) {
		memcpy(&__stack_chk_guard, entropy, sizeof(__stack_chk_guard));
	} else {
		// If no entropy is available, set it to the terminator canary
		__stack_chk_guard = 0;
		__stack_chk_guard |= ('\n' << 16);
		__stack_chk_guard |= (255 << 24);
	}
}

} // namespace mlibc

extern "C" [[noreturn]] void __stack_chk_fail() {
	mlibc::sys_libc_log("Stack smashing detected!");
	uintptr_t callerRet = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
	logGuardDiagnostics(callerRet);
	logResolvedAddress("caller_ret", callerRet);
	dumpStackTrace();
	mlibc::sys_libc_panic();
	__builtin_unreachable();
}

extern "C" [[noreturn, gnu::visibility("hidden")]] void __stack_chk_fail_local() {
	__stack_chk_fail();
};

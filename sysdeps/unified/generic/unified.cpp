#define MLIBC_UNIFIED_IMPLEMENTING_ABI_OVERRIDES

#include <unified/syscall.h>
#include <stddef.h>
#include <stdarg.h>
#include <bits/ensure.h>
#include <abi-bits/pid_t.h>
#include <mlibc/debug.hpp>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/thread-entry.hpp>
#include <errno.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/prctl.h>
#include <time.h>
#include <signal.h>
#include <sched.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <limits.h>
#include <mlibc/threads.hpp>

namespace mlibc{

extern "C" void __mlibc_raw_clone_entry();

static constexpr int kFutexWait = 0;
static constexpr int kFutexWake = 1;
static constexpr int kFutexWakeOne = 1;
static constexpr int kFutexWakeAll = INT_MAX;
static constexpr int kFutexPrivateFlag = 128;
static constexpr int kArchSetFs = 0x1002;

int Sysdeps<FutexTid>::operator()(){
	constexpr int kMaxFutexTid = (1 << 30) - 1;
	long ret = syscall(SYS_GETTID);
	if(ret > 0 && ret <= kMaxFutexTid)
		return static_cast<int>(ret);

	// Never propagate negative/oversized TIDs into mutex owner bits.
	// Keep this path RTLD-safe: get_current_tcb() is not available in all
	// build variants of this sysdeps TU.
	return 0;
}

int Sysdeps<FutexWait>::operator()(int *pointer, int expected, const struct timespec *time){
	// Linux-style futex op:
	// futex(uaddr, op=FUTEX_WAIT, val=expected, timeout, uaddr2, val3)
	// WAIT uses the Linux-compatible multiplexed futex ABI.
	long ret = syscall(SYS_FUTEX_WAIT, pointer, kFutexWait | kFutexPrivateFlag, expected, time, 0, 0);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<FutexWake>::operator()(int *pointer, bool all) {
	int count = all ? kFutexWakeAll : kFutexWakeOne;

	long ret = syscall(SYS_FUTEX_WAKE, pointer, count);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<TcbSet>::operator()(void* pointer){
	// x86_64 local-exec TLS sequences first load the canonical self-pointer
	// from %fs:0 and then apply the negative TLS offset. Re-establish that
	// slot every time we install a TCB so compiler-generated TLS accesses
	// cannot observe stale pre-switch contents.
#if defined(__x86_64__)
	auto tcb = reinterpret_cast<Tcb *>(pointer);
	tcb->selfPointer = tcb;
#endif

	// Set %fs base to point to the TCB itself (within mapped stack region)
	// This allows accessing TCB fields at positive offsets from %fs
	long ret = syscall(SYS_ARCH_PRCTL, kArchSetFs, (uintptr_t)pointer);
	if (ret < 0) {
		return -ret;
	}

#if defined(__x86_64__)
	asm volatile ("movq %0, %%fs:0" :: "r"(pointer) : "memory");
#endif
	return 0;
}

int Sysdeps<Tcflow>::operator()(int fd, int action) {
	// tcflow controls terminal flow control (suspend/resume I/O)
	// Use TCXONC ioctl command (0x540A)
	long ret = syscall(SYS_IOCTL, fd, 0x540A, action);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<VmMap>::operator()(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	size_t aligned_size = (size + 0xFFF) & ~static_cast<size_t>(0xFFF);
	long ret = syscall(SYS_MMAP, (uintptr_t)hint, aligned_size, prot, flags, fd, offset);
	if (ret < 0) {
		mlibc::infoLogger() << "mlibc: sys_vm_map failed"
				<< " errno=" << (-ret)
				<< " hint=" << hint
				<< " size=" << size
				<< " aligned_size=" << aligned_size
				<< " prot=0x" << frg::hex_fmt{static_cast<uintptr_t>(prot)}
				<< " flags=0x" << frg::hex_fmt{static_cast<uintptr_t>(flags)}
				<< " fd=" << fd
				<< " off=0x" << frg::hex_fmt{static_cast<uintptr_t>(offset)}
				<< frg::endlog;
		return -ret;
	}
	*window = reinterpret_cast<void *>(ret);
	return 0;
}

int Sysdeps<VmUnmap>::operator()(void* address, size_t size) {
	/* Round up size to page boundary - Linux munmap accepts any size */
	size_t aligned_size = (size + 0xFFF) & ~static_cast<size_t>(0xFFF);

	long ret = syscall(SYS_MUNMAP, (uintptr_t)address, aligned_size);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int
Sysdeps<VmProtect>::operator()(void *pointer, size_t size, int prot)
{
	long ret = syscall(SYS_MPROTECT, (uintptr_t)pointer, size, prot);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}


int Sysdeps<VmRemap>::operator()(void *pointer, size_t size, size_t new_size, void **window) {
	constexpr int flags = MREMAP_MAYMOVE;
	long ret = syscall(SYS_MREMAP, (uintptr_t)pointer, size, new_size, flags);
	if (ret < 0)
		return -ret;
	*window = (void *)ret;
	return 0;
}

int Sysdeps<Madvise>::operator()(void *pointer, size_t size, int advice) {
	long ret = syscall(SYS_MADVISE, (uintptr_t)pointer, size, advice);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Mincore>::operator()(void *addr, size_t length, unsigned char *vec) {
	long ret = syscall(SYS_MINCORE, (uintptr_t)addr, length, (uintptr_t)vec);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Msync>::operator()(void *addr, size_t length, int flags) {
	long ret = syscall(SYS_MSYNC, (uintptr_t)addr, length, flags);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<AnonAllocate>::operator()(size_t size, void **pointer) {
	return Sysdeps<VmMap>::operator()(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0, pointer);
}

int Sysdeps<AnonFree>::operator()(void *pointer, size_t size) {
	return Sysdeps<VmUnmap>::operator()(pointer, size);
}

#if __MLIBC_BSD_OPTION
int Sysdeps<Brk>::operator()(void **out) {
	long ret = syscall(SYS_BRK, 0);
	if(ret < 0)
		return -ret;

	*out = reinterpret_cast<void *>(ret);
	return 0;
}
#endif

void Sysdeps<LibcPanic>::operator()(){
	Sysdeps<LibcLog>::operator()("libc panic!");
	// Match abort() semantics:
	// 1) Unblock and raise SIGABRT.
	// 2) If a handler returns or SIGABRT was ignored, reset to default and raise again.
	// 3) If still alive, fall back to _Exit(127).
	pid_t pid = syscall(SYS_GETPID);
	if (pid > 0) {
		pid_t tid = syscall(SYS_GETTID);
		sigset_t set = {};
		set.__sig[(SIGABRT - 1) / (8 * sizeof(unsigned long))] =
		    1UL << ((SIGABRT - 1) % (8 * sizeof(unsigned long)));
		(void)syscall(SYS_SIGPROCMASK, SIG_UNBLOCK, (uintptr_t)&set, 0, sizeof(sigset_t));
		if (tid > 0)
			(void)syscall(SYS_TGKILL, pid, tid, SIGABRT);
		else
			(void)syscall(SYS_KILL, pid, SIGABRT);

		struct sigaction sa = {};
		sa.sa_handler = SIG_DFL;
		sa.sa_flags = 0;
		(void)syscall(SYS_SIGNAL_ACTION, SIGABRT, (uintptr_t)&sa, 0, sizeof(sigset_t));

		memset(&set, 0xff, sizeof(set));
		set.__sig[(SIGABRT - 1) / (8 * sizeof(unsigned long))] &=
		    ~(1UL << ((SIGABRT - 1) % (8 * sizeof(unsigned long))));
		(void)syscall(SYS_SIGPROCMASK, SIG_SETMASK, (uintptr_t)&set, 0, sizeof(sigset_t));
		if (tid > 0)
			(void)syscall(SYS_TGKILL, pid, tid, SIGABRT);
		else
			(void)syscall(SYS_KILL, pid, SIGABRT);
	}

	syscall(SYS_EXIT_GROUP, 127);
	__builtin_trap();
	for(;;);
}

void Sysdeps<LibcLog>::operator()(const char* msg){
	size_t n = 0;
	while (msg[n])
		n++;
	syscall(SYS_WRITE, 2, (uintptr_t)msg, n);
	char lf = '\n';
	syscall(SYS_WRITE, 2, (uintptr_t)&lf, 1);
}

int Sysdeps<GetHostname>::operator()(char *buffer, size_t bufsize) {
	if (!buffer) {
		return EFAULT;
	}

	if (!bufsize)
		return 0;

	struct utsname uts = {};
	if (Sysdeps<Uname>::operator()(&uts) == 0) {
		size_t i = 0;
		for (; i + 1 < bufsize && uts.nodename[i]; ++i)
			buffer[i] = uts.nodename[i];
		buffer[i] = '\0';
		return 0;
	}

	buffer[0] = '\0';
	return 0;
}

int Sysdeps<Uname>::operator()(struct utsname *buf) {
	long ret = syscall(SYS_UNAME, buf);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

#ifndef MLIBC_BUILDING_RTLD

void Sysdeps<Exit>::operator()(int status){
	syscall(SYS_EXIT_GROUP, status);

	__builtin_unreachable();
}

pid_t Sysdeps<GetPid>::operator()(){
	return syscall(SYS_GETPID);
}

pid_t Sysdeps<GetPpid>::operator()(){
	return syscall(SYS_GETPPID);
}

pid_t Sysdeps<GetTid>::operator()(){
	return syscall(SYS_GETTID);
}

int Sysdeps<ClockGet>::operator()(int clock, time_t *secs, long *nanos) {
	struct timespec ts;
	long ret = syscall(SYS_CLOCK_GETTIME, clock, &ts);
	if (ret < 0) {
		return -ret;
	}
	*secs = ts.tv_sec;
	*nanos = ts.tv_nsec;
	return 0;
}

int Sysdeps<ClockGetres>::operator()(int clock, time_t *secs, long *nanos) {
	struct timespec res;
	long ret = syscall(SYS_CLOCK_GETRES, clock, &res);
	if (ret < 0) {
		return -ret;
	}
	*secs = res.tv_sec;
	*nanos = res.tv_nsec;
	return 0;
}

int Sysdeps<GetCwd>::operator()(char *buffer, size_t size){
	long ret = syscall(SYS_GET_CWD, buffer, size);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Chdir>::operator()(const char *path){
	long ret = syscall(SYS_CHDIR, path);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Sleep>::operator()(time_t* sec, long* nanosec){
	struct timespec req = {};
	req.tv_sec = *sec;
	req.tv_nsec = *nanosec;
	long ret = syscall(SYS_NANO_SLEEP, &req, nullptr);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetItimer>::operator()(int which, const struct itimerval *new_value, struct itimerval *old_value) {
	long ret = syscall(SYS_SETITIMER, which, new_value, old_value);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<GetItimer>::operator()(int which, struct itimerval *curr_value) {
	long ret = syscall(SYS_GETITIMER, which, curr_value);
	if (ret < 0)
		return -ret;
	return 0;
}

uid_t Sysdeps<GetUid>::operator()(){
	return syscall(SYS_GETUID);
}

uid_t Sysdeps<GetEuid>::operator()(){
	return syscall(SYS_GETEUID);
}

int Sysdeps<SetUid>::operator()(uid_t uid){
	long ret = syscall(SYS_SETUID, uid);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<SetEuid>::operator()(uid_t euid){
	long ret = syscall(SYS_SETEUID, euid);
	if (ret < 0)
		return -ret;
	return 0;
}

gid_t Sysdeps<GetGid>::operator()(){
	return syscall(SYS_GETGID);
}

gid_t Sysdeps<GetEgid>::operator()(){
	return syscall(SYS_GETEGID);
}

int Sysdeps<SetPgid>::operator()(pid_t pid, pid_t pgid) {
	long ret = syscall(SYS_SETPGID, pid, pgid);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<GetPgid>::operator()(pid_t pid, pid_t *pgid) {
	long ret = pid ? syscall(SYS_GETPGID, pid) : syscall(SYS_GETPGRP);
	if (ret < 0)
		return -ret;
	*pgid = ret;
	return 0;
}

int Sysdeps<SetGid>::operator()(gid_t gid){
	long ret = syscall(SYS_SETGID, gid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetEgid>::operator()(gid_t egid){
	long ret = syscall(SYS_SETEGID, egid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

void Sysdeps<Yield>::operator()(){
	syscall(SYS_YIELD);
}

// Clone flags for pthread-style thread creation
#define CLONE_VM            0x00000100
#define CLONE_FS            0x00000200
#define CLONE_FILES         0x00000400
#define CLONE_SIGHAND       0x00000800
#define CLONE_THREAD        0x00010000
#define CLONE_SYSVSEM       0x00040000
#define CLONE_SETTLS        0x00080000
#define CLONE_PARENT_SETTID 0x00100000

int Sysdeps<Clone>::operator()(void *tcb, pid_t *tid_out, void *stack){
	//mlibc::infoLogger() << "mlibc: sys_clone entry tcb=" << (void*)tcb << " stack=" << (void*)stack << frg::endlog;
	// Follow Linux mlibc threading flags:
	// CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
	// CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID.
	// The generic pthread path publishes tcb->tid after Clone returns and
	// wakes that futex; join waits on tcb->didExit, not kernel CLEARTID.
	if (!tcb || !tid_out) {
		return EINVAL;
	}
	uint64_t flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	                 CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
	                 CLONE_PARENT_SETTID;

	//mlibc::infoLogger() << "mlibc: sys_clone syscall entry=" << (void*)__mlibc_start_thread << " stack=" << (void*)stack << " flags=0x" << flags << frg::endlog;

	// clone(entry, stack, flags, parent_tid, child_tid, tls)
	// entry is __mlibc_start_thread which pops actual entry/user_arg/tcb from stack
	long tid = syscall(SYS_CLONE, (uint64_t)__mlibc_start_thread, (uint64_t)stack,
	                   flags, (uint64_t)tid_out, 0, (uint64_t)tcb);

	if(tid < 0){
		return (int)(-tid);  // Return positive errno
	}
	if ((long)(pid_t)tid != tid) {
		return EOVERFLOW;
	}

	*tid_out = (pid_t)tid;

	return 0;
}

int sys_clone_linux(int (*fn)(void *), void *stack, int flags, void *arg,
		pid_t *parent_tid, void *tls, pid_t *child_tid, int *out) {
	if(!fn || !stack || !out)
		return EINVAL;

	uintptr_t sp = reinterpret_cast<uintptr_t>(stack);
	sp &= ~static_cast<uintptr_t>(0xF);

	auto *stack_words = reinterpret_cast<uintptr_t *>(sp);
	*--stack_words = static_cast<uintptr_t>(flags);
	*--stack_words = reinterpret_cast<uintptr_t>(arg);
	*--stack_words = reinterpret_cast<uintptr_t>(fn);

	long tid = syscall(SYS_CLONE,
	                   reinterpret_cast<uint64_t>(__mlibc_raw_clone_entry),
	                   reinterpret_cast<uint64_t>(stack_words),
	                   static_cast<uint64_t>(static_cast<uint32_t>(flags)),
	                   reinterpret_cast<uint64_t>(parent_tid),
	                   reinterpret_cast<uint64_t>(child_tid),
	                   reinterpret_cast<uint64_t>(tls),
	                   0);

	if(tid < 0)
		return static_cast<int>(-tid);
	if(static_cast<long>(static_cast<int>(tid)) != tid)
		return EOVERFLOW;

	*out = static_cast<int>(tid);
	return 0;
}

[[noreturn]] void Sysdeps<ThreadExit>::operator()(){
#if defined(__x86_64__)
	__asm__ volatile(
		"1:\n\t"
		"mov $60, %%rax\n\t"
		"xor %%edi, %%edi\n\t"
		"xor %%esi, %%esi\n\t"
		"xor %%edx, %%edx\n\t"
		"xor %%r10d, %%r10d\n\t"
		"xor %%r9d, %%r9d\n\t"
		"xor %%r8d, %%r8d\n\t"
		"int $0x69\n\t"
		"jmp 1b\n\t"
		:
		:
		: "rax", "rdi", "rsi", "rdx", "r10", "r9", "r8", "memory", "cc");
	__builtin_unreachable();
#else
	for(;;)
		syscall(SYS_EXIT_THREAD);
#endif
}

int Sysdeps<Waitpid>::operator()(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid){
	pid_t ret = ru
		? syscall(SYS_WAIT4, pid, status, flags, ru)
		: syscall(SYS_WAIT_PID, pid, status, flags);

	if(ret < 0){
		return -ret;
	}

	*ret_pid = ret;

	return 0;
}

int Sysdeps<Waitid>::operator()(idtype_t idtype, id_t id, siginfo_t *info, int options) {
	long ret = syscall(SYS_WAITID, idtype, id, info, options);
	if(ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<PidfdOpen>::operator()(pid_t pid, unsigned int flags, int *outfd) {
	long ret = syscall(SYS_PIDFD_OPEN, pid, flags);
	if(ret < 0)
		return -ret;
	*outfd = static_cast<int>(ret);
	return 0;
}

int Sysdeps<PidfdGetpid>::operator()(int fd, pid_t *outpid) {
	long ret = syscall(SYS_PIDFD_GETPID, fd);
	if(ret < 0)
		return -ret;
	*outpid = static_cast<pid_t>(ret);
	return 0;
}

int Sysdeps<PidfdSendSignal>::operator()(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
	long ret = syscall(SYS_PIDFD_SEND_SIGNAL, pidfd, sig, info, flags);
	if(ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<Fork>::operator()(pid_t *child){
	int retries = 0;
	while (true) {
		long ret = syscall(SYS_FORK, 0);
		int64_t sret = static_cast<int64_t>(ret);
		if (sret >= 0) {
			*child = static_cast<pid_t>(sret);
			return 0;
		}
		if (sret == -EAGAIN && retries < 10) {
			retries++;
			syscalln0(SYS_YIELD);
			continue;
		}
		return static_cast<int>(-sret);
	}
}

int Sysdeps<GetPriority>::operator()(int which, id_t who, int *value) {
	// Linux ABI: kernel returns (20 - nice), clamped to [1, 40]. Negative
	// result == -errno. mlibc translates back to raw nice for POSIX
	// getpriority() callers; they disambiguate the -1 sentinel by clearing
	// errno before the call.
	auto ret = syscalln3(SYS_GETPRIORITY, which, who, 0);
	int64_t sret = static_cast<int64_t>(ret);
	if (sret < 0) {
		return static_cast<int>(-sret);
	}
	if (value) *value = 20 - static_cast<int>(sret);
	return 0;
}

int Sysdeps<SetPriority>::operator()(int which, id_t who, int prio) {
	// Linux ABI: caller passes raw nice ([-20, 19]) directly; kernel clamps.
	// No translation needed.
	auto ret = syscalln3(SYS_SETPRIORITY, which, who, static_cast<uint64_t>(static_cast<int64_t>(prio)));
	int64_t sret = static_cast<int64_t>(ret);
	if (sret < 0) {
		return static_cast<int>(-sret);
	}
	return 0;
}

int Sysdeps<Execve>::operator()(const char *path, char *const argv[], char *const envp[]){
	long ret = syscall(SYS_EXECVE, path, argv, envp);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<GetEntropy>::operator()(void *buffer, size_t length){
	long ret = syscall(SYS_GETRANDOM, buffer, length, 0);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<GetRlimit>::operator()(int resource, struct rlimit *limit) {
	long ret = syscall(SYS_PRLIMIT64, 0, resource, 0, limit);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetRlimit>::operator()(int resource, const struct rlimit *limit) {
	long ret = syscall(SYS_PRLIMIT64, 0, resource, limit, 0);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<GetRusage>::operator()(int scope, struct rusage *usage) {
	long ret = syscall(SYS_GETRUSAGE, scope, usage);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_prctl_args(int option, unsigned long arg2, unsigned long arg3,
		unsigned long arg4, unsigned long arg5, int *out) {
	long ret = syscall(SYS_PRCTL, option, arg2, arg3, arg4, arg5);
	if (ret < 0) {
		return -ret;
	}
	*out = ret;
	return 0;
}

int Sysdeps<Prctl>::operator()(int option, va_list va, int *out) {
	unsigned long arg2 = 0;
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	switch(option) {
		case PR_SET_NAME:
		case PR_GET_NAME:
		case PR_SET_DUMPABLE:
		case PR_SET_CHILD_SUBREAPER:
		case PR_GET_CHILD_SUBREAPER:
			arg2 = va_arg(va, unsigned long);
			break;
		case PR_GET_DUMPABLE:
			break;
		default:
			// Unified currently implements only simple prctl operations in-kernel.
			// Do not speculatively read optional varargs here: many callers pass
			// only the arguments their specific operation requires.
			break;
	}

	return sys_prctl_args(option, arg2, arg3, arg4, arg5, out);
}

int Sysdeps<EventfdCreate>::operator()(unsigned int initval, int flags, int *fd) {
	long ret = flags ? syscall(SYS_EVENTFD2, initval, flags)
	                 : syscall(SYS_EVENTFD, initval);
	if (ret < 0) {
		return -ret;
	}
	*fd = ret;
	return 0;
}

int Sysdeps<TimerfdCreate>::operator()(int clockid, int flags, int *fd) {
	long ret = syscall(SYS_TIMERFD_CREATE, clockid, flags);
	if (ret < 0) {
		return -ret;
	}
	*fd = ret;
	return 0;
}

int Sysdeps<TimerfdSettime>::operator()(int fd, int flags, const struct itimerspec *value, struct itimerspec *oldvalue) {
	long ret = syscall(SYS_TIMERFD_SETTIME, fd, flags, value, oldvalue);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<TimerfdGettime>::operator()(int fd, struct itimerspec *its) {
	long ret = syscall(SYS_TIMERFD_GETTIME, fd, its);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SignalfdCreate>::operator()(const sigset_t *mask, int flags, int *fd) {
	long ret = syscall(SYS_SIGNALFD4, -1, mask, sizeof(sigset_t), flags);
	if (ret < 0) {
		return -ret;
	}
	*fd = ret;
	return 0;
}

int Sysdeps<SetSid>::operator()(pid_t *pid) {
	long ret = syscall(SYS_SETSID);
	if (ret < 0) {
		return -ret;
	}
	if (pid) *pid = ret;
	return 0;
}

int Sysdeps<GetSid>::operator()(pid_t pid, pid_t *sid) {
	long ret = syscall(SYS_GETSID, pid);
	if (ret < 0) {
		return -ret;
	}
	if (sid) *sid = ret;
	return 0;
}

int Sysdeps<Reboot>::operator()(int cmd) {
	long ret = syscall(SYS_REBOOT, 0xFEE1DEADu, 0x28121969u, cmd, 0);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
	long ret = syscall(SYS_SCHED_SETAFFINITY, pid, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
	long ret = syscall(SYS_SCHED_GETAFFINITY, pid, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<GetAffinity>::operator()(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
	long ret = syscall(SYS_SCHED_GETAFFINITY, pid, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetAffinity>::operator()(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
	long ret = syscall(SYS_SCHED_SETAFFINITY, pid, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<GetThreadaffinity>::operator()(pid_t tid, size_t cpusetsize, cpu_set_t *mask) {
	long ret = syscall(SYS_SCHED_GETAFFINITY, tid, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetThreadaffinity>::operator()(pid_t tid, size_t cpusetsize, const cpu_set_t *mask) {
	long ret = syscall(SYS_SCHED_SETAFFINITY, tid, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<GetResuid>::operator()(uid_t *ruid, uid_t *euid, uid_t *suid) {
	long ret = syscall(SYS_GETRESUID, ruid, euid, suid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetResuid>::operator()(uid_t ruid, uid_t euid, uid_t suid) {
	long ret = syscall(SYS_SETRESUID, ruid, euid, suid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<GetResgid>::operator()(gid_t *rgid, gid_t *egid, gid_t *sgid) {
	long ret = syscall(SYS_GETRESGID, rgid, egid, sgid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetResgid>::operator()(gid_t rgid, gid_t egid, gid_t sgid) {
	long ret = syscall(SYS_SETRESGID, rgid, egid, sgid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<GetGroups>::operator()(size_t size, gid_t *list, int *out) {
	long ret = syscall(SYS_GETGROUPS, size, list);
	if (ret < 0) {
		return -ret;
	}
	*out = static_cast<int>(ret);
	return 0;
}

int Sysdeps<SetGroups>::operator()(size_t gidsetsize, const gid_t *grouplist) {
	long ret = syscall(SYS_SETGROUPS, gidsetsize, grouplist);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetReuid>::operator()(uid_t ruid, uid_t euid) {
	long ret = syscall(SYS_SETREUID, ruid, euid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetRegid>::operator()(gid_t rgid, gid_t egid) {
	long ret = syscall(SYS_SETREGID, rgid, egid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Umask>::operator()(mode_t mode, mode_t *old) {
	long ret = syscall(SYS_UMASK, mode);
	if (ret < 0) {
		return -ret;
	}

	*old = static_cast<mode_t>(ret);
	return 0;
}

int Sysdeps<Getcpu>::operator()(int *cpu) {
	long result = syscall(SYS_GETCPU, cpu, nullptr);
	if (result < 0) {
		return -result;
	}
	return 0;
}

int sys_membarrier(int cmd, unsigned int flags, int cpu_id) {
	long result = syscall(SYS_MEMBARRIER, cmd, flags, cpu_id);
	if (result < 0) {
		return -result;
	}
	return 0;
}

int sys_get_mempolicy(int *mode, unsigned long *nodemask, unsigned long maxnode,
					  void *addr, unsigned long flags) {
	long result = syscall(SYS_GET_MEMPOLICY, mode, nodemask, maxnode, addr, flags);
	if (result < 0) {
		return -result;
	}
	return 0;
}

int Sysdeps<MemfdCreate>::operator()(const char *name, int flags, int *fd) {
	long result = syscall(SYS_MEMFD_CREATE, name, flags);
	if (result < 0) {
		return -result;
	}
	*fd = result;
	return 0;
}

int Sysdeps<GetMaxPriority>::operator()(int policy, int *out) {
	if (!out)
		return EINVAL;
	long ret = syscall(SYS_SCHED_GET_PRIORITY_MAX, policy);
	if (ret < 0) {
		return -ret;
	}
	*out = static_cast<int>(ret);
	return 0;
}

int Sysdeps<GetMinPriority>::operator()(int policy, int *out) {
	if (!out)
		return EINVAL;
	long ret = syscall(SYS_SCHED_GET_PRIORITY_MIN, policy);
	if (ret < 0) {
		return -ret;
	}
	*out = static_cast<int>(ret);
	return 0;
}

int Sysdeps<GetSchedparam>::operator()(void *tcb, int *policy, struct sched_param *param) {
	auto *t = reinterpret_cast<Tcb *>(tcb);
	if (policy) {
		long ret = syscall(SYS_SCHED_GETSCHEDULER, t->tid);
		if (ret < 0)
			return -ret;
		*policy = static_cast<int>(ret);
	}
	if (param) {
		long ret = syscall(SYS_SCHED_GETPARAM, t->tid, param);
		if (ret < 0)
			return -ret;
	}
	return 0;
}

int Sysdeps<GetScheduler>::operator()(pid_t pid, int *policy) {
	if (!policy)
		return EINVAL;

	long ret = syscall(SYS_SCHED_GETSCHEDULER, pid);
	if (ret < 0) {
		return -ret;
	}
	*policy = static_cast<int>(ret);
	return 0;
}

int Sysdeps<SetScheduler>::operator()(pid_t pid, int policy, const struct sched_param *param) {
	long ret = syscall(SYS_SCHED_SETSCHEDULER, pid, policy, param);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<GetParam>::operator()(pid_t pid, struct sched_param *param) {
	if (!param)
		return EINVAL;

	long ret = syscall(SYS_SCHED_GETPARAM, pid, param);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetParam>::operator()(pid_t pid, const struct sched_param *param) {
	long ret = syscall(SYS_SCHED_SETPARAM, pid, param);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<SetSchedparam>::operator()(void *tcb, int policy, const struct sched_param *param) {
	auto *t = reinterpret_cast<Tcb *>(tcb);

	long ret = syscall(SYS_SCHED_SETSCHEDULER, t->tid, policy, param);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

static inline unsigned long clamp_u64_to_ulong(uint64_t value) {
	if (value > static_cast<uint64_t>(ULONG_MAX))
		return ULONG_MAX;
	return static_cast<unsigned long>(value);
}

static inline unsigned short clamp_u64_to_ushort(uint64_t value) {
	if (value > static_cast<uint64_t>(USHRT_MAX))
		return USHRT_MAX;
	return static_cast<unsigned short>(value);
}

static inline long clamp_u64_to_long(uint64_t value) {
	if (value > static_cast<uint64_t>(LONG_MAX))
		return LONG_MAX;
	return static_cast<long>(value);
}

static int fetch_sysinfo(struct sysinfo *out) {
	long ret = syscall(SYS_INFO, out);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<Sysconf>::operator()(int num, long *ret) {
	// Prefer direct kernel system info for memory/cpu-related sysconf values.
	if (num == _SC_PHYS_PAGES || num == _SC_AVPHYS_PAGES
			|| num == _SC_NPROCESSORS_CONF || num == _SC_NPROCESSORS_ONLN) {
		struct sysinfo info = {};
		long page_size = 0;
		if (!fetch_sysinfo(&info)
				&& syscall(SYS_SYSCONF, _SC_PAGESIZE, &page_size) >= 0
				&& page_size > 0) {
			uint64_t total = static_cast<uint64_t>(info.totalram) * info.mem_unit;
			uint64_t free = static_cast<uint64_t>(info.freeram) * info.mem_unit;

			switch (num) {
				case _SC_PHYS_PAGES:
					*ret = clamp_u64_to_long(total / static_cast<uint64_t>(page_size));
					return 0;
				case _SC_AVPHYS_PAGES:
					*ret = clamp_u64_to_long(free / static_cast<uint64_t>(page_size));
					return 0;
				case _SC_NPROCESSORS_CONF:
				case _SC_NPROCESSORS_ONLN:
					*ret = info.procs ? static_cast<long>(info.procs) : 1;
					return 0;
			}
		}
	}

	long r = syscall(SYS_SYSCONF, num, ret);
	if (r < 0) return -r;
	return 0;
}

int Sysdeps<ThreadSetname>::operator()(void *tcb, const char *name) {
	(void)tcb;
	if(!name)
		return EINVAL;

	size_t nameLen = strlen(name);
	if(nameLen > 15)
		return ERANGE;

	long ret = syscall(SYS_SETTIDID, name, nameLen + 1);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<ThreadGetname>::operator()(void *tcb, char *name, size_t size) {
	(void)tcb;
	long ret = syscall(SYS_GETTIDID, name, size);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Sysinfo>::operator()(struct sysinfo *info) {
	if (!info)
		return EINVAL;

	memset(info, 0, sizeof(struct sysinfo));

	// Get uptime via CLOCK_MONOTONIC (clock 1)
	struct timespec ts;
	long ret = syscall(SYS_CLOCK_GETTIME, 1, &ts);
	if (ret >= 0) {
		info->uptime = ts.tv_sec;
	}

	// Prefer the Linux sysinfo syscall for memory limits.
	struct sysinfo raw = {};
	if (!fetch_sysinfo(&raw)) {
		*info = raw;
	} else {
		// Fallback for older kernels: derive bytes from sysconf pages.
		long phys_pages = 0;
		long avail_pages = 0;
		long nprocs = 1;
		long page_size = 4096;

		long phys_ret = syscall(SYS_SYSCONF, _SC_PHYS_PAGES, &phys_pages);
		long avail_ret = syscall(SYS_SYSCONF, _SC_AVPHYS_PAGES, &avail_pages);
		long nproc_ret = syscall(SYS_SYSCONF, _SC_NPROCESSORS_ONLN, &nprocs);
		long page_ret = syscall(SYS_SYSCONF, _SC_PAGESIZE, &page_size);

		if (phys_ret < 0)
			return -phys_ret;
		if (avail_ret < 0)
			return -avail_ret;

		if (page_ret < 0 || page_size <= 0)
			page_size = 4096;
		if (phys_pages < 0)
			phys_pages = 0;
		if (avail_pages < 0)
			avail_pages = 0;
		if (nproc_ret < 0 || nprocs < 1)
			nprocs = 1;

		uint64_t total = static_cast<uint64_t>(phys_pages) * static_cast<uint64_t>(page_size);
		uint64_t free = static_cast<uint64_t>(avail_pages) * static_cast<uint64_t>(page_size);
		info->totalram = clamp_u64_to_ulong(total);
		info->freeram = clamp_u64_to_ulong(free);
		info->procs = clamp_u64_to_ushort(static_cast<uint64_t>(nprocs));
	}

	info->sharedram = 0;
	info->bufferram = 0;
	info->totalswap = 0;
	info->freeswap = 0;
	info->totalhigh = 0;
	info->freehigh = 0;
	info->mem_unit = 1;

	// Load averages: no kernel load tracking yet, report idle system
	// SI_LOAD_SHIFT = 16, so 0 means 0.0 load
	info->loads[0] = 0;
	info->loads[1] = 0;
	info->loads[2] = 0;

	return 0;
}

#if __MLIBC_BSD_OPTION
int Sysdeps<GetLoadavg>::operator()(double *samples) {
	// No kernel load tracking - report idle system
	samples[0] = 0.0;
	samples[1] = 0.0;
	samples[2] = 0.0;
	return 0;
}
#endif

#endif

} // namespace mlibc

#ifndef MLIBC_BUILDING_RTLD
extern "C" void *mremap(void *pointer, size_t size, size_t new_size, int flags, ...) {
	void *new_address = nullptr;
	if(flags & MREMAP_FIXED) {
		va_list args;
		va_start(args, flags);
		new_address = va_arg(args, void *);
		va_end(args);
	}

	long ret;
	if(flags & MREMAP_FIXED) {
		ret = syscall(SYS_MREMAP, (uintptr_t)pointer, size, new_size, flags,
				(uintptr_t)new_address);
	} else {
		ret = syscall(SYS_MREMAP, (uintptr_t)pointer, size, new_size, flags);
	}
	if(ret < 0) {
		errno = -ret;
		return MAP_FAILED;
	}
	return (void *)ret;
}

extern "C" int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
	if(int e = mlibc::Sysdeps<SetAffinity>::operator()(pid, cpusetsize, mask); e) {
		errno = e;
		return -1;
	}
	return 0;
}

extern "C" int clone(int (*fn)(void *), void *stack, int flags, void *arg, ...) {
	pid_t *parent_tid = nullptr;
	void *tls = nullptr;
	pid_t *child_tid = nullptr;

	va_list args;
	va_start(args, arg);
	if(flags & (CLONE_PARENT_SETTID | CLONE_PIDFD))
		parent_tid = va_arg(args, pid_t *);
	if(flags & CLONE_SETTLS)
		tls = va_arg(args, void *);
	if(flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID))
		child_tid = va_arg(args, pid_t *);
	va_end(args);

	int ret;
	if(int e = mlibc::sys_clone_linux(fn, stack, flags, arg, parent_tid, tls, child_tid, &ret); e) {
		errno = e;
		return -1;
	}
	return ret;
}

extern "C" int sem_getvalue(sem_t *sem, int *sval) {
	if(!sem || !sval) {
		errno = EINVAL;
		return -1;
	}

	constexpr unsigned int semaphoreCountMask = (1u << 31) - 1;
	unsigned int state = __atomic_load_n(&sem->__mlibc_count, __ATOMIC_ACQUIRE);
	*sval = static_cast<int>(state & semaphoreCountMask);
	return 0;
}

extern "C" int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
		const struct timespec *abstime) {
	if(!cond || !mutex)
		return EINVAL;

	constexpr unsigned int mutexErrorCheck = 2;
	constexpr unsigned int mutexOwnerMask = (static_cast<unsigned int>(1) << 30) - 1;
	if(mutex->__mlibc_flags & mutexErrorCheck) {
		unsigned int state = __atomic_load_n(&mutex->__mlibc_state, __ATOMIC_ACQUIRE);
		long tid = syscall(SYS_GETTID);
		if(tid <= 0 ||
				!mutex->__mlibc_recursion ||
				(state & mutexOwnerMask) != static_cast<unsigned int>(tid))
			return EPERM;
	}

	return mlibc::thread_cond_timedwait(cond, mutex, abstime, cond->__mlibc_clock);
}
#endif

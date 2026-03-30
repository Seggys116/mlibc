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
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <limits.h>

namespace mlibc{

extern "C" void __mlibc_raw_clone_entry();

static constexpr int kFutexWait = 0;
static constexpr int kFutexPrivateFlag = 128;

int sys_futex_tid(){
	constexpr int kMaxFutexTid = (1 << 30) - 1;
	long ret = syscall(SYS_GETTID);
	if(ret > 0 && ret <= kMaxFutexTid)
		return static_cast<int>(ret);

	// Never propagate negative/oversized TIDs into mutex owner bits.
	// Keep this path RTLD-safe: get_current_tcb() is not available in all
	// build variants of this sysdeps TU.
	return 0;
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time){
	// Linux-style futex op through syscall 71:
	// futex(uaddr, op=FUTEX_WAIT, val=expected, timeout, uaddr2, val3)
	// Keep all futex traffic on one ABI path so WAIT/WAKE semantics match.
	long ret = syscall(SYS_FUTEX_WAIT, pointer, kFutexWait | kFutexPrivateFlag, expected, time, 0, 0);
	if (ret < 0)
		return -ret;
	return 0;
}

int sys_futex_wake(int *pointer, int count) {
	if(count <= 0)
		return 0;

	// Use the dedicated wake syscall so hot wake paths bypass WAIT-side ABI
	// compatibility decoding and timeout handling.
	long ret = syscall(SYS_FUTEX_WAKE, pointer, count);
	if (ret < 0)
		return -ret;
	return 0;
}

int sys_tcb_set(void* pointer){
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
	long ret = syscall(SYS_SET_FS_BASE, (uintptr_t)pointer);
	if (ret < 0) {
		return -ret;
	}

#if defined(__x86_64__)
	asm volatile ("movq %0, %%fs:0" :: "r"(pointer) : "memory");
#endif
	return 0;
}

int sys_tcflow(int fd, int action) {
	// tcflow controls terminal flow control (suspend/resume I/O)
	// Use TCXONC ioctl command (0x540A)
	long ret = syscall(SYS_IOCTL, fd, 0x540A, action);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	size_t aligned_size = (size + 0xFFF) & ~static_cast<size_t>(0xFFF);
	long ret = syscall(SYS_MMAP, (uintptr_t)window, aligned_size, (uintptr_t)hint, flags, prot, fd, offset);
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
	return 0;
}

int sys_vm_unmap(void* address, size_t size) {
	/* Round up size to page boundary - Linux munmap accepts any size */
	size_t aligned_size = (size + 0xFFF) & ~static_cast<size_t>(0xFFF);

	long ret = syscall(SYS_MUNMAP, (uintptr_t)address, aligned_size);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int
sys_vm_protect(void *pointer, size_t size, int prot)
{
	long ret = syscall(SYS_MPROTECT, (uintptr_t)pointer, size, prot);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}


int sys_vm_remap(void *pointer, size_t size, size_t new_size, int flags, void **window) {
	long ret = syscall(SYS_MREMAP, (uintptr_t)pointer, size, new_size, flags);
	if (ret < 0)
		return -ret;
	*window = (void *)ret;
	return 0;
}

int sys_madvise(void *pointer, size_t size, int advice) {
	long ret = syscall(SYS_MADVISE, (uintptr_t)pointer, size, advice);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_mincore(void *addr, size_t length, unsigned char *vec) {
	long ret = syscall(SYS_MINCORE, (uintptr_t)addr, length, (uintptr_t)vec);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_anon_allocate(size_t size, void **pointer) {
	return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0, pointer);
}

int sys_anon_free(void *pointer, size_t size) {
	return sys_vm_unmap(pointer, size);
}

void sys_libc_panic(){
	sys_libc_log("libc panic!");
	// Match abort() semantics:
	// 1) Raise SIGABRT.
	// 2) If a handler returns or SIGABRT was ignored, reset to default and raise again.
	// 3) If still alive, fall back to _Exit(127).
	pid_t pid = syscall(SYS_GETPID);
	if (pid > 0) {
		(void)syscall(SYS_KILL, pid, SIGABRT);

		struct sigaction sa = {};
		sa.sa_handler = SIG_DFL;
		sa.sa_flags = 0;
		(void)syscall(SYS_SIGNAL_ACTION, SIGABRT, (uintptr_t)&sa, 0);

		(void)syscall(SYS_KILL, pid, SIGABRT);
	}

	syscall(SYS_EXIT_GROUP, 127);
	__builtin_trap();
	for(;;);
}

void sys_libc_log(const char* msg){
	syscall(0, (uintptr_t)msg);
}

int sys_gethostname(char *buffer, size_t bufsize) {
	if (!buffer) {
		return EFAULT;
	}

	if (bufsize) {
		const char *name = "unified";
		size_t i = 0;
		for (; i + 1 < bufsize && name[i]; ++i) {
			buffer[i] = name[i];
		}
		buffer[i] = '\0';
	}
	return 0;
}

#ifndef MLIBC_BUILDING_RTLD

void sys_exit(int status){
	syscall(SYS_EXIT_GROUP, status);

	__builtin_unreachable();
}

pid_t sys_getpid(){
	return syscall(SYS_GETPID);
}

pid_t sys_getppid(){
	return syscall(SYS_GETPPID);
}

pid_t sys_gettid(){
	return syscall(SYS_GETTID);
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	struct timespec ts;
	long ret = syscall(SYS_CLOCK_GETTIME, clock, &ts);
	if (ret < 0) {
		return -ret;
	}
	*secs = ts.tv_sec;
	*nanos = ts.tv_nsec;
	return 0;
}

int sys_clock_getres(int clock, time_t *secs, long *nanos) {
	struct timespec res;
	long ret = syscall(SYS_CLOCK_GETRES, clock, &res);
	if (ret < 0) {
		return -ret;
	}
	*secs = res.tv_sec;
	*nanos = res.tv_nsec;
	return 0;
}

int sys_getcwd(char *buffer, size_t size){
	long ret = syscall(SYS_GET_CWD, buffer, size);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_chdir(const char *path){
	long ret = syscall(SYS_CHDIR, path);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_sleep(time_t* sec, long* nanosec){
	long ret = syscall(SYS_NANO_SLEEP, (*sec) * 1000000000 + (*nanosec));
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value) {
	long ret = syscall(SYS_SETITIMER, which, new_value, old_value);
	if (ret < 0)
		return -ret;
	return 0;
}

int sys_getitimer(int which, struct itimerval *curr_value) {
	long ret = syscall(SYS_GETITIMER, which, curr_value);
	if (ret < 0)
		return -ret;
	return 0;
}

uid_t sys_getuid(){
	return syscall(SYS_GETUID);
}

uid_t sys_geteuid(){
	return syscall(SYS_GETEUID);
}

int sys_setuid(uid_t uid){
	long ret = syscall(SYS_SETUID, uid);
	if (ret < 0)
		return -ret;
	return 0;
}

int sys_seteuid(uid_t euid){
	long ret = syscall(SYS_SETEUID, euid);
	if (ret < 0)
		return -ret;
	return 0;
}

gid_t sys_getgid(){
	return syscall(SYS_GETGID);
}

gid_t sys_getegid(){
	return syscall(SYS_GETEGID);
}

int sys_setpgid(pid_t pid, pid_t pgid) {
	long ret = syscall(SYS_SETPGID, pid, pgid);
	if (ret < 0)
		return -ret;
	return 0;
}

int sys_getpgid(pid_t pid, pid_t *pgid) {
	// Standard syscall: only pass pid, kernel returns PGID directly
	long ret = syscall(SYS_GETPGID, pid);
	if (ret < 0)
		return -ret;
	*pgid = ret;
	return 0;
}

int sys_setgid(gid_t gid){
	long ret = syscall(SYS_SETGID, gid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setegid(gid_t egid){
	long ret = syscall(SYS_SETEGID, egid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

void sys_yield(){
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
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_CHILD_SETTID  0x01000000

int sys_clone(void *tcb, pid_t *tid_out, void *stack){
	//mlibc::infoLogger() << "mlibc: sys_clone entry tcb=" << (void*)tcb << " stack=" << (void*)stack << frg::endlog;
	// Follow Linux mlibc threading flags:
	// CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
	// CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
	// CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
	// Wire child_tid to tcb->tid so the child sees its TID without relying on
	// a parent-side futex wake race.
	if (!tcb || !tid_out) {
		return EINVAL;
	}
	auto *child_tid = &reinterpret_cast<Tcb *>(tcb)->tid;
	uint64_t flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	                 CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
	                 CLONE_PARENT_SETTID | CLONE_CHILD_SETTID |
	                 CLONE_CHILD_CLEARTID;

	//mlibc::infoLogger() << "mlibc: sys_clone syscall entry=" << (void*)__mlibc_start_thread << " stack=" << (void*)stack << " flags=0x" << flags << frg::endlog;

	// clone(entry, stack, flags, parent_tid, child_tid, tls)
	// entry is __mlibc_start_thread which pops actual entry/user_arg/tcb from stack
	long tid = syscall(SYS_CLONE, (uint64_t)__mlibc_start_thread, (uint64_t)stack,
	                   flags, (uint64_t)tid_out, (uint64_t)child_tid, (uint64_t)tcb);

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
	                   reinterpret_cast<uint64_t>(tls));

	if(tid < 0)
		return static_cast<int>(-tid);
	if(static_cast<long>(static_cast<int>(tid)) != tid)
		return EOVERFLOW;

	*out = static_cast<int>(tid);
	return 0;
}

void sys_thread_exit(){
	syscall(SYS_EXIT_THREAD);

	__builtin_unreachable();
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid){
	pid_t ret = ru
		? syscall(SYS_WAIT4, pid, status, flags, ru)
		: syscall(SYS_WAIT_PID, pid, status, flags);

	if(ret < 0){
		return -ret;
	}

	*ret_pid = ret;

	return 0;
}

int sys_waitid(idtype_t idtype, id_t id, siginfo_t *info, int options) {
	long ret = syscall(SYS_WAITID, idtype, id, info, options);
	if(ret < 0)
		return -ret;
	return 0;
}

int sys_pidfd_open(pid_t pid, unsigned int flags, int *outfd) {
	long ret = syscall(SYS_PIDFD_OPEN, pid, flags);
	if(ret < 0)
		return -ret;
	*outfd = static_cast<int>(ret);
	return 0;
}

int sys_pidfd_getpid(int fd, pid_t *outpid) {
	long ret = syscall(SYS_PIDFD_GETPID, fd);
	if(ret < 0)
		return -ret;
	*outpid = static_cast<pid_t>(ret);
	return 0;
}

int sys_pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
	long ret = syscall(SYS_PIDFD_SEND_SIGNAL, pidfd, sig, info, flags);
	if(ret < 0)
		return -ret;
	return 0;
}

int sys_fork(pid_t *child){
	long pid = syscall(SYS_FORK, 0);
	if(pid < 0){
		return -pid;
	}
	*child = pid;
	return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]){
	long ret = syscall(SYS_EXECVE, path, argv, envp);
	if (ret < 0)
		return -ret;
	return 0;
}

int sys_getentropy(void *buffer, size_t length){
	long ret = syscall(SYS_GETENTROPY, buffer, length);
	if (ret < 0)
		return -ret;
	return 0;
}

int sys_uname(struct utsname *buf) {
	long ret = syscall(SYS_UNAME, buf);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_getrlimit(int resource, struct rlimit *limit) {
	long ret = syscall(SYS_GET_RESOURCE_LIMIT, resource, limit);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setrlimit(int resource, const struct rlimit *limit) {
	long ret = syscall(SYS_SET_RESOURCE_LIMIT, resource, limit);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_getrusage(int scope, struct rusage *usage) {
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

int sys_prctl(int option, va_list va, int *out) {
	unsigned long arg2 = 0;
	unsigned long arg3 = 0;
	unsigned long arg4 = 0;
	unsigned long arg5 = 0;

	switch(option) {
		case PR_SET_NAME:
		case PR_GET_NAME:
		case PR_SET_DUMPABLE:
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

int sys_eventfd_create(unsigned int initval, int flags, int *fd) {
	long ret = syscall(SYS_EVENTFD, initval, flags);
	if (ret < 0) {
		return -ret;
	}
	*fd = ret;
	return 0;
}

int sys_timerfd_create(int clockid, int flags, int *fd) {
	long ret = syscall(SYS_TIMERFD_CREATE, clockid, flags);
	if (ret < 0) {
		return -ret;
	}
	*fd = ret;
	return 0;
}

int sys_timerfd_settime(int fd, int flags, const struct itimerspec *value, struct itimerspec *oldvalue) {
	long ret = syscall(SYS_TIMERFD_SETTIME, fd, flags, value, oldvalue);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_timerfd_gettime(int fd, struct itimerspec *its) {
	long ret = syscall(SYS_TIMERFD_GETTIME, fd, its);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_signalfd_create(const sigset_t *mask, int flags, int *fd) {
	long ret = syscall(SYS_SIGNALFD, mask, flags);
	if (ret < 0) {
		return -ret;
	}
	*fd = ret;
	return 0;
}

int sys_setsid(pid_t *pid) {
	long ret = syscall(SYS_SETSID);
	if (ret < 0) {
		return -ret;
	}
	if (pid) *pid = ret;
	return 0;
}

int sys_getsid(pid_t pid, pid_t *sid) {
	long ret = syscall(SYS_GETSID, pid);
	if (ret < 0) {
		return -ret;
	}
	if (sid) *sid = ret;
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

int sys_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask) {
	long ret = syscall(SYS_SCHED_GETAFFINITY, pid, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask) {
	long ret = syscall(SYS_SCHED_SETAFFINITY, pid, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_getthreadaffinity(pid_t tid, size_t cpusetsize, cpu_set_t *mask) {
	pid_t encoded = tid > 0 ? -tid : tid;
	long ret = syscall(SYS_SCHED_GETAFFINITY, encoded, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setthreadaffinity(pid_t tid, size_t cpusetsize, const cpu_set_t *mask) {
	pid_t encoded = tid > 0 ? -tid : tid;
	long ret = syscall(SYS_SCHED_SETAFFINITY, encoded, cpusetsize, mask);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_getresuid(uid_t *ruid, uid_t *euid, uid_t *suid) {
	long ret = syscall(SYS_GETRESUID, ruid, euid, suid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
	long ret = syscall(SYS_SETRESUID, ruid, euid, suid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid) {
	long ret = syscall(SYS_GETRESGID, rgid, egid, sgid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
	long ret = syscall(SYS_SETRESGID, rgid, egid, sgid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_getgroups(int gidsetsize, gid_t *grouplist) {
	long ret = syscall(SYS_GETGROUPS, gidsetsize, grouplist);
	if (ret < 0) {
		return -ret;
	}
	return ret;
}

int sys_setgroups(size_t gidsetsize, const gid_t *grouplist) {
	long ret = syscall(SYS_SETGROUPS, gidsetsize, grouplist);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setreuid(uid_t ruid, uid_t euid) {
	long ret = syscall(SYS_SETREUID, ruid, euid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setregid(gid_t rgid, gid_t egid) {
	long ret = syscall(SYS_SETREGID, rgid, egid);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_umask(mode_t mode, mode_t *old) {
	long ret = syscall(SYS_UMASK, mode);
	if (ret < 0) {
		return -ret;
	}

	*old = static_cast<mode_t>(ret);
	return 0;
}

#if __MLIBC_BSD_OPTION
int sys_brk(void **out) {
	(void)out;
	return ENOSYS;
}
#endif

int sys_getcpu(int *cpu) {
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

int sys_memfd_create(const char *name, int flags, int *fd) {
	long result = syscall(SYS_MEMFD_CREATE, name, flags);
	if (result < 0) {
		return -result;
	}
	*fd = result;
	return 0;
}

int sys_get_max_priority(int policy, int *out) {
	if (!out)
		return EINVAL;
	long ret = syscall(SYS_GETPRIORITYMAX, policy, out);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_get_min_priority(int policy, int *out) {
	if (!out)
		return EINVAL;
	long ret = syscall(SYS_GETPRIORITYMIN, policy, out);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_getschedparam(void *tcb, int *policy, struct sched_param *param) {
	auto *t = reinterpret_cast<Tcb *>(tcb);
	int kern_policy = 0;
	int kern_priority = 0;

	long ret = syscall(SYS_GETSCHEDPARAM, t->tid, &kern_policy, &kern_priority);
	if (ret < 0) {
		return -ret;
	}

	if (policy)
		*policy = kern_policy;
	if (param)
		param->sched_priority = kern_priority;
	return 0;
}

int sys_getscheduler(pid_t pid, int *policy) {
	if (!policy)
		return EINVAL;

	int priority = 0;
	long ret = syscall(SYS_GETSCHEDPARAM, pid, policy, &priority);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setscheduler(pid_t pid, int policy, const struct sched_param *param) {
	int priority = param ? param->sched_priority : 0;

	long ret = syscall(SYS_SETSCHEDPARAM, pid, policy, priority);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_getparam(pid_t pid, struct sched_param *param) {
	if (!param)
		return EINVAL;

	int policy = 0;
	long ret = syscall(SYS_GETSCHEDPARAM, pid, &policy, &param->sched_priority);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_setparam(pid_t pid, const struct sched_param *param) {
	int policy = 0;
	long get_ret = syscall(SYS_GETSCHEDPARAM, pid, &policy, nullptr);
	if (get_ret < 0) {
		return -get_ret;
	}

	int priority = param ? param->sched_priority : 0;
	long set_ret = syscall(SYS_SETSCHEDPARAM, pid, policy, priority);
	if (set_ret < 0) {
		return -set_ret;
	}
	return 0;
}

int sys_setschedparam(void *tcb, int policy, const struct sched_param *param) {
	auto *t = reinterpret_cast<Tcb *>(tcb);
	int priority = param ? param->sched_priority : 0;

	long ret = syscall(SYS_SETSCHEDPARAM, t->tid, policy, priority);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

struct unified_sysinfo {
	uint64_t totalMem;
	uint64_t usedMem;
	uint16_t cpuCount;
} __attribute__((packed));

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

static int fetch_sysinfo(unified_sysinfo *out) {
	long ret = syscall(SYS_INFO, out);
	if (ret < 0)
		return -ret;
	return 0;
}

int sys_sysconf(int num, long *ret) {
	// Prefer direct kernel system info for memory/cpu-related sysconf values.
	if (num == _SC_PHYS_PAGES || num == _SC_AVPHYS_PAGES
			|| num == _SC_NPROCESSORS_CONF || num == _SC_NPROCESSORS_ONLN) {
		unified_sysinfo info = {};
		long page_size = 0;
		if (!fetch_sysinfo(&info)
				&& syscall(SYS_SYSCONF, _SC_PAGESIZE, &page_size) >= 0
				&& page_size > 0) {
			uint64_t total = info.totalMem;
			uint64_t used = info.usedMem;
			if (used > total)
				used = total;
			uint64_t free = total - used;

			switch (num) {
				case _SC_PHYS_PAGES:
					*ret = clamp_u64_to_long(total / static_cast<uint64_t>(page_size));
					return 0;
				case _SC_AVPHYS_PAGES:
					*ret = clamp_u64_to_long(free / static_cast<uint64_t>(page_size));
					return 0;
				case _SC_NPROCESSORS_CONF:
				case _SC_NPROCESSORS_ONLN:
					*ret = info.cpuCount ? static_cast<long>(info.cpuCount) : 1;
					return 0;
			}
		}
	}

	long r = syscall(SYS_SYSCONF, num, ret);
	if (r < 0) return -r;
	return 0;
}

int sys_thread_setname(void *tcb, const char *name) {
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

int sys_thread_getname(void *tcb, char *name, size_t size) {
	long ret = syscall(SYS_GETTIDID, name, size);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int sys_sysinfo(struct sysinfo *info) {
	if (!info)
		return EINVAL;

	memset(info, 0, sizeof(struct sysinfo));

	// Get uptime via CLOCK_MONOTONIC (clock 1)
	struct timespec ts;
	long ret = syscall(SYS_CLOCK_GETTIME, 1, &ts);
	if (ret >= 0) {
		info->uptime = ts.tv_sec;
	}

	// Prefer dedicated system-info syscall for memory limits.
	unified_sysinfo raw = {};
	if (!fetch_sysinfo(&raw)) {
		uint64_t total = raw.totalMem;
		uint64_t used = raw.usedMem;
		if (used > total)
			used = total;
		uint64_t free = total - used;
		info->totalram = clamp_u64_to_ulong(total);
		info->freeram = clamp_u64_to_ulong(free);
		info->procs = raw.cpuCount ? raw.cpuCount : 1;
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
int sys_getloadavg(double *samples) {
	// No kernel load tracking - report idle system
	samples[0] = 0.0;
	samples[1] = 0.0;
	samples[2] = 0.0;
	return 0;
}
#endif

#endif

} // namespace mlibc

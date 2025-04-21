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
#include <time.h>
#include <signal.h>

namespace mlibc{

int sys_futex_tid(){
	return syscall(SYS_GETTID);
}

int sys_futex_wait(int *pointer, int expected, const struct timespec *time){
	return syscall(SYS_FUTEX_WAIT, pointer, expected);
}

int sys_futex_wake(int *pointer) {
	return syscall(SYS_FUTEX_WAKE, pointer);
}

int sys_tcb_set(void* pointer){
	syscall(SYS_SET_FS_BASE, (uintptr_t)pointer);
	return 0;
}

int sys_vm_map(void *hint, size_t size, int prot, int flags, int fd, off_t offset, void **window) {
	return syscall(SYS_MMAP, (uintptr_t)window, (size + 0xFFF) & ~static_cast<size_t>(0xFFF), (uintptr_t)hint, flags, prot, fd, offset);
}

int sys_vm_unmap(void* address, size_t size) {
	__ensure(!(size & 0xFFF));

	long ret = syscall(SYS_MUNMAP, (uintptr_t)address, (size + 0xFFF) & ~static_cast<size_t>(0xFFF));

	return ret;
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


int sys_anon_allocate(size_t size, void **pointer) {
	return sys_vm_map(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0, pointer);
}

int sys_anon_free(void *pointer, size_t size) {
	return sys_vm_unmap(pointer, size);
}

void sys_libc_panic(){
	sys_libc_log("libc panic!");
	__builtin_trap();
	for(;;);
}

void sys_libc_log(const char* msg){
	syscall(0, (uintptr_t)msg);
}

int sys_gethostname(char *buffer, size_t bufsize) {
	if (bufsize >= 6) {
		memcpy(buffer, "unified", 8);
	}
	return 0;
}

#ifndef MLIBC_BUILDING_RTLD

void sys_exit(int status){
	syscall(SYS_EXIT, status);

	__builtin_unreachable();
}

pid_t sys_getpid(){
	uint64_t _pid;
	syscall(SYS_GETPID, (uintptr_t)&_pid);

	pid_t pid = _pid;
	return pid;
}

pid_t sys_getppid(){
	return syscall(SYS_GETPPID);
}

int sys_clock_get(int clock, time_t *secs, long *nanos) {
	syscall(SYS_UPTIME, nanos);

	*secs = (*nanos) / 1000000000;
	*nanos = (*nanos) - (*secs) * 1000000000;

	return 0;
}

int sys_getcwd(char *buffer, size_t size){
	return syscall(SYS_GET_CWD, buffer, size);
}

int sys_chdir(const char *path){
	syscall(SYS_CHDIR, path);
	return 0;
}

int sys_sleep(time_t* sec, long* nanosec){
	syscall(SYS_NANO_SLEEP, (*sec) * 1000000000 + (*nanosec));
	return 0;
}

uid_t sys_getuid(){
	return syscall(SYS_GETUID);
}

uid_t sys_geteuid(){
	return syscall(SYS_GETEUID);
}

int sys_setuid(uid_t uid){
	return -syscall(SYS_SETUID, uid);
}

int sys_seteuid(uid_t euid){
	return -syscall(SYS_SETEUID, euid);
}

gid_t sys_getgid(){
	return syscall(SYS_GETGID);
}

gid_t sys_getegid(){
	return syscall(SYS_GETEGID);
}

int sys_setpgid(pid_t pid, pid_t pgid) {
	return syscall(SYS_SETPGID, pid, pgid);
}

int sys_getpgid(pid_t pid, pid_t *pgid) {
	long error = syscall(SYS_GETPGID, pid, pgid);
	return error;
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
#define CLONE_SETTLS        0x00080000
#define CLONE_PARENT_SETTID 0x00100000
#define CLONE_CHILD_CLEARTID 0x00200000
#define CLONE_CHILD_SETTID  0x01000000

int sys_clone(void *tcb, pid_t *tid_out, void *stack){
	// Use full clone() syscall with Linux-compatible flags for pthreads
	// Standard pthread clone flags: CLONE_VM | CLONE_FS | CLONE_FILES |
	//                               CLONE_SIGHAND | CLONE_THREAD | CLONE_SETTLS |
	//                               CLONE_PARENT_SETTID | CLONE_CHILD_SETTID
	uint64_t flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	                 CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID |
	                 CLONE_CHILD_SETTID;

	// clone(flags, stack, parent_tid, child_tid, tls)
	pid_t tid = syscall(SYS_CLONE, flags, (uint64_t)stack,
	                    (uint64_t)tid_out, (uint64_t)tid_out, (uint64_t)tcb);

	if(tid < 0){
		return -tid;  // Return positive errno
	}

	*tid_out = tid;

	return 0;
}

void sys_thread_exit(){
	syscall(SYS_EXIT_THREAD);

	__builtin_unreachable();
}

int sys_waitpid(pid_t pid, int *status, int flags, struct rusage *ru, pid_t *ret_pid){
	if(ru) {
		mlibc::infoLogger() << "mlibc: struct rusage in sys_waitpid is unsupported" << frg::endlog;
		return ENOSYS;
	}

	pid_t ret = syscall(SYS_WAIT_PID, pid, status, flags);

	if(ret < 0){
		return -ret;
	}

	*ret_pid = ret;

	return 0;
}

int sys_fork(pid_t *child){
	long pid = syscall(SYS_FORK, 0);
	if(pid < 0){
		errno = pid;
		return -1;
	}

	*child = pid;
	return 0;
}

int sys_execve(const char *path, char *const argv[], char *const envp[]){
	return -syscall(SYS_EXECVE, path, argv, envp);
}

int sys_getentropy(void *buffer, size_t length){
	return -syscall(SYS_GETENTROPY, buffer, length);
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

int sys_prctl(int option, va_list va, int *out) {
	// Extract up to 4 additional arguments from va_list
	unsigned long arg2 = va_arg(va, unsigned long);
	unsigned long arg3 = va_arg(va, unsigned long);
	unsigned long arg4 = va_arg(va, unsigned long);
	unsigned long arg5 = va_arg(va, unsigned long);

	long ret = syscall(SYS_PRCTL, option, arg2, arg3, arg4, arg5);
	if (ret < 0) {
		return -ret;
	}
	*out = ret;
	return 0;
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

mode_t sys_umask(mode_t cmask) {
	long ret = syscall(SYS_UMASK, cmask);
	return ret;
}
#endif

}

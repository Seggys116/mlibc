#include <unified/syscall.h>

#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <mlibc/all-sysdeps.hpp>

namespace mlibc{

int Sysdeps<Sigprocmask>::operator()(int how, const sigset_t *__restrict set,
	sigset_t *__restrict retrieve){
    int ret = syscall(SYS_SIGPROCMASK, how, set, retrieve, sizeof(sigset_t));
    if(ret < 0){
        return -ret;
    }

    return 0;
}

int Sysdeps<Sigaction>::operator()(int signal, const struct sigaction *__restrict action,
	struct sigaction *__restrict oldAction) {
    int ret = syscall(SYS_SIGNAL_ACTION, signal, action, oldAction, sizeof(sigset_t));
    if(ret < 0){
        return -ret;
    }

    return 0;
}

int Sysdeps<Kill>::operator()(int pid, int signal){
    int ret = syscall(SYS_KILL, pid, signal);
    if(ret < 0){
        return -ret;
    }

    return 0;
}

int Sysdeps<Sigsuspend>::operator()(const sigset_t *set) {
    int ret = syscall(SYS_SIGSUSPEND, (uint64_t)set, sizeof(sigset_t));
    if(ret < 0){
        return -ret;
    }
    return 0;
}

int Sysdeps<Pause>::operator()() {
    long ret = syscall(SYS_PAUSE);
    if(ret < 0)
        return -ret;
    return 0;
}

int Sysdeps<Sigaltstack>::operator()(const stack_t *ss, stack_t *oss) {
    int ret = syscall(SYS_SIGALTSTACK, ss, oss);
    if (ret < 0)
        return -ret;
    return 0;
}

int Sysdeps<Sigpending>::operator()(sigset_t *set) {
    long ret = syscall(SYS_SIGPENDING, (uintptr_t)set, sizeof(sigset_t));
    if (ret < 0)
        return -ret;
    return 0;
}

int Sysdeps<Tgkill>::operator()(int tgid, int tid, int sig) {
    long ret = syscall(SYS_TGKILL, tgid, tid, sig);
    if (ret < 0)
        return -ret;
    return 0;
}

int Sysdeps<Sigtimedwait>::operator()(const sigset_t *__restrict set, siginfo_t *__restrict info,
    const struct timespec *__restrict timeout, int *out_signal) {
    long ret = syscall(SYS_SIGTIMEDWAIT, (uintptr_t)set, (uintptr_t)info,
                       (uintptr_t)timeout, sizeof(sigset_t));
    if (ret < 0)
        return -ret;
    // ret is the signal number on success
    *out_signal = (int)ret;
    return 0;
}

int Sysdeps<Sigqueue>::operator()(pid_t pid, int sig, const union sigval val) {
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    si.si_signo = sig;
    si.si_code = SI_QUEUE;
    si.si_value = val;

    long senderUid = syscall(SYS_GETUID);
    if (senderUid < 0)
        return -senderUid;
    long senderPid = syscall(SYS_GETPID);
    if (senderPid < 0)
        return -senderPid;

    si.si_uid = static_cast<uid_t>(senderUid);
    si.si_pid = static_cast<pid_t>(senderPid);

    long ret = syscall(SYS_SIGQUEUE, pid, sig, (uintptr_t)&si);
    if (ret < 0)
        return -ret;
    return 0;
}

}

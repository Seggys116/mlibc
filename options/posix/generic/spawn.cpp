
#include <spawn.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sched.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>

#include <bits/ensure.h>
#include <mlibc/debug.hpp>

/*
 * Musl places this in a seperate header called fdop.h
 * This header isn't present in glibc, or on my host, so I
 * include it's contents here
 */

#define FDOP_CLOSE 1
#define FDOP_DUP2 2
#define FDOP_OPEN 3
#define FDOP_CHDIR 4
#define FDOP_FCHDIR 5

struct fdop {
	struct fdop *next, *prev;
	int cmd, fd, srcfd, oflag;
	mode_t mode;
	char path[];
};

/*
 * This posix_spawn implementation is taken from musl
 */

struct args {
	int p[2];
	sigset_t oldmask;
	const char *path;
	const posix_spawn_file_actions_t *fa;
	const posix_spawnattr_t *__restrict attr;
	char *const *argv, *const *envp;
};

static int child(void *args_vp) {
	int i, ret;
	struct sigaction sa = {};
	struct args *args = (struct args *)args_vp;
	int p = args->p[1];
	const posix_spawn_file_actions_t *fa = args->fa;
	const posix_spawnattr_t *__restrict attr = args->attr;
	bool use_execvpe = false;

	if(attr->__fn)
		use_execvpe = true;

	close(args->p[0]);

	/* Reset any caught signal dispositions before unblocking signals.
	 * This implementation uses fork() rather than a CLONE_VM-based spawn,
	 * so the simplest safe approach is to query the current disposition
	 * directly instead of relying on out-of-band handler tracking. */
	for(i = 1; i < NSIG; i++) {
		bool install = false;
		if((attr->__flags & POSIX_SPAWN_SETSIGDEF) && sigismember(&attr->__def, i)) {
			sa.sa_handler = SIG_DFL;
			install = true;
		} else if(i >= SIGCANCEL && i < SIGCANCEL + 3) {
			sa.sa_handler = SIG_IGN;
			install = true;
		} else {
			if(sigaction(i, nullptr, &sa))
				continue;
			if(sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN)
				continue;
			sa.sa_handler = SIG_DFL;
			install = true;
		}
		if(!install)
			continue;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sigaction(i, &sa, nullptr);
	}

	if(attr->__flags & POSIX_SPAWN_SETSID) {
		if((ret = setsid()) < 0) {
			ret = errno ? errno : EIO;
			goto fail;
		}
	}

	if(attr->__flags & POSIX_SPAWN_SETPGROUP) {
		if((ret = setpgid(0, attr->__pgrp)) < 0) {
			ret = errno ? errno : EIO;
			goto fail;
		}
	}

	if(attr->__flags & (POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER)) {
		ret = ENOTSUP;
		goto fail;
	}

	if(attr->__flags & POSIX_SPAWN_RESETIDS) {
		if((ret = setgid(getgid())) < 0) {
			ret = errno ? errno : EIO;
			goto fail;
		}
		if((ret = setuid(getuid())) < 0) {
			ret = errno ? errno : EIO;
			goto fail;
		}
	}

	if(fa && fa->__actions) {
		struct fdop *op;
		int fd;
		for(op = (struct fdop *)fa->__actions; op->next; op = op->next);
		for(; op; op = op->prev) {
			/* It's possible that a file operation would clobber
			 * the pipe fd used for synchronizing with the
			 * parent. To avoid that, we dup the pipe onto
			 * an unoccupied fd. */
				if(op->fd == p) {
					ret = dup(p);
					if(ret < 0) {
						ret = errno ? errno : EIO;
						goto fail;
					}
					close(p);
					p = ret;
				}
				switch(op->cmd) {
				case FDOP_CLOSE:
				close(op->fd);
				break;
				case FDOP_DUP2:
					fd = op->srcfd;
					if(fd == p) {
						ret = EBADF;
						goto fail;
					}
					if(fd != op->fd) {
						if((ret = dup2(fd, op->fd)) < 0) {
							ret = errno ? errno : EIO;
							goto fail;
						}
					} else {
						ret = fcntl(fd, F_GETFD);
						if(ret < 0) {
							ret = errno ? errno : EIO;
							goto fail;
						}
						ret = fcntl(fd, F_SETFD, ret & ~FD_CLOEXEC);
						if(ret < 0) {
							ret = errno ? errno : EIO;
							goto fail;
						}
					}
					break;
				case FDOP_OPEN:
					fd = open(op->path, op->oflag, op->mode);
					if((ret = fd) < 0) {
						ret = errno ? errno : EIO;
						goto fail;
					}
					if(fd != op->fd) {
						if((ret = dup2(fd, op->fd)) < 0) {
							ret = errno ? errno : EIO;
							goto fail;
						}
						close(fd);
					}
					break;
				case FDOP_CHDIR:
					ret = chdir(op->path);
					if(ret < 0) {
						ret = errno ? errno : EIO;
						goto fail;
					}
					break;
				case FDOP_FCHDIR:
					ret = fchdir(op->fd);
					if(ret < 0) {
						ret = errno ? errno : EIO;
						goto fail;
					}
					break;
				}
			}
		}

	/* Close-on-exec flag may have been lost if we moved the pipe
	 * to a different fd. */
	fcntl(p, F_SETFD, FD_CLOEXEC);

	pthread_sigmask(SIG_SETMASK, (attr->__flags & POSIX_SPAWN_SETSIGMASK)
		? &attr->__mask : &args->oldmask, nullptr);

	if(use_execvpe)
		execvpe(args->path, args->argv, args->envp);
	else
		execve(args->path, args->argv, args->envp);
	ret = errno ? errno : EIO;

fail:
	/* Since sizeof errno < PIPE_BUF, the write is atomic. */
	if(ret)
		while(write(p, &ret, sizeof ret) < 0);
	_exit(127);
}

int posix_spawn(pid_t *__restrict res, const char *__restrict path,
		const posix_spawn_file_actions_t *file_actions,
		const posix_spawnattr_t *__restrict attrs,
		char *const argv[], char *const envp[]) {
	pid_t pid;
	int ec = 0, cs;
	struct args args;
	const posix_spawnattr_t empty_attr = {};
	sigset_t full_sigset;
	sigfillset(&full_sigset);

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);

	args.path = path;
	args.fa = file_actions;
	args.attr = attrs ? attrs : &empty_attr;
	args.argv = argv;
	args.envp = envp;
	pthread_sigmask(SIG_BLOCK, &full_sigset, &args.oldmask);

	if(args.attr->__flags & (POSIX_SPAWN_SETSCHEDPARAM | POSIX_SPAWN_SETSCHEDULER)) {
		ec = ENOTSUP;
		goto fail;
	}

	/* The lock guards both against seeing a SIGABRT disposition change
	 * by abort and against leaking the pipe fd to fork-without-exec. */
	//LOCK(__abort_lock);

	if(pipe2(args.p, O_CLOEXEC)) {
		//UNLOCK(__abort_lock);
		ec = errno;
		goto fail;
	}

	/* Mlibc change: We use fork + execve, as clone is not implemented.
	 * This yields the same result in the end. */
	//pid = clone(child, stack + sizeof stack, CLONE_VM | CLONE_VFORK | SIGCHLD, &args);
	pid = fork();
	if(!pid) {
		child(&args);
	}
	close(args.p[1]);
	//UNLOCK(__abort_lock);

	if(pid > 0) {
		ssize_t read_status;
		do {
			read_status = read(args.p[0], &ec, sizeof ec);
		} while(read_status < 0 && errno == EINTR);

		if(read_status == 0) {
			ec = 0;
		} else if(read_status == sizeof ec) {
			while(waitpid(pid, nullptr, 0) < 0) {
				if(errno != EINTR)
					break;
			}
		} else if(read_status < 0) {
			ec = errno ? errno : EIO;
		} else {
			ec = EIO;
			while(waitpid(pid, nullptr, 0) < 0) {
				if(errno != EINTR)
					break;
			}
		}
	} else {
		ec = errno ? errno : EAGAIN;
	}

	close(args.p[0]);

	if(!ec && res)
		*res = pid;

fail:
	pthread_sigmask(SIG_SETMASK, &args.oldmask, nullptr);
	pthread_setcancelstate(cs, nullptr);

	return ec;
}

int posix_spawnattr_init(posix_spawnattr_t *attr) {
	*attr = (posix_spawnattr_t){};
	return 0;
}

int posix_spawnattr_destroy(posix_spawnattr_t *) {
	return 0;
}

int posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags) {
	const unsigned all_flags = 
			POSIX_SPAWN_RESETIDS |
			POSIX_SPAWN_SETPGROUP |
			POSIX_SPAWN_SETSIGDEF |
			POSIX_SPAWN_SETSIGMASK |
			POSIX_SPAWN_SETSCHEDPARAM |
			POSIX_SPAWN_SETSCHEDULER |
			POSIX_SPAWN_USEVFORK |
			POSIX_SPAWN_SETSID;
	if(flags & ~all_flags)
		return EINVAL;
	attr->__flags = flags;
	return 0;
}

int posix_spawnattr_setsigdefault(posix_spawnattr_t *__restrict attr,
		const sigset_t *__restrict sigdefault) {
	attr->__def = *sigdefault;
	return 0;
}

int posix_spawnattr_setschedparam(posix_spawnattr_t *__restrict,
		const struct sched_param *__restrict) {
	return ENOTSUP;
}

int posix_spawnattr_setschedpolicy(posix_spawnattr_t *, int) {
	return ENOTSUP;
}

int posix_spawnattr_setsigmask(posix_spawnattr_t *__restrict attr,
		const sigset_t *__restrict sigmask) {
	attr->__mask = *sigmask;
	return 0;
}

int posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup) {
	attr->__pgrp = pgroup;
	return 0;
}

int posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions) {
	file_actions->__actions = nullptr;
	return 0;
}

int posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *file_actions) {
	struct fdop *op = (struct fdop *)file_actions->__actions, *next;
	while(op) {
		next = op->next;
		free(op);
		op = next;
	}
	return 0;
}

int posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *file_actions,
		int fildes, int newfildes) {
	struct fdop *op = (struct fdop *)malloc(sizeof *op);
	if(!op)
		return ENOMEM;
	op->cmd = FDOP_DUP2;
	op->srcfd = fildes;
	op->fd = newfildes;
	if((op->next = (struct fdop *)file_actions->__actions))
		op->next->prev = op;
	op->prev = nullptr;
	file_actions->__actions = op;
	return 0;
}

int posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *file_actions,
		int fildes) {
	struct fdop *op = (struct fdop *)malloc(sizeof *op);
	if(!op)
		return ENOMEM;
	op->cmd = FDOP_CLOSE;
	op->fd = fildes;
	if((op->next = (struct fdop *)file_actions->__actions))
		op->next->prev = op;
	op->prev = nullptr;
	file_actions->__actions = op;
	return 0;
}

int posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *__restrict file_actions,
		int fildes, const char *__restrict path, int oflag, mode_t mode) {
	struct fdop *op = (struct fdop *)malloc(sizeof *op + strlen(path) + 1);
	if(!op)
		return ENOMEM;
	op->cmd = FDOP_OPEN;
	op->fd = fildes;
	op->oflag = oflag;
	op->mode = mode;
	strcpy(op->path, path);
	if((op->next = (struct fdop *)file_actions->__actions))
		op->next->prev = op;
	op->prev = nullptr;
	file_actions->__actions = op;
	return 0;
}

int posix_spawnp(pid_t *__restrict pid, const char *__restrict file,
		const posix_spawn_file_actions_t *file_actions,
		const posix_spawnattr_t *__restrict attrp,
		char *const argv[], char *const envp[]) {
	posix_spawnattr_t spawnp_attr = {};
	if(attrp)
		spawnp_attr = *attrp;
	spawnp_attr.__fn = (void *)execvpe;	
	return posix_spawn(pid, file, file_actions, &spawnp_attr, argv, envp);
}

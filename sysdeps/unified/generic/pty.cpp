#include <unified/ioctl.h>

#include <errno.h>

#include <bits/ensure.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>

#include <stdio.h>

namespace mlibc {

int Sysdeps<Isatty>::operator()(int fd) {
	struct winsize ws;
	long ret = Sysdeps<Ioctl>::operator()(fd, TIOCGWINSZ, &ws, 0);

	if(!ret) return 0;

	return ENOTTY;
}

int Sysdeps<Tcgetattr>::operator()(int fd, struct termios *attr) {
	if(int e = Sysdeps<Isatty>::operator()(fd))
		return e;

	int ret;
	Sysdeps<Ioctl>::operator()(fd, TCGETS, attr, &ret);

	if(ret)
		return -ret;

	return 0;
}

int Sysdeps<Tcsetattr>::operator()(int fd, int optional_action, const struct termios *attr) {
	if(int e = Sysdeps<Isatty>::operator()(fd))
		return e;

    int cmd;
    switch (optional_action) {
    case TCSANOW:
        cmd = TCSETS;
        break;
    case TCSADRAIN:
        cmd = TCSETSW;
        break;
    case TCSAFLUSH:
        cmd = TCSETSF;
        break;
    default:
        return EINVAL;
    }
    int ret;
    Sysdeps<Ioctl>::operator()(fd, cmd, const_cast<struct termios *>(attr), &ret);

	if(ret)
		return -ret;

	return 0;
}

int Sysdeps<Ptsname>::operator()(int fd, char *buffer, size_t length) {
	int index = 0;
	int result = 0;
	if(int e = Sysdeps<Ioctl>::operator()(fd, TIOCGPTN, nullptr, &result); e)
		return e;
	index = result;
	if((size_t)snprintf(buffer, length, "/dev/pts/%d", index) >= length) {
		return ERANGE;
	}
	return 0;
}

int Sysdeps<Unlockpt>::operator()(int fd) {
	int unlock = 0;

	if (int e = Sysdeps<Ioctl>::operator()(fd, TIOCSPTLCK, &unlock, NULL); e)
		return e;

	return 0;
}
}
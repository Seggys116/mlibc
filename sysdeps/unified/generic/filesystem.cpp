#include <unified/syscall.h>

#include <asm/ioctls.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#if __MLIBC_LINUX_OPTION
#include <sys/statfs.h>
#endif
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>

#include <bits/ensure.h>
#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>

namespace mlibc{

typedef struct {
	dev_t st_dev;
	ino_t st_ino;
	mode_t st_mode;
	nlink_t st_nlink;
	uid_t st_uid;
	gid_t st_gid;
	dev_t st_rdev;
	off_t st_size;
	int64_t st_blksize;
	int64_t st_blocks;
	int64_t st_atime_sec;
	int64_t st_atime_nsec;
	int64_t st_mtime_sec;
	int64_t st_mtime_nsec;
	int64_t st_ctime_sec;
	int64_t st_ctime_nsec;
} unified_stat_t;

int Sysdeps<Write>::operator()(int fd, const void* buffer, size_t count, ssize_t* written){
	long ret = syscall(SYS_WRITE, fd, (uintptr_t)buffer, count);

	if(ret < 0)
		return -ret;

	*written = ret;
	return 0;
}

int Sysdeps<Read>::operator()(int fd, void *buf, size_t count, ssize_t *bytes_read) {
	long ret = syscall(SYS_READ, fd, (uintptr_t)buf, count);

	if(ret < 0){
		*bytes_read = 0;
		return -ret;
	}

	*bytes_read = ret;
	return 0;
}

int Sysdeps<Pwrite>::operator()(int fd, const void* buffer, size_t count, off_t off, ssize_t* written){
	int ret = syscall(SYS_PWRITE, fd, (uintptr_t)buffer, count, off);


	if(ret < 0){
		return -ret;
	}

	*written = ret;
	return 0;
}

int Sysdeps<Pread>::operator()(int fd, void *buf, size_t count, off_t off, ssize_t *bytes_read) {
	int ret = syscall(SYS_PREAD, fd, (uintptr_t)buf, count, off);

	if(ret < 0){
		return -ret;
	}

	*bytes_read = ret;
	return 0;
}

int Sysdeps<Seek>::operator()(int fd, off_t offset, int whence, off_t *new_offset) {
	long ret = syscall(SYS_LSEEK, fd, offset, whence);

	if(ret < 0){
		return -ret;
	}

	*new_offset = ret;
	return 0;
}


int Sysdeps<Open>::operator()(const char* filename, int flags, mode_t mode, int* fd){
	long ret = syscall(SYS_OPEN, (uintptr_t)filename, flags, mode);

	if(ret < 0)
		return -ret;

	*fd = ret;

	return 0;
}

int Sysdeps<Openat>::operator()(int dirfd, const char* path, int flags, mode_t mode, int *fd) {
    long ret = syscall(SYS_OPENAT, dirfd, (uintptr_t)path, flags, mode);
    if (ret < 0)
        return -ret;
    *fd = ret;
    return 0;
}

int Sysdeps<Close>::operator()(int fd){
	long ret = syscall(SYS_CLOSE, fd);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Access>::operator()(const char* filename, int mode){
	int fd;
	if(int e = Sysdeps<Open>::operator()(filename, O_RDONLY, 0, &fd)){
		return e;
	}

	Sysdeps<Close>::operator()(fd);
	return 0;
}

int Sysdeps<Stat>::operator()(fsfd_target fsfdt, int fd, const char *path, int flags, struct stat *statbuf){
	long ret = 0;

	unified_stat_t unifiedStat;
	switch(fsfdt){
		case fsfd_target::fd:
			ret = syscall(SYS_FSTAT, &unifiedStat, fd);
			break;
		case fsfd_target::path:
			if (flags & AT_SYMLINK_NOFOLLOW)
				ret = syscall(SYS_LSTAT, &unifiedStat, path);
			else
				ret = syscall(SYS_STAT, &unifiedStat, path);
			break;
		case fsfd_target::fd_path:
			ret = syscall(SYS_FSTATAT, fd, (uintptr_t)path, (uintptr_t)&unifiedStat, flags);
			break;
		default:
			mlibc::infoLogger() << "mlibc: stat: Unknown fsfd_target: " << (int)fsfdt << frg::endlog;
			return ENOSYS;
	}

	if (ret < 0) {
		return -ret;
	}

	memset(statbuf, 0, sizeof(struct stat));
	statbuf->st_dev = unifiedStat.st_dev;
	statbuf->st_ino = unifiedStat.st_ino;
	statbuf->st_mode = unifiedStat.st_mode;
	statbuf->st_nlink = unifiedStat.st_nlink;
	statbuf->st_uid = unifiedStat.st_uid;
	statbuf->st_gid = unifiedStat.st_gid;
	statbuf->st_rdev = unifiedStat.st_rdev;
	statbuf->st_size = unifiedStat.st_size;
	statbuf->st_blksize = unifiedStat.st_blksize;
	statbuf->st_blocks = unifiedStat.st_blocks;
	statbuf->st_atim.tv_sec = unifiedStat.st_atime_sec;
	statbuf->st_atim.tv_nsec = unifiedStat.st_atime_nsec;
	statbuf->st_mtim.tv_sec = unifiedStat.st_mtime_sec;
	statbuf->st_mtim.tv_nsec = unifiedStat.st_mtime_nsec;
	statbuf->st_ctim.tv_sec = unifiedStat.st_ctime_sec;
	statbuf->st_ctim.tv_nsec = unifiedStat.st_ctime_nsec;

	// Some filesystems report 0 for directory size; provide a standard
	// directory size so long-format ls output is more useful.
	if(S_ISDIR(statbuf->st_mode) && statbuf->st_size == 0)
		statbuf->st_size = 4096;

	if(statbuf->st_blksize == 0)
		statbuf->st_blksize = 4096;
	if(statbuf->st_blocks == 0 && statbuf->st_size > 0)
		statbuf->st_blocks = (statbuf->st_size + 511) / 512;

	return 0;
}

#if __MLIBC_LINUX_OPTION
int Sysdeps<Statx>::operator()(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf) {
	if(!statxbuf)
		return EFAULT;

	if(flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT
			| AT_STATX_SYNC_AS_STAT | AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC))
		return EINVAL;

	if(!(flags & AT_EMPTY_PATH) && (!pathname || !pathname[0]))
		return ENOENT;

	struct stat statbuf_storage;
	auto stat_flags = flags & (AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);
	int e = 0;

	if((flags & AT_EMPTY_PATH) && (!pathname || !pathname[0])) {
		e = mlibc::Sysdeps<Stat>::operator()(fsfd_target::fd, dirfd, nullptr, 0, &statbuf_storage);
	}else if(dirfd == AT_FDCWD) {
		e = mlibc::Sysdeps<Stat>::operator()(fsfd_target::path, 0, pathname, stat_flags, &statbuf_storage);
	}else{
		e = mlibc::Sysdeps<Stat>::operator()(fsfd_target::fd_path, dirfd, pathname, stat_flags, &statbuf_storage);
	}

	if(e)
		return e;

	memset(statxbuf, 0, sizeof(struct statx));
	statxbuf->stx_blksize = statbuf_storage.st_blksize;
	statxbuf->stx_blocks = statbuf_storage.st_blocks;
	statxbuf->stx_gid = statbuf_storage.st_gid;
	statxbuf->stx_ino = statbuf_storage.st_ino;
	statxbuf->stx_mode = statbuf_storage.st_mode;
	statxbuf->stx_nlink = statbuf_storage.st_nlink;
	statxbuf->stx_size = statbuf_storage.st_size;
	statxbuf->stx_uid = statbuf_storage.st_uid;

	statxbuf->stx_atime.tv_sec = statbuf_storage.st_atim.tv_sec;
	statxbuf->stx_atime.tv_nsec = statbuf_storage.st_atim.tv_nsec;
	statxbuf->stx_btime.tv_sec = statbuf_storage.st_mtim.tv_sec;
	statxbuf->stx_btime.tv_nsec = statbuf_storage.st_mtim.tv_nsec;
	statxbuf->stx_ctime.tv_sec = statbuf_storage.st_ctim.tv_sec;
	statxbuf->stx_ctime.tv_nsec = statbuf_storage.st_ctim.tv_nsec;
	statxbuf->stx_mtime.tv_sec = statbuf_storage.st_mtim.tv_sec;
	statxbuf->stx_mtime.tv_nsec = statbuf_storage.st_mtim.tv_nsec;

	statxbuf->stx_rdev_major = major(statbuf_storage.st_rdev);
	statxbuf->stx_rdev_minor = minor(statbuf_storage.st_rdev);
	statxbuf->stx_dev_major = major(statbuf_storage.st_dev);
	statxbuf->stx_dev_minor = minor(statbuf_storage.st_dev);

	(void)mask;
	statxbuf->stx_mask = STATX_BASIC_STATS | STATX_BTIME;
	return 0;
}
#endif

int Sysdeps<Ioctl>::operator()(int fd, unsigned long request, void *arg, int *result){
	long ret = syscall(SYS_IOCTL, fd, request, arg, result);

	if(ret < 0)
		return -ret;

	return 0;
}

#ifndef MLIBC_BUILDING_RTLD

int Sysdeps<Poll>::operator()(struct pollfd *fds, nfds_t count, int timeout, int *num_events){
	long ret = syscall(SYS_POLL, fds, count, timeout);

	if(ret < 0){
		return -ret;
	}

	*num_events = ret;

	return 0;
}

int Sysdeps<Mkdir>::operator()(const char* path, mode_t){
	long ret = syscall(SYS_MKDIR, path);
	if(ret < 0){
		return -ret;
	}
	return 0;
}

int Sysdeps<Mkdirat>::operator()(int dirfd, const char *path, mode_t mode)
{
    long ret = syscall(SYS_MKDIRAT, dirfd, (uintptr_t)path, mode);
    if (ret < 0)
        return -ret;
    return 0;
}

int Sysdeps<Sendfile>::operator()(int out_fd, int in_fd, off_t *offset, size_t count, ssize_t *bytes_sent) {
    long ret = syscall(SYS_SENDFILE, out_fd, in_fd, (uintptr_t)offset, count);
    if (ret < 0) {
        return (int)(-ret);
    }
    *bytes_sent = ret;
    return 0;
}

int Sysdeps<CopyFileRange>::operator()(int fd_in, off_t *off_in, int fd_out, off_t *off_out, size_t len, unsigned flags, ssize_t *bytes_copied) {
    long ret = syscall(SYS_COPY_FILE_RANGE,
                       fd_in,
                       (uintptr_t)off_in,
                       fd_out,
                       (uintptr_t)off_out,
                       len,
                       flags);
    if (ret < 0) {
        return (int)(-ret);
    }
    *bytes_copied = ret;
    return 0;
}

int Sysdeps<Rmdir>::operator()(const char* path){
	long ret = syscall(SYS_RMDIR, path);

	if(ret < 0){
		return -ret;
	}

	return 0;
}

int Sysdeps<Link>::operator()(const char* srcpath, const char* destpath){
	long ret = syscall(SYS_LINK, srcpath, destpath);

	if(ret < 0){
		return -ret;
	}

	return 0;
}

int Sysdeps<Unlinkat>::operator()(int fd, const char *path, int flags) {
	long ret = syscall(SYS_UNLINK, fd, path, flags);

	if(ret < 0) {
		return -ret;
	}

	return 0;
}

int Sysdeps<OpenDir>::operator()(const char* path, int* handle){
	return Sysdeps<Open>::operator()(path, O_DIRECTORY, 0, handle);
}

int Sysdeps<Rename>::operator()(const char* path, const char* new_path){
	long ret = syscall(SYS_RENAME, path, new_path);
	if(ret < 0){
		return -ret;
	}
	return 0;
}

int Sysdeps<Renameat>::operator()(int olddirfd, const char *old_path, int newdirfd, const char *new_path) {
	long ret = syscall(SYS_RENAME_AT, olddirfd, old_path, newdirfd, new_path);
	if(ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Readlink>::operator()(const char *path, void *buffer, size_t max_size, ssize_t *length){
	long ret = syscall(SYS_READLINK, path, buffer, max_size);
	if(ret < 0){
		return -ret;
	}

	*length = ret;
	return 0;
}

int Sysdeps<Dup>::operator()(int fd, int flags, int* newfd){
	int ret = syscall(SYS_DUP, fd, flags, -1);
	if(ret < 0){
		return -ret;
	}

	*newfd = ret;
	return 0;
}

int Sysdeps<Dup2>::operator()(int fd, int flags, int newfd){
	int ret = syscall(SYS_DUP, fd, flags, newfd);
	if(ret < 0){
		return -ret;
	}

	return 0;
}

typedef struct unified_dirent {
	ino_t inode; // Inode number
	uint32_t type;
	char name[NAME_MAX]; // Filename
} unified_dirent_t;

int Sysdeps<ReadEntries>::operator()(int handle, void *buffer, size_t max_size, size_t *bytes_read) {
    size_t total_bytes = 0;
    char *out_buf = reinterpret_cast<char *>(buffer);

    // Read entries until buffer is full or no more entries.
    while (true) {
        // Check if there's enough space for at least one struct dirent
        if (max_size - total_bytes < sizeof(struct dirent))
            break;

        unified_dirent_t unifiedDirent;
        long ret = syscall(SYS_READDIR_NEXT, handle, &unifiedDirent);

        // If no more entries (ret == 0) or end-of-directory error (ret == -ENOENT), exit loop.
        if (ret <= 0) {
            if (ret < 0 && ret != -ENOENT) {
                return -ret; // Propagate any error aside from EOF
            }
            break; // EOF or no entry
        }
        // ret > 0: one entry read successfully
        struct dirent *dir = reinterpret_cast<struct dirent *>(out_buf + total_bytes);

        // Copy fields from unified_dirent_t to struct dirent
        dir->d_ino = unifiedDirent.inode;
        dir->d_off = 0; // Offset not used
        dir->d_reclen = sizeof(struct dirent);
        dir->d_type = unifiedDirent.type;
        // Copy name safely, ensuring null-termination
        strncpy(dir->d_name, unifiedDirent.name, NAME_MAX - 1);
        dir->d_name[NAME_MAX - 1] = '\0';

        total_bytes += sizeof(struct dirent);
    }

    *bytes_read = total_bytes;
    return 0;
}

int Sysdeps<Mount>::operator()(const char *source, const char *target, const char *fstype, unsigned long flags, const void *data)
{
    long ret = syscall(SYS_MOUNT,
                       (uintptr_t)source,
                       (uintptr_t)target,
                       (uintptr_t)fstype,
                       flags,
                       (uintptr_t)data);
    if (ret < 0) {
        return -ret;   // return positive errno
    }
    return 0;
}

int Sysdeps<Umount2>::operator()(const char *target, int flags) {
	long ret = syscall(SYS_UNMOUNT, target, flags);
	if (ret < 0) {
        return -ret;   // return positive errno
    }
	return 0;
}

int Sysdeps<Fcntl>::operator()(int fd, int request, va_list args, int* result){
	if(request == F_DUPFD){
		int minfd = va_arg(args, int);
		int ret = syscall(SYS_FCNTL, fd, F_DUPFD, minfd);
		if (ret < 0) return -ret;
		*result = ret;
		return 0;
	} else if (request == F_DUPFD_CLOEXEC) {
		int minfd = va_arg(args, int);
		int ret = syscall(SYS_FCNTL, fd, F_DUPFD_CLOEXEC, minfd);
		if (ret < 0) return -ret;
		*result = ret;
		return 0;
	} else if(request == F_GETFD){
		int ret = syscall(SYS_FCNTL, fd, F_GETFD);
		if (ret < 0) return -ret;
		*result = ret;
		return 0;
	} else if(request == F_SETFD){
		if(va_arg(args, int) & FD_CLOEXEC) {
			return Sysdeps<Ioctl>::operator()(fd, FIOCLEX, NULL, result);
		} else {
			return Sysdeps<Ioctl>::operator()(fd, FIONCLEX, NULL, result);
		}
	} else if(request == F_GETFL){
		int ret = syscall(SYS_GET_FILE_STATUS_FLAGS, fd);
		if(ret < 0){
			return -ret;
		}

		*result = ret;
		return 0;
	} else if(request == F_SETFL){
		int ret = syscall(SYS_SET_FILE_STATUS_FLAGS, fd, va_arg(args, int));
		if (ret < 0) return -ret;
		*result = 0;
		return 0;
	} else if(request == F_GETPIPE_SZ) {
		// Return a default pipe buffer size (64 KiB)
		*result = 65536;
		return 0;
	} else if(request == F_SETPIPE_SZ) {
		// Ignore attempts to change pipe size; return the current size
		int newSize = va_arg(args, int);
		(void)newSize;
		*result = 65536;
		return 0;
	} else if(request == F_GET_SEALS) {
		int ret = syscall(SYS_FCNTL, fd, F_GET_SEALS, 0);
		if(ret < 0)
			return -ret;
		*result = ret;
		return 0;
	} else {
		// Forward other requests to the kernel.
		// Guard vararg reads for known no-arg requests.
		unsigned long arg = 0;
		bool hasArg = true;
		switch(request) {
#ifdef F_GETOWN
			case F_GETOWN:
#endif
#ifdef F_GETSIG
			case F_GETSIG:
#endif
#ifdef F_GETLEASE
			case F_GETLEASE:
#endif
				hasArg = false;
				break;
			default:
				break;
		}
		if(hasArg)
			arg = va_arg(args, unsigned long);

		int ret = syscall(SYS_FCNTL, fd, request, arg);
		if(ret < 0)
			return -ret;
		*result = ret;
		return 0;
	}
}

int Sysdeps<Pselect>::operator()(int nfds, fd_set* readfds, fd_set* writefds,
	fd_set *exceptfds, const struct timespec* timeout, const sigset_t* sigmask, int *num_events){
	int ret = syscall(SYS_SELECT, nfds, readfds, writefds, exceptfds, timeout, sigmask);
	if(ret < 0){
		return -ret;
	}

	*num_events = ret;
	return 0;
}

int Sysdeps<Symlink>::operator()(const char *target, const char *linkpath) {
	long ret = syscall(SYS_SYMLINK, (uintptr_t)target, (uintptr_t)linkpath);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<Fchmod>::operator()(int fd, mode_t mode) {
	long ret = syscall(SYS_FCHMOD, fd, mode);
	if (ret < 0)
		return -ret;
	return 0;
}

int Sysdeps<Chmod>::operator()(const char *pathname, mode_t mode){
	int ret = syscall(SYS_CHMOD, pathname, mode);

	if(ret < 0){
		return -ret;
	}

	return 0;
}

int Sysdeps<Pipe>::operator()(int *fds, int flags){
	long ret = syscall(SYS_PIPE, fds, flags);
	if(ret < 0){
		return -ret;
	}
	return 0;
}

int Sysdeps<EpollCreate>::operator()(int flags, int *fd) {
	int ret = syscall(SYS_EPOLL_CREATE, flags);

	if(ret < 0){
		return -ret;
	}

	*fd = ret;

	return 0;
}

int Sysdeps<EpollCtl>::operator()(int epfd, int mode, int fd, struct epoll_event *ev) {
	int ret = syscall(SYS_EPOLL_CTL, epfd, mode, fd, ev);

	if(ret < 0) {
		return -ret;
	}

	return 0;
}

int Sysdeps<EpollPwait>::operator()(int epfd, struct epoll_event *ev, int n,
		int timeout, const sigset_t *sigmask, int *raised) {
	int ret = syscall(SYS_EPOLL_WAIT, epfd, ev, n, timeout, sigmask);

	if(ret < 0) {
		return -ret;
	}

	*raised = ret;

	return 0;
}

int Sysdeps<Ttyname>::operator()(int tty, char *buf, size_t size) {
	char path[PATH_MAX] = {"/dev/pts/"};

	struct stat stat;
	if(int e = Sysdeps<Stat>::operator()(fsfd_target::fd, tty, nullptr, 0, &stat)) {
		return e;
	}

	if(!S_ISCHR(stat.st_mode)) {
		return ENOTTY; // Not a char device, isn't a tty
	}

	if(Sysdeps<Isatty>::operator()(tty)) {
		return ENOTTY;
	}

	// Look for tty in /dev/pts
	int ptDir = open("/dev/pts", O_DIRECTORY);
	__ensure(ptDir >= 0);

	struct dirent dirent;
	size_t direntBytesRead;
	while(!Sysdeps<ReadEntries>::operator()(ptDir, &dirent, sizeof(dirent), &direntBytesRead) && direntBytesRead) {
		// Compare the inodes
		if(dirent.d_ino == stat.st_ino) {
			__ensure(strlen(path) + strlen(dirent.d_name) < PATH_MAX);
			strcat(path, dirent.d_name);

			strncpy(buf, path, size);
			return 0;
		}
	}

	// Could not find corresponding TTY in /dev/pts
	return ENODEV;
}

int Sysdeps<Fchdir>::operator()(int fd) {
	long ret = syscall(SYS_FCHDIR, fd);
	if (ret < 0) {
		return -ret;
	}
	return 0;
}

int Sysdeps<Fsync>::operator()(int fd)
{
    long ret = syscall(SYS_FSYNC, fd);
    if (ret < 0) {
        return -ret;   // return positive errno
    }
    return 0;
}

int Sysdeps<Fdatasync>::operator()(int fd)
{
    long ret = syscall(SYS_FDATASYNC, fd);
    if (ret == -ENOSYS) {
        // fdatasync() is a weaker durability contract than fsync();
        // using fsync as a fallback is safe on older kernels.
        ret = syscall(SYS_FSYNC, fd);
    }
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

void Sysdeps<Sync>::operator()()
{
    syscall(SYS_SYNC);
}

int Sysdeps<Fallocate>::operator()(int fd, off_t offset, size_t size)
{
    long ret = syscall(SYS_FALLOCATE, fd, offset, size);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Flock>::operator()(int fd, int options)
{
    long ret = syscall(SYS_FLOCK, fd, options);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Fadvise>::operator()(int fd, off_t offset, off_t length, int advice)
{
    long ret = syscall(SYS_FADVISE, fd, offset, length, advice);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Ftruncate>::operator()(int fd, size_t size)
{
    long ret = syscall(SYS_FTRUNCATE, fd, size);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Truncate>::operator()(const char *path, off_t size)
{
    long ret = syscall(SYS_TRUNCATE, path, size);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Readv>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_read)
{
    long ret = syscall(SYS_READV, fd, iovs, iovc);
    if (ret < 0) {
        return -ret;
    }
    *bytes_read = ret;
    return 0;
}

int Sysdeps<Writev>::operator()(int fd, const struct iovec *iovs, int iovc, ssize_t *bytes_written)
{
    long ret = syscall(SYS_WRITEV, fd, iovs, iovc);
    if (ret < 0) {
        return -ret;
    }
    *bytes_written = ret;
    return 0;
}

int Sysdeps<Faccessat>::operator()(int dirfd, const char *pathname, int mode, int flags)
{
    long ret = syscall(SYS_FACCESSAT, dirfd, pathname, mode, flags);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Statvfs>::operator()(const char *path, struct statvfs *out)
{
    long ret = syscall(SYS_STATVFS, path, out);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Fstatvfs>::operator()(int fd, struct statvfs *out)
{
    long ret = syscall(SYS_FSTATVFS, fd, out);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

#if __MLIBC_LINUX_OPTION
static void statvfs_to_statfs(const struct statvfs *from, struct statfs *to)
{
    memset(to, 0, sizeof(*to));
    to->f_type = 0;
    to->f_bsize = from->f_bsize;
    to->f_blocks = from->f_blocks;
    to->f_bfree = from->f_bfree;
    to->f_bavail = from->f_bavail;
    to->f_files = from->f_files;
    to->f_ffree = from->f_ffree;
    to->f_fsid.__val[0] = (int)from->f_fsid;
    to->f_fsid.__val[1] = (int)(from->f_fsid >> (sizeof(int) * 8));
    to->f_namelen = from->f_namemax;
    to->f_frsize = from->f_frsize;
    to->f_flags = from->f_flag;
}

int Sysdeps<Statfs>::operator()(const char *path, struct statfs *buf)
{
    struct statvfs vfs;
    int e = Sysdeps<Statvfs>::operator()(path, &vfs);
    if (e)
        return e;
    statvfs_to_statfs(&vfs, buf);
    return 0;
}

int Sysdeps<Fstatfs>::operator()(int fd, struct statfs *buf)
{
    struct statvfs vfs;
    int e = Sysdeps<Fstatvfs>::operator()(fd, &vfs);
    if (e)
        return e;
    statvfs_to_statfs(&vfs, buf);
    return 0;
}
#endif

int Sysdeps<Fchmodat>::operator()(int dirfd, const char *pathname, mode_t mode, int flags)
{
    long ret = syscall(SYS_FCHMODAT, dirfd, pathname, mode, flags);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Fchownat>::operator()(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{
    long ret = syscall(SYS_FCHOWNAT, dirfd, pathname, owner, group, flags);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Linkat>::operator()(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{
    long ret = syscall(SYS_LINKAT, olddirfd, oldpath, newdirfd, newpath, flags);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Symlinkat>::operator()(const char *target, int newdirfd, const char *linkpath)
{
    long ret = syscall(SYS_SYMLINKAT, target, newdirfd, linkpath);
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

int Sysdeps<Utimensat>::operator()(int dirfd, const char *pathname, const struct timespec times[2], int flags)
{
    long ret = syscalln4(SYS_UTIMENSAT,
                         static_cast<uint64_t>(dirfd),
                         reinterpret_cast<uint64_t>(pathname),
                         reinterpret_cast<uint64_t>(times),
                         static_cast<uint64_t>(flags));
    if (ret < 0) {
        return -ret;
    }
    return 0;
}

#endif

}

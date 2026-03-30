
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <frg/vector.hpp>
#include <mlibc/allocator.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/posix-sysdeps.hpp>
#include <bits/ensure.h>

ssize_t readv(int fd, const struct iovec *iovs, int iovc) {
	ssize_t read_bytes = 0;

	auto sysdep = MLIBC_CHECK_OR_ENOSYS(mlibc::sys_readv, -1);

	if (int e = sysdep(fd, iovs, iovc, &read_bytes); e) {
		errno = e;
		return -1;
	}

	return read_bytes;
}

ssize_t writev(int fd, const struct iovec *iovs, int iovc) {
	__ensure(iovc);

	ssize_t written = 0;

	auto sysdep = mlibc::sys_writev;
	if(sysdep) {
		int e = sysdep(fd, iovs, iovc, &written);
		if(e) {
			errno = e;
			return -1;
		}
		return written;
	}

	// TODO: this implementation is not safe to use in signal contexts
	mlibc::infoLogger() << "mlibc: falling back to signal-unsafe writev implementation!" << frg::endlog;
	size_t bytes = 0;
	for(int i = 0; i < iovc; i++) {
		if(SSIZE_MAX - bytes < iovs[i].iov_len) {
			errno = EINVAL;
			return -1;
		}
		bytes += iovs[i].iov_len;
	}
	frg::vector<char, MemoryAllocator> buffer{getAllocator()};
	buffer.resize(bytes);

	size_t to_copy = bytes;
	char *bp = buffer.data();
	for(int i = 0; i < iovc; i++) {
		size_t copy = frg::min(iovs[i].iov_len, to_copy);

		bp = (char *)memcpy((void *)bp, (void *)iovs[i].iov_base, copy) + copy;

		to_copy -= copy;
		if(to_copy == 0)
			break;
	}

	written = write(fd, buffer.data(), bytes);
	return written;
}

ssize_t preadv(int fd, const struct iovec *iovs, int iovc, off_t offset) {
	if(iovc < 0) {
		errno = EINVAL;
		return -1;
	}
	if(iovc == 0)
		return 0;

	ssize_t total_read = 0;
	off_t current = offset;

	for(int i = 0; i < iovc; i++) {
		const auto base = reinterpret_cast<char *>(iovs[i].iov_base);
		size_t len = iovs[i].iov_len;
		if(!len)
			continue;

		ssize_t r = pread(fd, base, len, current);
		if(r < 0) {
			return total_read > 0 ? total_read : -1;
		}
		if(r == 0) {
			return total_read; // EOF
		}

		total_read += r;
		current += r;
		if(static_cast<size_t>(r) < len)
			return total_read; // short read
	}

	return total_read;
}

ssize_t pwritev(int fd, const struct iovec *iovs, int iovc, off_t offset) {
	if(iovc < 0) {
		errno = EINVAL;
		return -1;
	}
	if(iovc == 0)
		return 0;

	ssize_t total_written = 0;
	off_t current = offset;

	for(int i = 0; i < iovc; i++) {
		const auto base = reinterpret_cast<const char *>(iovs[i].iov_base);
		size_t len = iovs[i].iov_len;
		if(!len)
			continue;

		ssize_t w = pwrite(fd, base, len, current);
		if(w < 0) {
			return total_written > 0 ? total_written : -1;
		}
		if(w == 0) {
			return total_written;
		}

		total_written += w;
		current += w;
		if(static_cast<size_t>(w) < len)
			return total_written; // short write
	}

	return total_written;
}

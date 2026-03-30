#include <unified/syscall.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <mlibc/all-sysdeps.hpp>
#include <mlibc/debug.hpp>

namespace {

int fcntl_helper(int fd, int request, int *result, ...) {
	va_list args;
	va_start(args, result);
	if(!mlibc::sys_fcntl) {
		return ENOSYS;
	}
	int ret = mlibc::sys_fcntl(fd, request, args, result);
	va_end(args);
	return ret;
}

}

namespace mlibc{

int sys_socket(int domain, int type, int protocol, int *fd){
    long ret = syscall(SYS_SOCKET, domain, type, protocol);

    if(ret < 0){
        return -ret;
    }

    *fd = ret;
    return 0;
}

int sys_bind(int sockfd, const struct sockaddr *addr_ptr, socklen_t addrlen){
    long ret = syscall(SYS_BIND, sockfd, addr_ptr, addrlen);

    if(ret < 0){
        return -ret;
    }

    return 0;
}

int sys_connect(int sockfd, const struct sockaddr *addr_ptr, socklen_t addrlen){
    long ret = syscall(SYS_CONNECT, sockfd, addr_ptr, addrlen);

    if(ret < 0){
        return -ret;
    }

    return 0;
}

int sys_accept(int fd, int *newfd, struct sockaddr *addr_ptr, socklen_t *addr_length, int flags){
    long ret = syscall(SYS_ACCEPT, fd, addr_ptr, addr_length);

    if(ret < 0){
        return -ret;
    }

    *newfd = ret;

	if(flags & SOCK_NONBLOCK) {
		int fcntl_ret = 0;
		int err = fcntl_helper(*newfd, F_GETFL, &fcntl_ret);
		if(err) {
			mlibc::sys_close(*newfd);
			return err;
		}
		err = fcntl_helper(*newfd, F_SETFL, &fcntl_ret, fcntl_ret | O_NONBLOCK);
		if(err) {
			mlibc::sys_close(*newfd);
			return err;
		}
	}

	if(flags & SOCK_CLOEXEC) {
		int fcntl_ret = 0;
		int err = fcntl_helper(*newfd, F_GETFD, &fcntl_ret);
		if(err) {
			mlibc::sys_close(*newfd);
			return err;
		}
		err = fcntl_helper(*newfd, F_SETFD, &fcntl_ret, fcntl_ret | FD_CLOEXEC);
		if(err) {
			mlibc::sys_close(*newfd);
			return err;
		}
	}

    return 0;
}

int sys_listen(int fd, int backlog){
    long ret = syscall(SYS_LISTEN, fd, backlog);

    if(ret < 0){
        return -ret;
    }

    return 0;
}

int sys_msg_recv(int sockfd, struct msghdr *hdr, int flags, ssize_t *length){
    long ret = syscall(SYS_RECVMSG, sockfd, hdr, flags);

    if(ret < 0){
        return -ret;
    }

    *length = ret;

    return 0;
}

int sys_msg_send(int sockfd, const struct msghdr *hdr, int flags, ssize_t *length){
    long ret = syscall(SYS_SENDMSG, sockfd, hdr, flags);

    if(ret < 0){
        return -ret;
    }

    *length = ret;

    return 0;
}

int sys_setsockopt(int fd, int layer, int number, const void *buffer, socklen_t size){
    long ret = syscall(SYS_SET_SOCKET_OPTIONS, fd, layer, number, buffer, size);

    if(ret < 0){
        return -ret;
    }

    return 0;
}

int sys_getsockopt(int fd, int layer, int number, void *__restrict buffer, socklen_t *__restrict size){
    long ret = syscall(SYS_GET_SOCKET_OPTIONS, fd, layer, number, buffer, size);

    if(ret < 0){
        return -ret;
    }

    return 0;
}

int sys_socketpair(int domain, int type_and_flags, int proto, int *fds){
    long ret = syscall(SYS_SOCKETPAIR, domain, type_and_flags, proto, fds);
    if(ret < 0){
        return -ret;
    }
    return 0;
}

int sys_sockname(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
    socklen_t *actual_length) {
    long ret = syscall(SYS_SOCKNAME, fd, addr_ptr, max_addr_length);
    if (ret < 0) {
        return -ret;
    }
    if (actual_length) {
        switch (addr_ptr->sa_family) {
            case AF_INET:
                *actual_length = sizeof(struct sockaddr_in);
                break;
            case AF_UNIX:
                *actual_length = sizeof(struct sockaddr_un);
                break;
            default:
                *actual_length = max_addr_length;
                break;
        }
    }
    return 0;
}

int sys_peername(int fd, struct sockaddr *addr_ptr, socklen_t max_addr_length,
    socklen_t *actual_length) {
    long ret = syscall(SYS_PEERNAME, fd, addr_ptr, max_addr_length);
    if (ret < 0) {
        return -ret;
    }
    if (actual_length) {
        switch (addr_ptr->sa_family) {
            case AF_INET:
                *actual_length = sizeof(struct sockaddr_in);
                break;
            case AF_UNIX:
                *actual_length = sizeof(struct sockaddr_un);
                break;
            default:
                *actual_length = max_addr_length;
                break;
        }
    }
    return 0;
}

ssize_t sys_sendto(int fd, const void *buffer, size_t size, int flags,
    const struct sockaddr *sock_addr, socklen_t addr_length, ssize_t *length) {
    long ret = syscall(SYS_SENDTO, fd, buffer, size, flags, sock_addr, addr_length);

    if (ret < 0) {
        return -ret;
    }

    *length = ret;
    return 0;
}

ssize_t sys_recvfrom(int fd, void *buffer, size_t size, int flags,
    struct sockaddr *sock_addr, socklen_t *addr_length, ssize_t *length) {
    long ret = syscall(SYS_RECEIVEFROM, fd, buffer, size, flags, sock_addr, addr_length);

    if (ret < 0) {
        return -ret;
    }

    *length = ret;
    return 0;
}

int sys_shutdown(int sockfd, int how) {
    long ret = syscall(SYS_SHUTDOWN, sockfd, how);

    if (ret < 0) {
        return -ret;
    }

    return 0;
}

int sys_inet_configured(bool *ipv4, bool *ipv6) {
    // WORKAROUND: Just return true for IPv4 to bypass interface enumeration
    // This allows curl/wget to proceed with DNS resolution
    mlibc::infoLogger() << "[MLIBC] sys_inet_configured: STUBBED - returning ipv4=true" << frg::endlog;

    if (ipv4) *ipv4 = true;
    if (ipv6) *ipv6 = false;

    return 0;
}

}

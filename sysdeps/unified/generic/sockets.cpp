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

#include "generic-helpers/netlink.hpp"

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

int sys_if_indextoname(unsigned int index, char *name) {
	int fd = 0;
	int r = sys_socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, AF_UNSPEC, &fd);

	if(r)
		return r;

	struct ifreq ifr = {};
	ifr.ifr_ifindex = index;

	int res = 0;
	int ret = sys_ioctl(fd, SIOCGIFNAME, &ifr, &res);
	close(fd);

	if(ret) {
		if(ret == ENODEV)
			return ENXIO;
		return ret;
	}

	strncpy(name, ifr.ifr_name, IF_NAMESIZE);
	name[IF_NAMESIZE - 1] = '\0';
	return 0;
}

int sys_if_nametoindex(const char *name, unsigned int *ret) {
	int fd = 0;
	int r = sys_socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, AF_UNSPEC, &fd);

	if(r)
		return r;

	struct ifreq ifr = {};
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

	int res = 0;
	r = sys_ioctl(fd, SIOCGIFINDEX, &ifr, &res);
	close(fd);

	if(r)
		return r;

	*ret = ifr.ifr_ifindex;
	return 0;
}

int sys_getifaddrs(struct ifaddrs **out) {
	*out = nullptr;

	NetlinkHelper nl;
	bool link_ret = nl.send_request(RTM_GETLINK) && nl.recv(&getifaddrs_callback, out);
	__ensure(link_ret);
	bool addr_ret = nl.send_request(RTM_GETADDR) && nl.recv(&getifaddrs_callback, out);
	__ensure(addr_ret);

	return 0;
}

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
	struct context {
		bool *ipv4;
		bool *ipv6;
	} context = {.ipv4 = ipv4, .ipv6 = ipv6};

	if(ipv4)
		*ipv4 = false;
	if(ipv6)
		*ipv6 = false;

	NetlinkHelper nl;
	if(!nl.send_request(RTM_GETADDR)) {
		return 0;
	}

	auto ret = nl.recv(
		[](void *data, const nlmsghdr *hdr) {
			if(hdr->nlmsg_type == RTM_NEWADDR
					&& hdr->nlmsg_len >= sizeof(struct nlmsghdr) + sizeof(struct ifaddrmsg)) {
				const struct ifaddrmsg *ifaddr =
					reinterpret_cast<const struct ifaddrmsg *>(NLMSG_DATA(hdr));
				struct context *ctx = reinterpret_cast<struct context *>(data);

				char name[IF_NAMESIZE];
				auto interface_name_result = sys_if_indextoname(ifaddr->ifa_index, name);

				if(interface_name_result || !strncmp(name, "lo", IF_NAMESIZE))
					return;

				if(ifaddr->ifa_family == AF_INET && ctx->ipv4)
					*ctx->ipv4 = true;
				else if(ifaddr->ifa_family == AF_INET6 && ctx->ipv6)
					*ctx->ipv6 = true;
			}
		},
		&context
	);

	if(!ret) {
		if(ipv4)
			*ipv4 = false;
		if(ipv6)
			*ipv6 = false;
	}

	return 0;
}

}

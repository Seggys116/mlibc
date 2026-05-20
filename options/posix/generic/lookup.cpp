#include <mlibc/lookup.hpp>
#include <mlibc/resolv_conf.hpp>
#include <mlibc/debug.hpp>
#include <mlibc/services.hpp>
#include <bits/ensure.h>

#include <frg/string.hpp>
#include <mlibc/allocator.hpp>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <poll.h>
#include <frg/scope_exit.hpp>
#include <mlibc/ansi-sysdeps.hpp>
#include <time.h>

namespace mlibc {

namespace {
	constexpr unsigned short RETURN_NOERROR [[maybe_unused]] = 0x0;
	constexpr unsigned short RETURN_NXDOMAIN = 0x3;
	constexpr unsigned short RESPONSE_FLAG_TC = 0x0200;

	constexpr unsigned int RECORD_A = 1;
	constexpr unsigned int RECORD_CNAME = 5;
	constexpr unsigned int RECORD_PTR = 12;
	constexpr unsigned int RECORD_AAAA = 28;
	constexpr size_t DNS_MAX_RESPONSE_SIZE = 512;
	constexpr int DNS_NAME_MAX_DEPTH = 32;
	constexpr int DNS_QUERY_MAX_ATTEMPTS = 3;
	constexpr long DNS_QUERY_TIMEOUT_MS = 5000;

	uint16_t allocate_dns_id() {
		static uint16_t next_dns_id = 0x1200;
		return __atomic_add_fetch(&next_dns_id, 1, __ATOMIC_ACQ_REL);
	}

	int get_poll_timeout(struct timespec *original_time, long timeout_ms) {
		struct timespec current_time;
		if (int e = mlibc::sys_clock_get(CLOCK_MONOTONIC, &current_time.tv_sec, &current_time.tv_nsec); e)
			mlibc::panicLogger() << "mlibc: sys_clock_get() failed with error code: " << e << frg::endlog;

		current_time.tv_sec -= original_time->tv_sec;
		current_time.tv_nsec -= original_time->tv_nsec;
		if (current_time.tv_nsec < 0) {
			--current_time.tv_sec;
			current_time.tv_nsec = 1000000000 + current_time.tv_nsec;
		}

		// poll timeout unit is msec. The timeout is per attempt so retries
		// do not multiply the total DNS lookup delay.
		// TODO resolv.conf can specify a timeout and we ignore it currently.
		return frg::max(timeout_ms - (current_time.tv_sec * 1000 + current_time.tv_nsec / 1000000), 0l);
	}

	static bool read_dns_name_impl(const uint8_t *buf, const uint8_t *end,
			const uint8_t *&it, frg::string<MemoryAllocator> &out, int depth) {
		if (depth > DNS_NAME_MAX_DEPTH)
			return false;

		while (true) {
			if (it >= end)
				return false;

			uint8_t code = *it++;
			if (!code)
				return true;

			if ((code & 0xC0) == 0xC0) {
				if (it >= end)
					return false;

				size_t offset = static_cast<size_t>((code & 0x3F) << 8) | *it++;
				if (offset >= static_cast<size_t>(end - buf))
					return false;

				const uint8_t *offset_it = buf + offset;
				return read_dns_name_impl(buf, end, offset_it, out, depth + 1);
			}

			if (code & 0xC0)
				return false;

			if (it + code > end)
				return false;

			if (out.size())
				out += '.';

			for (uint8_t i = 0; i < code; i++)
				out += static_cast<char>(*it++);
		}
	}

	static bool read_dns_name_safe(const uint8_t *buf, const uint8_t *end,
			const uint8_t *&it, frg::string<MemoryAllocator> &out) {
		return read_dns_name_impl(buf, end, it, out, 0);
	}
} // namespace

int lookup_name_dns(struct lookup_result &buf, const char *name,
		frg::string<MemoryAllocator> &canon_name, int family) {
	frg::string<MemoryAllocator> request{getAllocator()};

	int num_q = 1;
	struct dns_header header;
	header.identification = htons(allocate_dns_id());
	header.flags = htons(0x100);
	header.no_q = htons(num_q);
	header.no_ans = htons(0);
	header.no_auths = htons(0);
	header.no_additional = htons(0);

	request.resize(sizeof(header));
	memcpy(request.data(), &header, sizeof(header));

	const char *end = name;
	while (*end != '\0') {
		end = strchrnul(name, '.');
		size_t length = end - name;
		frg::string_view substring{name, length};
		name += length + 1;
		request += char(length);
		request += substring;
	}

	request += char(0);
	// set question type to fetch A or AAAA records
	uint16_t qtype = RECORD_A;
	if (family == AF_INET6)
		qtype = RECORD_AAAA;

	request += qtype >> 8;
	request += qtype & 0xFF;
	// set CLASS to IN
	request += 0;
	request += 1;

	mlibc::service_result serv_buf{getAllocator()};
	int serv_count = mlibc::lookup_serv_by_name(serv_buf, "domain", IPPROTO_UDP, SOCK_DGRAM, 0);
	if (serv_count < 0) {
		mlibc::infoLogger() << "mlibc: could not resolve DNS service" << frg::endlog;
		return -EAI_SERVICE;
	}

	struct sockaddr_in sin = {};
	sin.sin_family = AF_INET;
	sin.sin_port = htons(serv_buf[0].port);

	auto nameserver = get_nameserver();
	if (!inet_aton(nameserver ? nameserver->name.data() : "127.0.0.1", &sin.sin_addr)) {
		mlibc::infoLogger() << "lookup_name_dns(): inet_aton() failed!" << frg::endlog;
		return -EAI_SYSTEM;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		mlibc::infoLogger() << "lookup_name_dns(): socket() failed" << frg::endlog;
		return -EAI_SYSTEM;
	}

	frg::scope_exit close_fd{[&] {
		close(fd);
	}};

	uint8_t response[DNS_MAX_RESPONSE_SIZE];
	int num_ans = 0;

	struct pollfd pollfd;
	pollfd.fd = fd;
	pollfd.events = POLLIN;
	for (int attempt = 0; attempt < DNS_QUERY_MAX_ATTEMPTS; attempt++) {
		size_t sent = sendto(fd, request.data(), request.size(), 0,
				(struct sockaddr*)&sin, sizeof(sin));
		if (sent != request.size()) {
			mlibc::infoLogger() << "lookup_name_dns(): sendto() failed to send everything" << frg::endlog;
			return -EAI_SYSTEM;
		}

		int fds_ready = 0;
		struct timespec start_time;
		if (int e = mlibc::sys_clock_get(CLOCK_MONOTONIC, &start_time.tv_sec, &start_time.tv_nsec); e)
			mlibc::panicLogger() << "mlibc: sys_clock_get() failed with error code: " << e << frg::endlog;

		while ((fds_ready = poll(&pollfd, 1, get_poll_timeout(&start_time,
				DNS_QUERY_TIMEOUT_MS / DNS_QUERY_MAX_ATTEMPTS))) > 0) {
			ssize_t rlen = recvfrom(fd, response, sizeof(response), 0, nullptr, nullptr);
			if (rlen < 0) {
				mlibc::infoLogger() << "lookup_name_dns(): recvfrom() failed" << frg::endlog;
				return -EAI_SYSTEM;
			}

			if ((size_t)rlen < sizeof(struct dns_header))
				continue;

			auto response_header = reinterpret_cast<struct dns_header*>(response);
			if (response_header->identification != header.identification)
				continue;

			uint16_t response_flags = ntohs(response_header->flags);
			if (response_flags & RESPONSE_FLAG_TC)
				continue;

			if ((response_flags & 0xF) == RETURN_NXDOMAIN)
				return -EAI_NONAME;

			const uint8_t *response_end = response + rlen;
			const uint8_t *it = response + sizeof(struct dns_header);
			bool malformed = false;
			for (int i = 0; i < ntohs(response_header->no_q); i++) {
				frg::string<MemoryAllocator> dns_name{getAllocator()};
				if (!read_dns_name_safe(response, response_end, it, dns_name) || (response_end - it) < 4) {
					malformed = true;
					break;
				}
				(void) dns_name;
				it += 4;
			}

			if (malformed)
				continue;

			for (int i = 0; i < ntohs(response_header->no_ans); i++) {
				struct dns_addr_buf buffer;
				frg::string<MemoryAllocator> dns_name{getAllocator()};
				if (!read_dns_name_safe(response, response_end, it, dns_name) || (response_end - it) < 10) {
					malformed = true;
					break;
				}

				uint16_t rr_type = (it[0] << 8) | it[1];
				uint16_t rr_class = (it[2] << 8) | it[3];
				uint16_t rr_length = (it[8] << 8) | it[9];
				it += 10;
				(void)rr_class;
				if ((response_end - it) < rr_length) {
					malformed = true;
					break;
				}
				const uint8_t *rdata = it;
				it += rr_length;

				switch (rr_type) {
					case RECORD_A:
						if (family != AF_UNSPEC && family != AF_INET)
							continue;
						if (rr_length != 4)
							continue;

						memcpy(buffer.addr, rdata, rr_length);
						buffer.family = AF_INET;
						buffer.name = std::move(dns_name);
						buf.buf.push(std::move(buffer));
						break;
					case RECORD_AAAA:
						if (family != AF_UNSPEC && family != AF_INET6)
							continue;
						if (rr_length != 16)
							continue;

						memcpy(buffer.addr, rdata, rr_length);
						buffer.family = AF_INET6;
						buffer.name = std::move(dns_name);
						buf.buf.push(std::move(buffer));
						break;
					case RECORD_CNAME: {
						const uint8_t *name_it = rdata;
						frg::string<MemoryAllocator> cname{getAllocator()};
						if (!read_dns_name_safe(response, response_end, name_it, cname)) {
							malformed = true;
							break;
						}
						canon_name = std::move(cname);
						buf.aliases.push(std::move(dns_name));
						break;
					}
					default:
						mlibc::infoLogger() << "lookup_name_dns: unknown rr type "
							<< rr_type << frg::endlog;
						break;
				}
				if (malformed)
					break;
			}
			if (malformed)
				continue;
			num_ans += ntohs(response_header->no_ans);

			if (num_ans >= num_q)
				return buf.buf.size();
		}

		if (fds_ready < 0)
			return -EAI_SYSTEM;
	}

	return -EAI_AGAIN;
}

int lookup_addr_dns(frg::span<char> name, frg::array<uint8_t, 16> &addr, int family) {
	frg::string<MemoryAllocator> request{getAllocator()};

	int num_q = 1;
	struct dns_header header;
	header.identification = htons(allocate_dns_id());
	header.flags = htons(0x100);
	header.no_q = htons(num_q);
	header.no_ans = htons(0);
	header.no_auths = htons(0);
	header.no_additional = htons(0);

	request.resize(sizeof(header));
	memcpy(request.data(), &header, sizeof(header));

	char addr_str[64];
	if(!inet_ntop(family, addr.data(), addr_str, sizeof(addr_str))) {
		switch(errno) {
			case EAFNOSUPPORT:
				return -EAI_FAMILY;
			case ENOSPC:
				return -EAI_OVERFLOW;
			default:
				return -EAI_FAIL;
		}
	}
	frg::string<MemoryAllocator> req_str{getAllocator(), addr_str};
	req_str += ".in-addr.arpa";

	frg::string_view req_view{req_str.data(), req_str.size()};
	size_t ptr = 0;
	do {
		size_t next = req_view.find_first('.', ptr);
		size_t length = next != (size_t)-1 ? next - ptr : req_view.size() - ptr;
		frg::string_view substring = req_view.sub_string(ptr, length);
		request += char(length);
		request += substring;
		ptr = next + 1;
	} while(ptr != 0);

	request += char(0);
	// set question type to fetch PTR records
	request += 0;
	request += 12;
	// set CLASS to IN
	request += 0;
	request += 1;

	mlibc::service_result serv_buf{getAllocator()};
	int serv_count = mlibc::lookup_serv_by_name(serv_buf, "domain", IPPROTO_UDP, SOCK_DGRAM, 0);
	if (serv_count < 0) {
		mlibc::infoLogger() << "mlibc: could not resolve DNS service" << frg::endlog;
		return -EAI_SERVICE;
	}

	struct sockaddr_in sin = {};
	sin.sin_family = AF_INET;
	sin.sin_port = htons(serv_buf[0].port);

	auto nameserver = get_nameserver();
	if (!inet_aton(nameserver ? nameserver->name.data() : "127.0.0.1", &sin.sin_addr)) {
		mlibc::infoLogger() << "lookup_name_dns(): inet_aton() failed!" << frg::endlog;
		return -EAI_SYSTEM;
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		mlibc::infoLogger() << "lookup_name_dns(): socket() failed" << frg::endlog;
		return -EAI_SYSTEM;
	}

	frg::scope_exit close_fd{[&] {
		close(fd);
	}};

	uint8_t response[DNS_MAX_RESPONSE_SIZE];
	int num_ans = 0;

	struct pollfd pollfd;
	pollfd.fd = fd;
	pollfd.events = POLLIN;
	for (int attempt = 0; attempt < DNS_QUERY_MAX_ATTEMPTS; attempt++) {
		size_t sent = sendto(fd, request.data(), request.size(), 0,
				(struct sockaddr*)&sin, sizeof(sin));

		if (sent != request.size()) {
			mlibc::infoLogger() << "lookup_name_dns(): sendto() failed to send everything" << frg::endlog;
			return -EAI_SYSTEM;
		}

		int fds_ready = 0;
		struct timespec start_time;
		if (int e = mlibc::sys_clock_get(CLOCK_MONOTONIC, &start_time.tv_sec, &start_time.tv_nsec); e)
			mlibc::panicLogger() << "mlibc: sys_clock_get() failed with error code: " << e << frg::endlog;

		while ((fds_ready = poll(&pollfd, 1, get_poll_timeout(&start_time,
				DNS_QUERY_TIMEOUT_MS / DNS_QUERY_MAX_ATTEMPTS))) > 0) {
			ssize_t rlen = recvfrom(fd, response, sizeof(response), 0, nullptr, nullptr);
			if (rlen < 0) {
				mlibc::infoLogger() << "lookup_name_dns(): recvfrom() failed" << frg::endlog;
				return -EAI_SYSTEM;
			}

			if ((size_t)rlen < sizeof(struct dns_header))
				continue;

			auto response_header = reinterpret_cast<struct dns_header*>(response);
			if (response_header->identification != header.identification)
				continue;

			uint16_t response_flags = ntohs(response_header->flags);
			if (response_flags & RESPONSE_FLAG_TC)
				continue;

			const uint8_t *response_end = response + rlen;
			const uint8_t *it = response + sizeof(struct dns_header);
			bool malformed = false;
			for (int i = 0; i < ntohs(response_header->no_q); i++) {
				frg::string<MemoryAllocator> dns_name{getAllocator()};
				if (!read_dns_name_safe(response, response_end, it, dns_name) || (response_end - it) < 4) {
					malformed = true;
					break;
				}
				(void) dns_name;
				it += 4;
			}

			if (malformed)
				continue;

			for (int i = 0; i < ntohs(response_header->no_ans); i++) {
				struct dns_addr_buf buffer;
				frg::string<MemoryAllocator> dns_name{getAllocator()};
				if (!read_dns_name_safe(response, response_end, it, dns_name) || (response_end - it) < 10) {
					malformed = true;
					break;
				}

				uint16_t rr_type = (it[0] << 8) | it[1];
				uint16_t rr_class = (it[2] << 8) | it[3];
				uint16_t rr_length = (it[8] << 8) | it[9];
				it += 10;
				(void)rr_class;
				(void)rr_length;
				if ((response_end - it) < rr_length) {
					malformed = true;
					break;
				}
				const uint8_t *rdata = it;
				it += rr_length;

				(void)dns_name;

				switch (rr_type) {
					case RECORD_PTR: {
						const uint8_t *name_it = rdata;
						frg::string<MemoryAllocator> ptr_name{getAllocator()};
						if (!read_dns_name_safe(response, response_end, name_it, ptr_name)) {
							malformed = true;
							break;
						}
						if (ptr_name.size() >= name.size())
							return -EAI_OVERFLOW;
						std::copy(ptr_name.begin(), ptr_name.end(), name.data());
						name.data()[ptr_name.size()] = '\0';
						return 1;
					}
					default:
						mlibc::infoLogger() << "lookup_addr_dns: unknown rr type "
							<< rr_type << frg::endlog;
						break;
				}
				if (malformed)
					break;
			}
			if (malformed)
				continue;
			num_ans += ntohs(response_header->no_ans);

			if (num_ans >= num_q)
				return 0;
		}

		if (fds_ready < 0)
			return -EAI_SYSTEM;
	}

	return -EAI_AGAIN;
}

int lookup_name_hosts(struct lookup_result &buf, const char *name,
		frg::string<MemoryAllocator> &canon_name, int family) {
	auto file = fopen("/etc/hosts", "r");
	if (!file) {
		switch (errno) {
			case ENOENT:
			case ENOTDIR:
			case EACCES:
				return -EAI_SERVICE;
			default:
				return -EAI_SYSTEM;
		}
	}

	char line[128];
	int name_length = strlen(name);
	while (fgets(line, 128, file)) {
		char *pos;
		// same way to deal with comments as in services.cpp
		if ((pos = strchr(line, '#'))) {
			*pos++ = '\n';
			*pos = '\0';
		}

		for(pos = line + 1; (pos = strstr(pos, name)) &&
				(!isspace(pos[-1]) || !isspace(pos[name_length])); pos++);
		if (!pos)
			continue;

		for (pos = line; !isspace(*pos); pos++);
		*pos = '\0';

		struct dns_addr_buf buffer;

		if ((family == AF_UNSPEC || family == AF_INET) && inet_pton(AF_INET, line, buffer.addr)) {
			buffer.family = AF_INET;
		} else if((family == AF_UNSPEC || family == AF_INET6) && inet_pton(AF_INET6, line, buffer.addr)) {
			buffer.family = AF_INET6;
		} else {
			continue; // not a valid address
		}

		pos++;
		for(; *pos && isspace(*pos); pos++);
		char *end;
		for(end = pos; *end && !isspace(*end); end++);

		buffer.name = frg::string<MemoryAllocator>{pos,
			static_cast<size_t>(end - pos), getAllocator()};
		canon_name = buffer.name;

		buf.buf.push(std::move(buffer));

		pos = end;
		while (pos[1]) {
			for (; *pos && isspace(*pos); pos++);
			for (end = pos; *end && !isspace(*end); end++);
			auto name = frg::string<MemoryAllocator>{pos,
				static_cast<size_t>(end - pos), getAllocator()};
			buf.aliases.push(std::move(name));
			pos = end;
		}
	}

	fclose(file);
	return buf.buf.size();
}

int lookup_addr_hosts(frg::span<char> name, frg::array<uint8_t, 16> &addr, int family) {
	auto file = fopen("/etc/hosts", "r");
	if (!file) {
		switch (errno) {
			case ENOENT:
			case ENOTDIR:
			case EACCES:
				return -EAI_SERVICE;
			default:
				return -EAI_SYSTEM;
		}
	}

	// Buffer to hold ASCII version of address
	char addr_str[64];
	if(!inet_ntop(family, addr.data(), addr_str, sizeof(addr_str))) {
		switch(errno) {
			case EAFNOSUPPORT:
				return -EAI_FAMILY;
			case ENOSPC:
				return -EAI_OVERFLOW;
			default:
				return -EAI_FAIL;
		}
	}
	int addr_str_len = strlen(addr_str);

	char line[128];
	while (fgets(line, 128, file)) {
		char *pos;
		// same way to deal with comments as in services.cpp
		if ((pos = strchr(line, '#'))) {
			*pos++ = '\n';
			*pos = '\0';
		}
		if (strncmp(line, addr_str, addr_str_len))
			continue;

		for (pos = line + addr_str_len + 1; isspace(*pos); pos++);
		char *begin = pos;
		for (; !isspace(*pos); pos++);
		char *end = pos;

		size_t size = end - begin;
		if (size >= name.size())
			return -EAI_OVERFLOW;
		std::copy(begin, end, name.data());
		name.data()[size] = '\0';
		return 1;
	}
	return 0;
}

int lookup_name_null(struct lookup_result &buf, int flags, int family) {
	if (flags & AI_PASSIVE) {
		if (family != AF_INET6) {
			struct dns_addr_buf addr_buf;
			addr_buf.family = AF_INET;

			in_addr_t addr = INADDR_ANY;
			memcpy(&addr_buf.addr, &addr, 4);

			buf.buf.push_back(addr_buf);
		}
		if (family != AF_INET) {
			struct dns_addr_buf addr_buf;
			addr_buf.family = AF_INET6;

			struct in6_addr addr = IN6ADDR_ANY_INIT;
			memcpy(&addr_buf.addr, &addr, 16);

			buf.buf.push_back(addr_buf);
		}
	} else {
		if (family != AF_INET6) {
			struct dns_addr_buf addr_buf;
			addr_buf.family = AF_INET;

			in_addr_t addr = INADDR_LOOPBACK;
			memcpy(&addr_buf.addr, &addr, 4);

			buf.buf.push_back(addr_buf);
		}
		if (family != AF_INET) {
			struct dns_addr_buf addr_buf;
			addr_buf.family = AF_INET6;

			struct in6_addr addr = IN6ADDR_LOOPBACK_INIT;
			memcpy(&addr_buf.addr, &addr, 16);

			buf.buf.push_back(addr_buf);
		}
	}
	return buf.buf.size();
}

int lookup_name_ip(struct lookup_result &buf, const char *name, int family) {
	if (family == AF_INET) {
		in_addr_t addr = 0;
		int res = inet_pton(AF_INET, name, &addr);

		if (res <= 0)
			return -EAI_NONAME;

		struct dns_addr_buf addr_buf;
		addr_buf.family = AF_INET;
		memcpy(&addr_buf.addr, &addr, 4);

		buf.buf.push_back(addr_buf);
		return 1;
	}

	if (family == AF_INET6) {
		struct in6_addr addr{};
		int res = inet_pton(AF_INET6, name, &addr);

		if (res <= 0)
			return -EAI_NONAME;

		struct dns_addr_buf addr_buf;
		addr_buf.family = AF_INET6;
		memcpy(&addr_buf.addr, &addr, 16);

		buf.buf.push_back(addr_buf);
		return 1;
	}

	// If no family was specified we try ipv4 and then ipv6.
	in_addr_t addr4 = 0;
	int res = inet_pton(AF_INET, name, &addr4);

	if (res > 0) {
		struct dns_addr_buf addr_buf;
		addr_buf.family = AF_INET;
		memcpy(&addr_buf.addr, &addr4, 4);

		buf.buf.push_back(addr_buf);
		return 1;
	}

	struct in6_addr addr6{};
	res = inet_pton(AF_INET6, name, &addr6);

	if (res <= 0)
		return -EAI_NONAME;

	struct dns_addr_buf addr_buf;
	addr_buf.family = AF_INET6;
	memcpy(&addr_buf.addr, &addr6, 16);

	buf.buf.push_back(addr_buf);
	return 1;
}

} // namespace mlibc

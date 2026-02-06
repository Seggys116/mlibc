#include <stdio.h>
#include <bits/ensure.h>
#include <netinet/ether.h>

char *ether_ntoa(const struct ether_addr *addr) {
	static char x[18];
	return ether_ntoa_r (addr, x);
}

char *ether_ntoa_r(const struct ether_addr *addr, char *buf) {
	char *orig_ptr = buf;

	for(int i = 0; i < ETH_ALEN; i++) {
		buf += sprintf(buf, i == 0 ? "%.2X" : ":%.2X", addr->ether_addr_octet[i]);
	}

	return orig_ptr;
}

struct ether_addr *ether_aton(const char *) {
	__ensure(!"Not implemented");
	__builtin_unreachable();
}

struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr) {
	unsigned int values[ETH_ALEN];
	if (sscanf(asc, "%x:%x:%x:%x:%x:%x",
	           &values[0], &values[1], &values[2],
	           &values[3], &values[4], &values[5]) != ETH_ALEN) {
		return nullptr;
	}
	for (int i = 0; i < ETH_ALEN; i++) {
		addr->ether_addr_octet[i] = values[i];
	}
	return addr;
}

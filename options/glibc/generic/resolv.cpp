#include <resolv.h>
#include <bits/ensure.h>
#include <mlibc/debug.hpp>

int dn_expand(const unsigned char *msg, const unsigned char *eom,
		const unsigned char *src, char *dst, int dstsize) {
	const unsigned char *s = src;
	char *d = dst;
	char *dend = dst + dstsize;
	int len = -1;
	int i, n;
	int loops = 0;

	while (*s && loops < 256) {
		if ((*s & 0xc0) == 0xc0) {
			// Compression pointer
			if (s + 1 >= eom)
				return -1;
			n = ((s[0] & 0x3f) << 8) | s[1];
			if (len < 0)
				len = s + 2 - src;
			if (n >= eom - msg)
				return -1;
			s = msg + n;
			loops++;
			continue;
		}

		n = *s++;
		if (d != dst) {
			if (d >= dend)
				return -1;
			*d++ = '.';
		}

		if (d + n >= dend)
			return -1;

		for (i = 0; i < n && s < eom; i++)
			*d++ = *s++;

		if (s >= eom)
			return -1;
	}

	if (d >= dend)
		return -1;
	*d = 0;

	if (len < 0)
		len = s + 1 - src;

	return len;
}

// Helper function to encode a domain name into DNS wire format
static int dn_comp_impl(const char *src, unsigned char *dst, int dstsize) {
	unsigned char *p = dst;
	unsigned char *end = dst + dstsize;
	const char *s = src;
	int label_len = 0;
	unsigned char *label_ptr = NULL;

	if (*s == 0) {
		if (p >= end)
			return -1;
		*p++ = 0;
		return p - dst;
	}

	while (*s) {
		if (*s == '.') {
			if (label_ptr) {
				*label_ptr = label_len;
				label_len = 0;
				label_ptr = NULL;
			}
			s++;
			continue;
		}

		if (label_ptr == NULL) {
			if (p >= end)
				return -1;
			label_ptr = p++;
			label_len = 0;
		}

		if (p >= end)
			return -1;
		*p++ = *s++;
		label_len++;

		if (label_len > 63)
			return -1;
	}

	if (label_ptr) {
		*label_ptr = label_len;
	}

	if (p >= end)
		return -1;
	*p++ = 0;

	return p - dst;
}

// Build a DNS query message
int res_mkquery(int op, const char *dname, int class_val, int type,
                const unsigned char *data, int datalen, const unsigned char *newrr,
                unsigned char *buf, int buflen) {
	unsigned char *p = buf;
	unsigned char *end = buf + buflen;
	int n;
	static int id = 0;

	// Check minimum buffer size for header
	if (buflen < 12)
		return -1;

	// Build header
	// Transaction ID
	*p++ = (++id) >> 8;
	*p++ = id & 0xff;

	// Flags: recursion desired, standard query
	*p++ = (op << 3) | 0x01; // Opcode in bits 3-6, RD bit set
	*p++ = 0x00;

	// Question count
	*p++ = 0x00;
	*p++ = 0x01;

	// Answer count
	*p++ = 0x00;
	*p++ = 0x00;

	// Authority count
	*p++ = 0x00;
	*p++ = 0x00;

	// Additional count
	*p++ = 0x00;
	*p++ = 0x00;

	// Encode the domain name
	n = dn_comp_impl(dname, p, end - p);
	if (n < 0)
		return -1;
	p += n;

	// Check space for QTYPE and QCLASS
	if (p + 4 > end)
		return -1;

	// QTYPE
	*p++ = type >> 8;
	*p++ = type & 0xff;

	// QCLASS
	*p++ = class_val >> 8;
	*p++ = class_val & 0xff;

	return p - buf;
}

int res_query(const char *, int, int, unsigned char *, int) {
	__ensure(!"Not implemented");
	__builtin_unreachable();
}

int res_init() {
	mlibc::infoLogger() << "mlibc: res_init is a stub!" << frg::endlog;
	return 0;
}

int res_ninit(res_state) {
	mlibc::infoLogger() << "mlibc: res_ninit is a stub!" << frg::endlog;
	return 0;
}

void res_nclose(res_state) {
	mlibc::infoLogger() << "mlibc: res_nclose is a stub!" << frg::endlog;
	return;
}

int dn_comp(const char *src, unsigned char *dst, int dstsize, unsigned char **dnptrs, unsigned char **lastdnptr) {
	// For now, we don't implement compression with dnptrs/lastdnptr
	// Just do simple encoding
	(void)dnptrs;
	(void)lastdnptr;
	return dn_comp_impl(src, dst, dstsize);
}

/* This is completely unused, and exists purely to satisfy broken apps. */

struct __res_state *__res_state() {
	static struct __res_state res;
	return &res;
}

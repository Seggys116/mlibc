#include <errno.h>
#include <arpa/nameser.h>
#include <bits/ensure.h>
#include <mlibc/debug.hpp>
#include <string.h>

// The ns_get* and ns_put* functions are taken from musl.
unsigned ns_get16(const unsigned char *cp) {
	return cp[0] << 8 | cp[1];
}

unsigned long ns_get32(const unsigned char *cp) {
	return (unsigned)cp[0] << 24 | cp[1] << 16 | cp[2] << 8 | cp[3];
}

void ns_put16(unsigned s, unsigned char *cp) {
	*cp++ = s >> 8;
	*cp++ = s;
}

void ns_put32(unsigned long l, unsigned char *cp) {
	*cp++ = l >> 24;
	*cp++ = l >> 16;
	*cp++ = l >> 8;
	*cp++ = l;
}

// Skip a DNS name in a message
static int dn_skipname_impl(const unsigned char *s, const unsigned char *end) {
	const unsigned char *p = s;

	while (p < end) {
		int c = *p++;
		if (c == 0)
			return p - s;
		if ((c & 0xc0) == 0xc0) {
			// Compression pointer
			if (p >= end)
				return -1;
			return p + 1 - s;
		}
		// Regular label
		p += c;
		if (p > end)
			return -1;
	}

	return -1;
}

// Expand a compressed DNS name
static int dn_expand_impl(const unsigned char *msg, const unsigned char *eom,
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

// Skip resource records in a section
static int ns_skiprr(const unsigned char *ptr, const unsigned char *eom, ns_sect section, int count) {
	const unsigned char *p = ptr;
	int rdlength;

	for (int i = 0; i < count; i++) {
		// Skip name
		int n = dn_skipname_impl(p, eom);
		if (n < 0)
			return -1;
		p += n;

		// Check if we have room for type, class, ttl, rdlength
		if (section == ns_s_qd) {
			// Questions only have type and class
			if (p + 4 > eom)
				return -1;
			p += 4;
		} else {
			// Answers/Authority/Additional have type, class, ttl, rdlength, rdata
			if (p + 10 > eom)
				return -1;
			rdlength = ns_get16(p + 8);
			p += 10 + rdlength;
			if (p > eom)
				return -1;
		}
	}

	return p - ptr;
}

int ns_initparse(const unsigned char *msg, int msglen, ns_msg *handle) {
	const unsigned char *eom = msg + msglen;
	int i;

	if (msglen < 12) {
		errno = EMSGSIZE;
		return -1;
	}

	handle->_msg = msg;
	handle->_eom = eom;
	handle->_id = ns_get16(msg);
	handle->_flags = ns_get16(msg + 2);

	for (i = 0; i < 4; i++)
		handle->_counts[i] = ns_get16(msg + 4 + i * 2);

	handle->_sections[0] = msg + 12;
	handle->_sect = ns_s_max;
	handle->_rrnum = -1;
	handle->_msg_ptr = NULL;

	// Set up section pointers
	const unsigned char *p = msg + 12;
	for (i = 0; i < 4; i++) {
		int n = ns_skiprr(p, eom, (ns_sect)i, handle->_counts[i]);
		if (n < 0) {
			errno = EMSGSIZE;
			return -1;
		}
		handle->_sections[i] = p;
		p += n;
	}

	return 0;
}

int ns_parserr(ns_msg *handle, ns_sect section, int rrnum, ns_rr *rr) {
	if (section < 0 || section >= ns_s_max) {
		errno = ENODEV;
		return -1;
	}
	if (rrnum < 0 || rrnum >= handle->_counts[section]) {
		errno = ENODEV;
		return -1;
	}

	const unsigned char *p = handle->_sections[section];
	const unsigned char *eom = handle->_eom;

	// Skip to the requested RR
	for (int i = 0; i < rrnum; i++) {
		int n = dn_skipname_impl(p, eom);
		if (n < 0) {
			errno = EMSGSIZE;
			return -1;
		}
		p += n;

		if (section == ns_s_qd) {
			if (p + 4 > eom) {
				errno = EMSGSIZE;
				return -1;
			}
			p += 4;
		} else {
			if (p + 10 > eom) {
				errno = EMSGSIZE;
				return -1;
			}
			int rdlength = ns_get16(p + 8);
			p += 10 + rdlength;
			if (p > eom) {
				errno = EMSGSIZE;
				return -1;
			}
		}
	}

	// Parse the name
	int n = dn_expand_impl(handle->_msg, eom, p, rr->name, NS_MAXDNAME);
	if (n < 0) {
		errno = EMSGSIZE;
		return -1;
	}
	p += n;

	// Parse type, class
	if (p + 4 > eom) {
		errno = EMSGSIZE;
		return -1;
	}
	rr->type = ns_get16(p);
	rr->rr_class = ns_get16(p + 2);
	p += 4;

	if (section == ns_s_qd) {
		rr->ttl = 0;
		rr->rdlength = 0;
		rr->rdata = NULL;
	} else {
		if (p + 6 > eom) {
			errno = EMSGSIZE;
			return -1;
		}
		rr->ttl = ns_get32(p);
		rr->rdlength = ns_get16(p + 4);
		p += 6;

		if (p + rr->rdlength > eom) {
			errno = EMSGSIZE;
			return -1;
		}
		rr->rdata = p;
	}

	return 0;
}

int ns_name_uncompress(const unsigned char *msg, const unsigned char *eom,
                       const unsigned char *src, char *dst, size_t dstsize) {
	int n = dn_expand_impl(msg, eom, src, dst, dstsize);
	if (n < 0) {
		errno = EMSGSIZE;
		return -1;
	}
	return n;
}

int ns_msg_count(ns_msg handle, ns_sect section) {
	if (section < 0 || section >= ns_s_max)
		return -1;
	return handle._counts[section];
}

uint16_t ns_rr_class(ns_rr rr) {
	return rr.rr_class;
}

uint16_t ns_rr_type(ns_rr rr) {
	return rr.type;
}

uint32_t ns_rr_ttl(ns_rr rr) {
	return rr.ttl;
}

uint16_t ns_rr_rdlen(ns_rr rr) {
	return rr.rdlength;
}

const unsigned char *ns_rr_rdata(ns_rr rr) {
	return rr.rdata;
}

const char *ns_rr_name(ns_rr rr) {
	return rr.name;
}

const unsigned char *ns_msg_base(ns_msg handle) {
	return handle._msg;
}

const unsigned char *ns_msg_end(ns_msg handle) {
	return handle._eom;
}

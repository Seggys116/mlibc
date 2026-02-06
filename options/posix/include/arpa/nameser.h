#ifndef _ARPA_NAMESER_H
#define _ARPA_NAMESER_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum domain name length */
#define MAXDNAME 1025
#define NS_MAXDNAME MAXDNAME

/* Maximum message length */
#define NS_PACKETSZ 512

/* DNS header structure */
typedef struct {
	unsigned id :16;        /* Query identification number */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	/* Fields in big-endian order */
	unsigned qr:1;          /* Response flag */
	unsigned opcode:4;      /* Operation code */
	unsigned aa:1;          /* Authoritative answer */
	unsigned tc:1;          /* Truncation flag */
	unsigned rd:1;          /* Recursion desired */
	unsigned ra:1;          /* Recursion available */
	unsigned unused:1;      /* Unused bits */
	unsigned ad:1;          /* Authentic data */
	unsigned cd:1;          /* Checking disabled */
	unsigned rcode:4;       /* Response code */
#else
	/* Fields in little-endian order */
	unsigned rd:1;          /* Recursion desired */
	unsigned tc:1;          /* Truncation flag */
	unsigned aa:1;          /* Authoritative answer */
	unsigned opcode:4;      /* Operation code */
	unsigned qr:1;          /* Response flag */
	unsigned rcode:4;       /* Response code */
	unsigned cd:1;          /* Checking disabled */
	unsigned ad:1;          /* Authentic data */
	unsigned unused:1;      /* Unused bits */
	unsigned ra:1;          /* Recursion available */
#endif
	unsigned qdcount:16;    /* Number of question entries */
	unsigned ancount:16;    /* Number of answer entries */
	unsigned nscount:16;    /* Number of authority entries */
	unsigned arcount:16;    /* Number of additional entries */
} HEADER;

/* DNS resource record types */
typedef enum __ns_type {
	ns_t_invalid = 0,       /* Invalid type */
	ns_t_a = 1,            /* Host address */
	ns_t_ns = 2,           /* Authoritative server */
	ns_t_md = 3,           /* Mail destination */
	ns_t_mf = 4,           /* Mail forwarder */
	ns_t_cname = 5,        /* Canonical name */
	ns_t_soa = 6,          /* Start of authority zone */
	ns_t_mb = 7,           /* Mailbox domain name */
	ns_t_mg = 8,           /* Mail group member */
	ns_t_mr = 9,           /* Mail rename name */
	ns_t_null = 10,        /* Null resource record */
	ns_t_wks = 11,         /* Well known service */
	ns_t_ptr = 12,         /* Domain name pointer */
	ns_t_hinfo = 13,       /* Host information */
	ns_t_minfo = 14,       /* Mailbox information */
	ns_t_mx = 15,          /* Mail routing information */
	ns_t_txt = 16,         /* Text strings */
	ns_t_rp = 17,          /* Responsible person */
	ns_t_afsdb = 18,       /* AFS cell database */
	ns_t_x25 = 19,         /* X.25 calling address */
	ns_t_isdn = 20,        /* ISDN calling address */
	ns_t_rt = 21,          /* Router */
	ns_t_nsap = 22,        /* NSAP address */
	ns_t_nsap_ptr = 23,    /* Reverse NSAP lookup */
	ns_t_sig = 24,         /* Security signature */
	ns_t_key = 25,         /* Security key */
	ns_t_px = 26,          /* X.400 mail mapping */
	ns_t_gpos = 27,        /* Geographical position */
	ns_t_aaaa = 28,        /* IPv6 address */
	ns_t_loc = 29,         /* Location information */
	ns_t_nxt = 30,         /* Next domain */
	ns_t_eid = 31,         /* Endpoint identifier */
	ns_t_nimloc = 32,      /* Nimrod locator */
	ns_t_srv = 33,         /* Server selection */
	ns_t_atma = 34,        /* ATM address */
	ns_t_naptr = 35,       /* Naming authority pointer */
	ns_t_kx = 36,          /* Key exchange */
	ns_t_cert = 37,        /* Certificate */
	ns_t_a6 = 38,          /* IPv6 address (deprecated) */
	ns_t_dname = 39,       /* Non-terminal DNAME */
	ns_t_sink = 40,        /* Kitchen sink */
	ns_t_opt = 41,         /* EDNS0 option */
	ns_t_apl = 42,         /* Address prefix list */
	ns_t_ds = 43,          /* Delegation signer */
	ns_t_sshfp = 44,       /* SSH fingerprint */
	ns_t_ipseckey = 45,    /* IPSEC key */
	ns_t_rrsig = 46,       /* DNSSEC signature */
	ns_t_nsec = 47,        /* Denial of existence */
	ns_t_dnskey = 48,      /* DNSSEC key */
	ns_t_dhcid = 49,       /* DHCP identifier */
	ns_t_nsec3 = 50,       /* Hashed denial of existence */
	ns_t_nsec3param = 51,  /* NSEC3 parameters */
	ns_t_tlsa = 52,        /* TLSA certificate association */
	ns_t_hip = 55,         /* Host identity protocol */
	ns_t_spf = 99,         /* Sender policy framework */
	ns_t_tkey = 249,       /* Transaction key */
	ns_t_tsig = 250,       /* Transaction signature */
	ns_t_ixfr = 251,       /* Incremental zone transfer */
	ns_t_axfr = 252,       /* Transfer zone of authority */
	ns_t_mailb = 253,      /* Transfer mailbox records */
	ns_t_maila = 254,      /* Transfer mail agent records */
	ns_t_any = 255,        /* Wildcard match */
	ns_t_uri = 256,        /* URI */
	ns_t_caa = 257,        /* Certification authority authorization */
	ns_t_max = 65536
} ns_type;

/* DNS message handle */
typedef struct __ns_msg {
	const unsigned char *_msg;
	const unsigned char *_eom;
	uint16_t _id;
	uint16_t _flags;
	uint16_t _counts[4];
	const unsigned char *_sections[4];
	int _sect;
	int _rrnum;
	const unsigned char *_msg_ptr;
} ns_msg;

/* DNS resource record handle */
typedef struct __ns_rr {
	char name[NS_MAXDNAME];
	uint16_t type;
	uint16_t rr_class;
	uint32_t ttl;
	uint16_t rdlength;
	const unsigned char *rdata;
} ns_rr;

/* DNS message sections */
typedef enum __ns_sect {
	ns_s_qd = 0,    /* Question section */
	ns_s_zn = 0,    /* Zone section */
	ns_s_an = 1,    /* Answer section */
	ns_s_pr = 1,    /* Prerequisite section */
	ns_s_ns = 2,    /* Authority section */
	ns_s_ud = 2,    /* Update section */
	ns_s_ar = 3,    /* Additional section */
	ns_s_max = 4
} ns_sect;

/* DNS class values */
typedef enum __ns_class {
	ns_c_invalid = 0,   /* Invalid class */
	ns_c_in = 1,       /* Internet */
	ns_c_2 = 2,        /* Unallocated */
	ns_c_chaos = 3,    /* CHAOS */
	ns_c_hs = 4,       /* Hesiod */
	ns_c_none = 254,   /* No class */
	ns_c_any = 255,    /* Wildcard match */
	ns_c_max = 65536
} ns_class;

/* DNS opcode values */
typedef enum __ns_opcode {
	ns_o_query = 0,    /* Standard query */
	ns_o_iquery = 1,   /* Inverse query */
	ns_o_status = 2,   /* Name server status query */
	ns_o_notify = 4,   /* Zone change notification */
	ns_o_update = 5,   /* Zone update message */
	ns_o_max = 6
} ns_opcode;

/* DNS response codes */
typedef enum __ns_rcode {
	ns_r_noerror = 0,   /* No error */
	ns_r_formerr = 1,   /* Format error */
	ns_r_servfail = 2,  /* Server failure */
	ns_r_nxdomain = 3,  /* Non-existent domain */
	ns_r_notimpl = 4,   /* Not implemented */
	ns_r_refused = 5,   /* Query refused */
	ns_r_yxdomain = 6,  /* Name exists */
	ns_r_yxrrset = 7,   /* RRset exists */
	ns_r_nxrrset = 8,   /* RRset does not exist */
	ns_r_notauth = 9,   /* Not authoritative */
	ns_r_notzone = 10,  /* Zone of record different from zone section */
	ns_r_max = 11,
	ns_r_badvers = 16,  /* Bad OPT version */
	ns_r_badsig = 16,   /* TSIG signature failure */
	ns_r_badkey = 17,   /* Key not recognized */
	ns_r_badtime = 18   /* Signature out of time window */
} ns_rcode;

/* Legacy compatibility macros for older code */
#define QUERY       ns_o_query
#define IQUERY      ns_o_iquery
#define STATUS      ns_o_status
#define NS_NOTIFY_OP ns_o_notify
#define NS_UPDATE_OP ns_o_update

#define C_IN        ns_c_in
#define C_CHAOS     ns_c_chaos
#define C_HS        ns_c_hs
#define C_NONE      ns_c_none
#define C_ANY       ns_c_any

#define T_A         ns_t_a
#define T_NS        ns_t_ns
#define T_CNAME     ns_t_cname
#define T_SOA       ns_t_soa
#define T_PTR       ns_t_ptr
#define T_MX        ns_t_mx
#define T_TXT       ns_t_txt
#define T_AAAA      ns_t_aaaa
#define T_SRV       ns_t_srv
#define T_ANY       ns_t_any

#define NOERROR     ns_r_noerror
#define FORMERR     ns_r_formerr
#define SERVFAIL    ns_r_servfail
#define NXDOMAIN    ns_r_nxdomain
#define NOTIMP      ns_r_notimpl
#define REFUSED     ns_r_refused

#ifndef __MLIBC_ABI_ONLY

/* Parse a DNS message */
int ns_initparse(const unsigned char *__msg, int __msglen, ns_msg *__handle);

/* Get number of records in section */
int ns_msg_count(ns_msg __handle, ns_sect __section);

/* Get a resource record */
int ns_parserr(ns_msg *__handle, ns_sect __section, int __rrnum, ns_rr *__rr);

/* Skip to next section */
int ns_skipname(const unsigned char *__ptr, const unsigned char *__eom);

/* Uncompress a domain name */
int ns_name_uncompress(const unsigned char *__msg, const unsigned char *__eom,
                       const unsigned char *__src, char *__dst, size_t __dstsize);

/* Get/put 16 and 32 bit values */
unsigned ns_get16(const unsigned char *__cp);
unsigned long ns_get32(const unsigned char *__cp);
void ns_put16(unsigned __s, unsigned char *__cp);
void ns_put32(unsigned long __l, unsigned char *__cp);

/* Get the name of an rr */
const char *ns_rr_name(ns_rr __rr);

/* Get the class of an rr */
uint16_t ns_rr_class(ns_rr __rr);

/* Get the type of an rr */
uint16_t ns_rr_type(ns_rr __rr);

/* Get the ttl of an rr */
uint32_t ns_rr_ttl(ns_rr __rr);

/* Get the rdlength of an rr */
uint16_t ns_rr_rdlen(ns_rr __rr);

/* Get the rdata of an rr */
const unsigned char *ns_rr_rdata(ns_rr __rr);

/* Message accessors */
const unsigned char *ns_msg_base(ns_msg __handle);
const unsigned char *ns_msg_end(ns_msg __handle);

#endif /* !__MLIBC_ABI_ONLY */

#ifdef __cplusplus
}
#endif

#endif /* _ARPA_NAMESER_H */

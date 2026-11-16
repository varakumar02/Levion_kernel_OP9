/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Minimal libresolv (BIND ns_parse/ns_name) port used by the DNS optimizer,
 * with a 254-byte name limit.
 * Layouts follow glibc's <arpa/nameser.h>.
 */
#ifndef _DNS_OPT_RESOLV_H
#define _DNS_OPT_RESOLV_H

#include <linux/types.h>

#define NS_HFIXEDSZ	12
#define NS_QFIXEDSZ	4
#define NS_RRFIXEDSZ	10
#define NS_MAXDNAME	1025
#define DNS_NAME_LIMIT	254	/* dn_expand/ns_parserr output cap */

#define ns_t_a		1
#define ns_t_cname	5
#define ns_t_aaaa	28

typedef enum __ns_sect {
	ns_s_qd = 0,
	ns_s_an = 1,
	ns_s_ns = 2,
	ns_s_ar = 3,
	ns_s_max = 4
} ns_sect;

typedef struct __ns_msg {
	const u8 *_msg, *_eom;
	u16 _id, _flags, _counts[ns_s_max];
	const u8 *_sections[ns_s_max];
	ns_sect _sect;
	int _rrnum;
	const u8 *_msg_ptr;
} ns_msg;

typedef struct __ns_rr {
	char name[NS_MAXDNAME];
	u16 type;
	u16 rr_class;
	u32 ttl;
	u16 rdlength;
	const u8 *rdata;
} ns_rr;

#define ns_msg_id(h)		((h)._id)
#define ns_msg_count(h, s)	((h)._counts[s])

int dn_skipname(const u8 *ptr, const u8 *eom);
int dn_expand(const u8 *msg, const u8 *eom, const u8 *src, char *dst, int dstsiz);
int ns_skiprr(const u8 *ptr, const u8 *eom, ns_sect section, int count);
int ns_initparse(const u8 *msg, int msglen, ns_msg *handle);
int ns_name_uncompress(const u8 *msg, const u8 *eom, const u8 *src,
		       char *dst, size_t dstsiz);
int ns_parserr(ns_msg *handle, ns_sect section, int rrnum, ns_rr *rr);

#endif /* _DNS_OPT_RESOLV_H */

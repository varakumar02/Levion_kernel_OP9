// SPDX-License-Identifier: GPL-2.0-only
/*
 * libresolv subset for the DNS optimizer (see dns_resolv.h).
 * Names are expanded without escaping, into
 * at most 254 bytes, and a compression-pointer walk is bounded by the
 * message length.
 */
#include <linux/kernel.h>
#include <linux/string.h>
#include <asm/unaligned.h>

#include "dns_resolv.h"

/* length of the encoded name at @ptr, or -1 */
int dn_skipname(const u8 *ptr, const u8 *eom)
{
	const u8 *p = ptr;

	while (p < eom) {
		u8 n = *p;

		if (n == 0)
			return p - ptr + 1;
		if (n >= 0xc0)
			return p + 1 < eom ? p - ptr + 2 : -1;
		if (n >= eom - p)
			return -1;
		p += n + 1;
	}
	return -1;
}

/* expand the name at @src into dotted text; returns its encoded length */
int dn_expand(const u8 *msg, const u8 *eom, const u8 *src, char *dst, int dstsiz)
{
	long msglen = eom - msg;
	const u8 *p = src;
	char *d = dst;
	int len = -1, checked = 0;

	if (src == eom || dstsiz < 1 || msglen < 1)
		return -1;
	if (dstsiz > DNS_NAME_LIMIT)
		dstsiz = DNS_NAME_LIMIT;

	for (;;) {
		u8 n = *p;

		if (n < 0x40) {
			if (n == 0) {
				*d = '\0';
				return len >= 0 ? len : p - src + 1;
			}
			if (d != dst)
				*d++ = '.';
			if (n >= eom - (p + 1) || n >= dst + dstsiz - d)
				return -1;
			memcpy(d, p + 1, n);
			d += n;
			p += n + 1;
		} else {
			long off;

			if (p + 1 == eom)
				return -1;
			off = ((n & 0x3f) << 8) | p[1];
			if (off >= msglen)
				return -1;
			if (len < 0)
				len = p - src + 2;
			p = msg + off;
		}
		checked += 2;
		if (checked >= msglen)
			return -1;
	}
}

int ns_name_uncompress(const u8 *msg, const u8 *eom, const u8 *src,
		       char *dst, size_t dstsiz)
{
	return dn_expand(msg, eom, src, dst, dstsiz);
}

/* skip @count records; returns the bytes skipped or -1 */
int ns_skiprr(const u8 *ptr, const u8 *eom, ns_sect section, int count)
{
	const u8 *p = ptr;

	while (count--) {
		int n;

		if (p >= eom)
			return -1;
		n = dn_skipname(p, eom);
		if (n < 0 || eom - p < n + NS_QFIXEDSZ)
			return -1;
		p += n + NS_QFIXEDSZ;
		if (section != ns_s_qd) {
			u16 rdlen;

			if (eom - p < 6)
				return -1;
			rdlen = get_unaligned_be16(p + 4);
			if (eom - (p + 6) < rdlen)
				return -1;
			p += 6 + rdlen;
		}
	}
	return p - ptr;
}

static void ns_setsection(ns_msg *h, ns_sect sect)
{
	h->_sect = sect;
	if (sect == ns_s_max) {
		h->_rrnum = -1;
		h->_msg_ptr = NULL;
	} else {
		h->_rrnum = 0;
		h->_msg_ptr = h->_sections[sect];
	}
}

int ns_initparse(const u8 *msg, int msglen, ns_msg *h)
{
	const u8 *eom = msg + msglen;
	int i, n;

	h->_msg = msg;
	h->_eom = eom;
	if (msglen < NS_HFIXEDSZ)
		return -1;
	h->_id = get_unaligned_be16(msg);
	h->_flags = get_unaligned_be16(msg + 2);
	for (i = 0; i < ns_s_max; i++)
		h->_counts[i] = get_unaligned_be16(msg + 4 + 2 * i);
	msg += NS_HFIXEDSZ;
	for (i = 0; i < ns_s_max; i++) {
		if (!h->_counts[i]) {
			h->_sections[i] = NULL;
			continue;
		}
		h->_sections[i] = msg;
		n = ns_skiprr(msg, eom, i, h->_counts[i]);
		if (n < 0)
			return -1;
		msg += n;
	}
	if (msg != eom)
		return -1;
	ns_setsection(h, ns_s_max);
	return 0;
}

int ns_parserr(ns_msg *h, ns_sect section, int rrnum, ns_rr *rr)
{
	int n;

	if (section < ns_s_qd || section >= ns_s_max)
		return -1;
	if (section != h->_sect)
		ns_setsection(h, section);
	if (rrnum == -1)
		rrnum = h->_rrnum;
	if (rrnum < 0 || rrnum >= h->_counts[section])
		return -1;
	if (rrnum < h->_rrnum)
		ns_setsection(h, section);
	if (rrnum > h->_rrnum) {
		n = ns_skiprr(h->_msg_ptr, h->_eom, section, rrnum - h->_rrnum);
		if (n < 0)
			return -1;
		h->_msg_ptr += n;
		h->_rrnum = rrnum;
	}

	n = dn_expand(h->_msg, h->_eom, h->_msg_ptr, rr->name, DNS_NAME_LIMIT);
	if (n < 0)
		return -1;
	h->_msg_ptr += n;
	if (h->_eom - h->_msg_ptr < NS_QFIXEDSZ)
		return -1;
	rr->type = get_unaligned_be16(h->_msg_ptr);
	rr->rr_class = get_unaligned_be16(h->_msg_ptr + 2);
	h->_msg_ptr += NS_QFIXEDSZ;
	if (section == ns_s_qd) {
		rr->ttl = 0;
		rr->rdlength = 0;
		rr->rdata = NULL;
	} else {
		if (h->_eom - h->_msg_ptr < 6)
			return -1;
		rr->ttl = get_unaligned_be32(h->_msg_ptr);
		rr->rdlength = get_unaligned_be16(h->_msg_ptr + 4);
		h->_msg_ptr += 6;
		if (h->_eom - h->_msg_ptr < rr->rdlength)
			return -1;
		rr->rdata = h->_msg_ptr;
		h->_msg_ptr += rr->rdlength;
	}
	if (++h->_rrnum > h->_counts[section])
		ns_setsection(h, section + 1);
	return 0;
}

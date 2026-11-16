/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Internal interface between the two parts of the DNS optimizer:
 * race (dns_race.c) and fast retransmit (dns_fast_retransmit.c).
 */
#ifndef _DNS_OPTIMIZER_H
#define _DNS_OPTIMIZER_H

#include <linux/types.h>

/* skb->mark bit set on queries this code re-sends itself */
#define DNS_OPT_RESENT_MARK	0x2000000

#define DNS_DOMAIN_LEN		256

/* sysctl net.dns_optimizer.* */
extern int dns_opt_race_enable;
extern int dns_opt_fast_retransmit_enable;
extern int dns_opt_debug;
extern int dns_opt_race_answered;	/* forged answers delivered */
extern int dns_opt_retransmits;		/* queries re-sent */

#define dns_opt_dbg(tag, fmt, ...) \
	do { if (dns_opt_debug) pr_info("[%s]: " fmt, tag, ##__VA_ARGS__); } while (0)

int dns_race_init(void);
void dns_race_exit(void);
void dns_race_set_enable(bool enable);
int dns_fast_retransmit_init(void);
void dns_fast_retransmit_exit(void);

/*
 * Answer the pending query for @domain (uid @uid) with an empty NOERROR if
 * the other address family already got an answer; 0 when it did.
 */
int request_dns_race(const char *domain, size_t len, u32 uid);

#endif /* _DNS_OPTIMIZER_H */

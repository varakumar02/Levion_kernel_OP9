// SPDX-License-Identifier: GPL-2.0-only
/*
 * DNS race: apps usually ask for A and AAAA together and wait for both.
 * POST_ROUTING keeps a copy of each A/AAAA query per (uid, domain). When
 * PRE_ROUTING sees an answer with addresses for one family while the other
 * query is still pending, the pending query is kept as a "response node".
 * If that query then times out (dns_fast_retransmit.c calls
 * request_dns_race()), an empty NOERROR answer is built from it and
 * delivered to the app, so it stops waiting and uses the family it has.
 * Nodes expire after 10 s.
 *
 * Ported from the OnePlus 15 oplus_network_dns_optimizer.ko race part
 * (reconstructed source in varakumar02/oplus-op15-modules), with the
 * OPLUS data_module netlink control and its 10-minute statistics report
 * replaced by the net.dns_optimizer sysctls.
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/sysctl.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <asm/unaligned.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/udp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/net_namespace.h>

#include "dns_optimizer.h"
#include "dns_resolv.h"

#define TAG			"dns_race"
#define RACE_RESENT_MARK	0x10000000
#define RACE_NODE_TTL_MS	10000
#define RACE_CHECK_PERIOD	(5 * HZ)

#define race_dbg(fmt, ...) dns_opt_dbg(TAG, fmt, ##__VA_ARGS__)

static struct timer_list s_race_check_timer;

static DEFINE_SPINLOCK(s_dns_race_lock);
static DEFINE_HASHTABLE(s_dns_query_map, 8);
static DEFINE_HASHTABLE(s_dns_response_map, 8);

struct race_key {
	u32 uid;
	char domain[DNS_DOMAIN_LEN];
};

/* an app's A and AAAA queries for one name */
struct dns_query_node {
	struct hlist_node node;
	bool has_a, has_aaaa;
	u16 txn_a, txn_aaaa;
	u64 time_a, time_aaaa;		/* ms */
	struct race_key key;
	struct sk_buff *skb_a, *skb_aaaa;	/* copies, ->sk held */
};

/* the still-pending query once the other family was answered */
struct dns_rsp_node {
	struct hlist_node node;
	u32 uid;
	u16 txn_id;
	char domain[DNS_DOMAIN_LEN];
	u64 time;			/* ms */
	struct sk_buff *skb;		/* query copy, ->sk held */
};

/* what parse_dns_data extracts */
struct race_dns_info {
	bool has_answer;		/* response carries an A/AAAA address */
	u16 type;
	u16 txn_id;
};

static u64 race_now_ms(void)
{
	struct timespec64 ts;

	ktime_get_raw_ts64(&ts);
	return ts.tv_sec * MSEC_PER_SEC + ts.tv_nsec / NSEC_PER_MSEC;
}

static u32 race_hash_str(u32 seed, const char *s)
{
	return jhash(s, strnlen(s, DNS_DOMAIN_LEN), seed);
}

/* drop a query copy and the socket reference it carries */
static void race_free_skb(struct sk_buff *skb)
{
	if (!skb)
		return;
	if (skb->sk)
		sock_put(skb->sk);
	skb->sk = NULL;
	kfree_skb(skb);
}

/* keep a private, untracked copy of @skb owned by @sk */
static struct sk_buff *race_copy_skb(struct sk_buff *skb, struct sock *sk)
{
	struct sk_buff *c = skb_copy(skb, GFP_ATOMIC);

	if (!c)
		return NULL;
	c->dev = NULL;
	nf_reset_ct(c);
	nf_ct_set(c, NULL, IP_CT_UNTRACKED);
	sock_hold(sk);
	c->sk = sk;
	return c;
}

static void remove_dns_query_node(struct dns_query_node *q)
{
	race_free_skb(q->skb_a);
	race_free_skb(q->skb_aaaa);
	hash_del(&q->node);
	kfree(q);
}

static void remove_dns_rsp_node(struct dns_rsp_node *r)
{
	race_free_skb(r->skb);
	hash_del(&r->node);
	kfree(r);
}

static void dns_race_clear_all_maps(void)
{
	struct dns_query_node *q;
	struct dns_rsp_node *r;
	struct hlist_node *tmp;
	int bkt;

	spin_lock_bh(&s_dns_race_lock);
	hash_for_each_safe(s_dns_query_map, bkt, tmp, q, node)
		remove_dns_query_node(q);
	hash_for_each_safe(s_dns_response_map, bkt, tmp, r, node)
		remove_dns_rsp_node(r);
	spin_unlock_bh(&s_dns_race_lock);
}

/* ---- parsing ---------------------------------------------------------------- */

/* fill @key->domain and @info from an A/AAAA query (@response false) or
 * answer (@response true); 0 on success */
static int parse_dns_data(struct sk_buff *skb, struct race_key *key,
			  struct race_dns_info *info, bool response)
{
	ns_msg msg;
	ns_rr *rr;
	struct udphdr *uh;
	u8 *dns;
	int dlen, i, ret = -1;

	if (skb->mark & RACE_RESENT_MARK) {
		race_dbg("parse_dns_data: skb enter multiple times\n");
		return -1;
	}
	if (skb_linearize(skb)) {
		race_dbg("parse_dns_data: skb linearize failed\n");
		return -1;
	}
	uh = udp_hdr(skb);
	dlen = ntohs(uh->len) - (int)sizeof(*uh);
	if (dlen <= 0)
		return -1;
	dns = (u8 *)(uh + 1);
	rr = kzalloc(sizeof(*rr), GFP_ATOMIC);
	if (!rr)
		return -1;

	if (ns_initparse(dns, dlen, &msg) < 0)
		goto out;
	if (ns_msg_count(msg, ns_s_qd) != 1) {
		race_dbg("parse_dns_data: query count err, count=%d\n", ns_msg_count(msg, ns_s_qd));
		goto out;
	}
	if (!!(msg._flags & 0x8000) != response) {
		race_dbg("parse_dns_data: not dns %s\n", response ? "response" : "query");
		goto out;
	}
	if (ns_parserr(&msg, ns_s_qd, 0, rr) < 0) {
		race_dbg("parse_dns_data: ns_parserr err\n");
		goto out;
	}
	if (rr->type != ns_t_a && rr->type != ns_t_aaaa) {
		race_dbg("parse_dns_data: not a or aaaa dns\n");
		goto out;
	}
	if (dn_expand(dns, dns + dlen, dns + NS_HFIXEDSZ, key->domain, DNS_DOMAIN_LEN) <= 0) {
		race_dbg("parse_dns_data: dns domain err\n");
		goto out;
	}
	info->has_answer = false;
	info->type = rr->type;
	info->txn_id = ns_msg_id(msg);

	if (response) {
		race_dbg("parse_dns_data: downlink_stat: answer_count=%d\n",
			 ns_msg_count(msg, ns_s_an));
		for (i = 0; i < ns_msg_count(msg, ns_s_an); i++) {
			if (ns_parserr(&msg, ns_s_an, i, rr) < 0) {
				race_dbg("parse_dns_data: downlink_stat: dns answer err\n");
				goto out;
			}
			if ((rr->type == ns_t_a && rr->rdlength == 4) ||
			    (rr->type == ns_t_aaaa && rr->rdlength == 16)) {
				info->has_answer = true;
				race_dbg("dns_response_answer: addr=%*phN\n", rr->rdlength, rr->rdata);
				break;
			}
		}
	}
	race_dbg("parse_dns_data: %s: uid=%d, query_type=%d, trans_id=%04x\n",
		 response ? "downlink_stat" : "uplink_stat", key->uid, info->type, info->txn_id);
	ret = 0;
out:
	kfree(rr);
	return ret;
}

/* the owning socket of a port-53 packet: skb->sk or a UDP lookup */
static struct sock *race_dns_sock(struct sk_buff *skb, bool v6)
{
	struct sock *sk = skb_to_full_sk(skb);
	struct net *net = dev_net(skb->dev);
	struct udphdr *uh = udp_hdr(skb);

	if (sk)
		return sk;
	if (v6)
		sk = __udp6_lib_lookup(net, &ipv6_hdr(skb)->saddr, uh->source,
				       &ipv6_hdr(skb)->daddr, uh->dest, inet6_iif(skb),
				       0, &udp_table, skb);
	else
		sk = __udp4_lib_lookup(net, ip_hdr(skb)->saddr, uh->source,
				       ip_hdr(skb)->daddr, uh->dest, inet_iif(skb),
				       0, &udp_table, skb);
	if (!sk)
		race_dbg("skb_dns_v%c_check: sk is null\n", v6 ? '6' : '4');
	return sk;
}

/* UDP with port 53 on the server side; returns false to skip */
static bool skb_dns_check(struct sk_buff *skb, bool v6, bool downlink)
{
	struct udphdr *uh;
	u8 proto;

	if (!skb->dev) {
		race_dbg("!dev\n");
		return false;
	}
	if (v6 ? skb->protocol != htons(ETH_P_IPV6) : skb->protocol != htons(ETH_P_IP))
		return false;
	proto = v6 ? ipv6_hdr(skb)->nexthdr : ip_hdr(skb)->protocol;
	if (proto != IPPROTO_UDP)
		return false;
	uh = udp_hdr(skb);
	return (downlink ? uh->source : uh->dest) == htons(53);
}

static u32 race_sock_uid(struct sock *sk)
{
	u32 uid;

	if (!sk || !sk_fullsock(sk) || !sk->sk_socket)
		return 0;
	uid = __kuid_val(sk->sk_uid);
	race_dbg("get_uid_from_sock: sk_uid=%u\n", uid);
	return uid;
}

/* ---- uplink: remember queries --------------------------------------------- */

static struct dns_query_node *find_query_node(const struct race_key *key, u32 h)
{
	struct dns_query_node *q;

	hash_for_each_possible(s_dns_query_map, q, node, h)
		if (q->key.uid == key->uid && !strcmp(q->key.domain, key->domain))
			return q;
	return NULL;
}

static void dns_race_uplink_stat(struct sk_buff *skb, struct sock *sk)
{
	struct race_key key = {};
	struct race_dns_info info;
	struct dns_query_node *q;
	struct sk_buff **slot;
	bool created = false;
	u32 h;

	key.uid = race_sock_uid(sk);
	if (!key.uid) {
		race_dbg("uplink_stat: uid is 0\n");
		return;
	}
	if (parse_dns_data(skb, &key, &info, false))
		return;
	h = race_hash_str(key.uid, key.domain);

	spin_lock_bh(&s_dns_race_lock);
	q = find_query_node(&key, h);
	if (!q) {
		q = kzalloc(sizeof(*q), GFP_ATOMIC);
		if (!q) {
			race_dbg("create_dns_query_node: kmalloc failed!\n");
			goto out;
		}
		q->key = key;
		created = true;
	}
	if (info.type == ns_t_aaaa) {
		slot = &q->skb_aaaa;
		q->has_aaaa = true;
		q->txn_aaaa = info.txn_id;
		q->time_aaaa = race_now_ms();
	} else {
		slot = &q->skb_a;
		q->has_a = true;
		q->txn_a = info.txn_id;
		q->time_a = race_now_ms();
	}
	race_free_skb(*slot);
	*slot = race_copy_skb(skb, sk);
	if (!*slot) {
		race_dbg("%s_dns_query_node: skb_copy %s query failed!\n",
			 created ? "create" : "update", info.type == ns_t_aaaa ? "AAAA" : "A");
		if (created) {
			race_free_skb(q->skb_a);
			kfree(q);
		} else {
			remove_dns_query_node(q);
		}
		goto out;
	}
	if (created)
		hash_add(s_dns_query_map, &q->node, h);
	race_dbg("uplink_stat: %s_dns_query_node, trans id=%04x, sk=%p\n",
		 created ? "insert" : "update", info.txn_id, sk);
out:
	spin_unlock_bh(&s_dns_race_lock);
}

/* ---- downlink: pair answers with the other family ------------------------- */

static u32 rsp_hash(u32 uid, u16 txn_id, const char *domain)
{
	return race_hash_str(uid ^ ((u32)txn_id << 16), domain);
}

/* called with s_dns_race_lock held; takes over @q */
static void race_keep_pending(struct dns_query_node *q, u32 uid, u16 txn_id,
			      struct sk_buff *pending)
{
	struct dns_rsp_node *r, *old;
	u32 h;

	r = kzalloc(sizeof(*r), GFP_ATOMIC);
	if (!r) {
		race_dbg("create_dns_rsp_node: kmalloc failed!\n");
		goto out;
	}
	r->uid = uid;
	r->txn_id = txn_id;
	r->time = race_now_ms();
	strscpy(r->domain, q->key.domain, sizeof(r->domain));
	r->skb = race_copy_skb(pending, pending->sk);
	if (!r->skb) {
		race_dbg("create_dns_rsp_node: skb_copy failed!\n");
		kfree(r);
		goto out;
	}
	h = rsp_hash(uid, txn_id, r->domain);
	hash_for_each_possible(s_dns_response_map, old, node, h)
		if (old->uid == uid && old->txn_id == txn_id && !strcmp(old->domain, r->domain)) {
			remove_dns_rsp_node(old);
			break;
		}
	hash_add(s_dns_response_map, &r->node, h);
	race_dbg("upsert_dns_rsp_node: inserted uid=%u trans_id=%04x\n", uid, txn_id);
out:
	remove_dns_query_node(q);
}

static void dns_race_downlink_stat(struct sk_buff *skb, struct sock *sk)
{
	struct race_key key = {};
	struct race_dns_info info;
	struct dns_rsp_node *r;
	struct dns_query_node *q;

	if (parse_dns_data(skb, &key, &info, true))
		return;

	key.uid = race_sock_uid(sk);
	if (!key.uid) {
		race_dbg("downlink_stat: uid is 0\n");
		return;
	}

	spin_lock_bh(&s_dns_race_lock);
	/* the pending query got its own answer after all */
	hash_for_each_possible(s_dns_response_map, r, node,
			       rsp_hash(key.uid, info.txn_id, key.domain)) {
		if (r->uid == key.uid && r->txn_id == info.txn_id &&
		    !strcmp(r->domain, key.domain)) {
			remove_dns_rsp_node(r);
			goto out;
		}
	}

	q = find_query_node(&key, race_hash_str(key.uid, key.domain));
	if (!q || !((q->has_a && q->txn_a == info.txn_id) ||
		    (q->has_aaaa && q->txn_aaaa == info.txn_id))) {
		race_dbg("downlink_stat: target_node is NULL\n");
		goto out;
	}
	if (!q->has_a || !q->skb_a) {
		remove_dns_query_node(q);
		race_dbg("downlink_stat: only AAAA query\n");
		goto out;
	}
	if (!q->has_aaaa || !q->skb_aaaa) {
		remove_dns_query_node(q);
		race_dbg("downlink_stat: only A query\n");
		goto out;
	}
	if (!info.has_answer) {
		remove_dns_query_node(q);
		race_dbg("downlink_stat: invalid response\n");
		goto out;
	}
	if (info.type == ns_t_a)
		race_keep_pending(q, key.uid, q->txn_aaaa, q->skb_aaaa);
	else
		race_keep_pending(q, key.uid, q->txn_a, q->skb_a);
	race_dbg("downlink_stat: upsert_dns_rsp_node trans id=%04x\n", info.txn_id);
out:
	spin_unlock_bh(&s_dns_race_lock);
}

/* ---- the forged answer ------------------------------------------------------ */

/* turn a copy of the pending query into an empty NOERROR answer to it */
static struct sk_buff *gen_dns_response(struct sk_buff *query)
{
	struct sk_buff *skb;
	struct udphdr *uh;
	__be16 app_port;
	u8 *dns;
	int len;

	skb = skb_copy_expand(query, skb_headroom(query), skb_tailroom(query), GFP_ATOMIC);
	if (!skb) {
		race_dbg("gen_dns_response: skb_copy_expand failed!\n");
		return NULL;
	}
	skb->dev = NULL;
	skb_reset_mac_header(skb);
	if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);

		swap(ip6h->saddr, ip6h->daddr);
	} else {
		struct iphdr *iph = ip_hdr(skb);

		swap(iph->saddr, iph->daddr);
		ip_send_check(iph);
	}

	uh = udp_hdr(skb);
	app_port = uh->source;
	uh->source = htons(53);
	uh->dest = app_port;
	uh->check = 0;
	dns = (u8 *)(uh + 1);
	dns[2] = 0x81;			/* QR | RD */
	dns[3] = 0x80;			/* RA, NOERROR */
	memset(dns + 6, 0, 6);		/* no answer/authority/additional */

	len = ntohs(uh->len);
	if (skb->protocol == htons(ETH_P_IPV6))
		uh->check = csum_ipv6_magic(&ipv6_hdr(skb)->saddr, &ipv6_hdr(skb)->daddr,
					    len, IPPROTO_UDP, csum_partial(uh, len, 0));
	else
		uh->check = csum_tcpudp_magic(ip_hdr(skb)->saddr, ip_hdr(skb)->daddr,
					      len, IPPROTO_UDP, csum_partial(uh, len, 0));
	if (!uh->check)
		uh->check = CSUM_MANGLED_0;
	/* the copy may carry CHECKSUM_PARTIAL from the query; this one is complete */
	skb->ip_summed = CHECKSUM_NONE;
	nf_ct_attach(skb, query);
	return skb;
}

static void send_fake_response(struct sk_buff *skb, struct sock *sk)
{
	struct net *net = sock_net(sk);
	int ret;

	skb->mark |= RACE_RESENT_MARK;
	if (skb->protocol == htons(ETH_P_IPV6)) {
		if (ip6_route_me_harder(net, sk, skb)) {
			race_dbg("send_fake_response: ip6_route_me_harder error\n");
			kfree_skb(skb);
			return;
		}
		ret = ip6_local_out(net, sk, skb);
		race_dbg("send_fake_response: ip6_local_out %d\n", ret);
	} else {
		if (ip_route_me_harder(net, sk, skb, RTN_UNSPEC)) {
			race_dbg("send_fake_response: ip_route_me_harder error\n");
			kfree_skb(skb);
			return;
		}
		ret = ip_local_out(net, sk, skb);
		race_dbg("send_fake_response: ip_local_out %d\n", ret);
	}
}

int request_dns_race(const char *domain, size_t len, u32 uid)
{
	char name[DNS_DOMAIN_LEN];
	struct sk_buff *rsp = NULL;
	struct dns_rsp_node *r;
	struct sock *sk = NULL;
	int bkt;

	if (!READ_ONCE(dns_opt_race_enable))
		return -1;
	if (!domain || !len || !uid) {
		race_dbg("request_dns_race: invalid param\n");
		return -1;
	}
	len = min_t(size_t, len, DNS_DOMAIN_LEN - 1);
	memcpy(name, domain, len);
	name[len] = '\0';

	spin_lock_bh(&s_dns_race_lock);
	hash_for_each(s_dns_response_map, bkt, r, node) {
		if (r->uid == uid && !strcmp(r->domain, name))
			goto found;
	}
	spin_unlock_bh(&s_dns_race_lock);
	race_dbg("request_dns_race: not found, uid=%d, domain=%s\n", uid, name);
	return -1;

found:
	sk = r->skb->sk;
	if (!sk || !sk_fullsock(sk)) {
		race_dbg("request_dns_race: sk not fullsock\n");
		sk = NULL;
	} else if (!sk->sk_socket) {
		race_dbg("request_dns_race: sk closed\n");
		sk = NULL;
	} else {
		sock_hold(sk);
		rsp = gen_dns_response(r->skb);
	}
	remove_dns_rsp_node(r);
	spin_unlock_bh(&s_dns_race_lock);

	if (!sk)
		return -1;
	if (!rsp) {
		race_dbg("request_dns_race: rsp_skb is NULL, uid=%d, domain=%s\n", uid, name);
		sock_put(sk);
		return -1;
	}
	send_fake_response(rsp, sk);
	sock_put(sk);
	dns_opt_race_answered++;
	race_dbg("request_dns_race: send fake response success, uid=%d, domain=%s\n", uid, name);
	return 0;
}

/* ---- housekeeping ----------------------------------------------------------- */

/* expire nodes older than 10 s */
static void dns_race_check_timer_fn(struct timer_list *t)
{
	struct dns_query_node *q;
	struct dns_rsp_node *r;
	struct hlist_node *tmp;
	u64 now = race_now_ms();
	int bkt;

	spin_lock_bh(&s_dns_race_lock);
	hash_for_each_safe(s_dns_query_map, bkt, tmp, q, node)
		if ((q->has_a && now - q->time_a >= RACE_NODE_TTL_MS) ||
		    (q->has_aaaa && now - q->time_aaaa >= RACE_NODE_TTL_MS))
			remove_dns_query_node(q);
	hash_for_each_safe(s_dns_response_map, bkt, tmp, r, node)
		if (now - r->time >= RACE_NODE_TTL_MS)
			remove_dns_rsp_node(r);
	spin_unlock_bh(&s_dns_race_lock);
	if (READ_ONCE(dns_opt_race_enable))
		mod_timer(&s_race_check_timer, jiffies + RACE_CHECK_PERIOD);
}

/* ---- hooks and control ------------------------------------------------------ */

static unsigned int dns_race_postrouting_hook4(void *priv, struct sk_buff *skb,
					       const struct nf_hook_state *state)
{
	if (READ_ONCE(dns_opt_race_enable) && skb_dns_check(skb, false, false))
		dns_race_uplink_stat(skb, race_dns_sock(skb, false));
	return NF_ACCEPT;
}

static unsigned int dns_race_prerouting_hook4(void *priv, struct sk_buff *skb,
					      const struct nf_hook_state *state)
{
	if (READ_ONCE(dns_opt_race_enable) && skb_dns_check(skb, false, true))
		dns_race_downlink_stat(skb, race_dns_sock(skb, false));
	return NF_ACCEPT;
}

static unsigned int dns_race_postrouting_hook6(void *priv, struct sk_buff *skb,
					       const struct nf_hook_state *state)
{
	if (READ_ONCE(dns_opt_race_enable) && skb_dns_check(skb, true, false))
		dns_race_uplink_stat(skb, race_dns_sock(skb, true));
	return NF_ACCEPT;
}

static unsigned int dns_race_prerouting_hook6(void *priv, struct sk_buff *skb,
					      const struct nf_hook_state *state)
{
	if (READ_ONCE(dns_opt_race_enable) && skb_dns_check(skb, true, true))
		dns_race_downlink_stat(skb, race_dns_sock(skb, true));
	return NF_ACCEPT;
}

static const struct nf_hook_ops dns_race_netfilter_ops[] = {
	{ .hook = dns_race_postrouting_hook4, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_POST_ROUTING, .priority = 1 },
	{ .hook = dns_race_prerouting_hook4, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_PRE_ROUTING, .priority = 1 },
	{ .hook = dns_race_postrouting_hook6, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_POST_ROUTING, .priority = 1 },
	{ .hook = dns_race_prerouting_hook6, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_PRE_ROUTING, .priority = 1 },
};

/* called by the net.dns_optimizer.race sysctl handler after a change */
void dns_race_set_enable(bool enable)
{
	if (enable) {
		mod_timer(&s_race_check_timer, jiffies + RACE_CHECK_PERIOD);
	} else {
		del_timer_sync(&s_race_check_timer);
		dns_race_clear_all_maps();
	}
}

int dns_race_init(void)
{
	int ret;

	/* housekeeping only: never wake an idle CPU for it */
	timer_setup(&s_race_check_timer, dns_race_check_timer_fn, TIMER_DEFERRABLE);
	ret = nf_register_net_hooks(&init_net, dns_race_netfilter_ops,
				    ARRAY_SIZE(dns_race_netfilter_ops));
	if (ret < 0) {
		pr_err("[%s]: netfilter register failed, ret=%d\n", TAG, ret);
		return ret;
	}
	if (READ_ONCE(dns_opt_race_enable))
		dns_race_set_enable(true);
	return 0;
}

void dns_race_exit(void)
{
	nf_unregister_net_hooks(&init_net, dns_race_netfilter_ops,
				ARRAY_SIZE(dns_race_netfilter_ops));
	del_timer_sync(&s_race_check_timer);
	dns_race_clear_all_maps();
}

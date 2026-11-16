// SPDX-License-Identifier: GPL-2.0-only
/*
 * DNS fast retransmit: every outgoing A/AAAA query of an app (uid != 0) is
 * copied and kept, keyed by DNS transaction id, with a timeout of
 * min(8 * smoothed RTT, 2 s) (2 s before the first sample). Answers
 * (LOCAL_IN) cancel their query and feed the RTT estimator. When a query
 * times out:
 *  - if the race path (dns_race.c) can answer it, it is not re-sent;
 *  - the first time, the kept copy is re-sent (marked so the hooks ignore
 *    it) and the query's key is remembered for 10 s;
 *  - the app's own retry of a query already re-sent is not re-sent again.
 * Queries for example.com (CTS) are left alone.
 *
 * Ported from the OnePlus 15 oplus_network_dns_optimizer.ko fast
 * retransmit part (reconstructed source in varakumar02/oplus-op15-modules),
 * with the OPLUS data_module netlink control replaced by the
 * net.dns_optimizer sysctls and the reserve-cache answer path left out.
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/sysctl.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <asm/unaligned.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/net_namespace.h>

#include "dns_optimizer.h"
#include "dns_resolv.h"

#define TAG			"dns_fast_retransmit"
#define FRTX_MAX_RTO_US		2000000
#define KEY_INFO_TTL		(10 * HZ)
#define KEY_INFO_MAX		3000

#define frtx_dbg(fmt, ...) dns_opt_dbg(TAG, fmt, ##__VA_ARGS__)

/* one outstanding query */
struct dns_query_entry {
	u16 txn_id;
	u64 query_time;			/* ktime ns */
	u32 uid;
	u16 type;
	char domain[DNS_DOMAIN_LEN];
	struct hlist_node hnode;	/* s_txn_id_hash_table */
	struct sk_buff *skb;		/* copy kept for the retransmit */
	unsigned long expire_jiffies;
	struct rb_node rbnode;		/* s_event_queue, by expire_jiffies */
	bool sent;
	struct list_head expired;	/* timer handler's work list */
};

/* a query already retransmitted once */
struct dns_entry_key_info {
	u16 txn_id;
	u32 uid;
	u16 type;
	char domain[DNS_DOMAIN_LEN];
	struct list_head list;
};

static DEFINE_SPINLOCK(s_dns_entry_lock);
static DEFINE_HASHTABLE(s_txn_id_hash_table, 10);

/* expiry queue; state: 0 idle, 1 armed, 2 handler running */
static struct {
	struct rb_root root;
	struct timer_list timer;
	atomic_t state;
} s_event_queue;

static DEFINE_SPINLOCK(s_entry_key_info_lock);
static LIST_HEAD(s_entry_key_info_list);
static atomic_t s_entry_key_info_cnt;
static struct timer_list s_entry_key_info_cleanup_timer;

/* TCP-style estimator: srtt << 3, mdev, mdev_max, rttvar (us) */
static struct {
	u32 srtt_us, mdev_us, mdev_max_us, rttvar_us;
} s_dns_rtt_stats;

/* ---- send ----------------------------------------------------------------- */

/* route and send a locally generated copy; always consumes *pskb */
static int dns_rtx_skb(struct net *net, struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	int ret;

	if (!net || !skb)
		return -EINVAL;
	if (skb->protocol == htons(ETH_P_IPV6)) {
		if (ip6_route_me_harder(net, NULL, skb))
			goto unreach;
		ret = ip6_local_out(net, NULL, skb);
	} else if (skb->protocol == htons(ETH_P_IP)) {
		if (ip_route_me_harder(net, NULL, skb, RTN_UNSPEC))
			goto unreach;
		ret = ip_local_out(net, NULL, skb);
	} else {
		consume_skb(skb);
		ret = -EPROTONOSUPPORT;
	}
	*pskb = NULL;
	return ret;
unreach:
	consume_skb(skb);
	*pskb = NULL;
	return -EHOSTUNREACH;
}

/* ---- expiry queue ---------------------------------------------------------- */

static void event_queue_arm(unsigned long expires)
{
	if (atomic_cmpxchg(&s_event_queue.state, 0, 1) == 0) {
		mod_timer(&s_event_queue.timer, expires);
		frtx_dbg("need_restart_timer, entry->expire_jiffies %lu\n", expires);
	} else {
		frtx_dbg("activate timer failed\n");
	}
}

/* called with s_dns_entry_lock held */
static void event_queue_insert(struct dns_query_entry *e)
{
	struct rb_node **p = &s_event_queue.root.rb_node, *parent = NULL;

	while (*p) {
		struct dns_query_entry *cur = rb_entry(*p, struct dns_query_entry, rbnode);

		parent = *p;
		frtx_dbg("cur->expire_jiffies %lu, entry->expire_jiffies %lu\n",
			 cur->expire_jiffies, e->expire_jiffies);
		if (time_before(e->expire_jiffies, cur->expire_jiffies))
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&e->rbnode, parent, p);
	rb_insert_color(&e->rbnode, &s_event_queue.root);

	/* re-arm when this query is now the next to expire */
	if (rb_first(&s_event_queue.root) == &e->rbnode) {
		if (timer_pending(&s_event_queue.timer)) {
			del_timer(&s_event_queue.timer);
			atomic_set(&s_event_queue.state, 0);
		}
		event_queue_arm(e->expire_jiffies);
	}
}

/* called with s_dns_entry_lock held */
static void event_queue_remove(struct dns_query_entry *e)
{
	struct rb_node *first;

	if (RB_EMPTY_NODE(&e->rbnode))
		return;
	first = rb_first(&s_event_queue.root);
	rb_erase(&e->rbnode, &s_event_queue.root);
	RB_CLEAR_NODE(&e->rbnode);
	if (first != &e->rbnode)
		return;
	del_timer(&s_event_queue.timer);
	atomic_set(&s_event_queue.state, 0);
	first = rb_first(&s_event_queue.root);
	if (first)
		event_queue_arm(rb_entry(first, struct dns_query_entry, rbnode)->expire_jiffies);
}

static struct dns_query_entry *find_dns_query_entry(u16 txn_id)
{
	struct dns_query_entry *e;

	hash_for_each_possible(s_txn_id_hash_table, e, hnode, txn_id)
		if (e->txn_id == txn_id)
			return e;
	return NULL;
}

static void free_dns_query_entry(struct dns_query_entry *e)
{
	if (e->skb)
		consume_skb(e->skb);
	kfree(e);
}

/* ---- retransmit keys ------------------------------------------------------- */

static void entry_key_info_flush(void)
{
	struct dns_entry_key_info *k, *tmp;

	spin_lock_bh(&s_entry_key_info_lock);
	list_for_each_entry_safe(k, tmp, &s_entry_key_info_list, list) {
		list_del(&k->list);
		kfree(k);
	}
	atomic_set(&s_entry_key_info_cnt, 0);
	spin_unlock_bh(&s_entry_key_info_lock);
}

static void retransmit_info_cleanup_timer_fn(struct timer_list *t)
{
	frtx_dbg("retransmit_info_cleanup: s_entry_key_info_cnt = %d\n",
		 atomic_read(&s_entry_key_info_cnt));
	entry_key_info_flush();
	mod_timer(&s_entry_key_info_cleanup_timer, jiffies + KEY_INFO_TTL);
}

/* take the saved key for (@txn_id, @domain); true if it was there */
static bool take_entry_key_info(u16 txn_id, const char *domain, u32 *uid, u16 *type)
{
	struct dns_entry_key_info *k;

	spin_lock_bh(&s_entry_key_info_lock);
	list_for_each_entry(k, &s_entry_key_info_list, list) {
		if (k->txn_id != txn_id || strcmp(k->domain, domain))
			continue;
		*uid = k->uid;
		*type = k->type;
		list_del(&k->list);
		kfree(k);
		atomic_dec(&s_entry_key_info_cnt);
		spin_unlock_bh(&s_entry_key_info_lock);
		return true;
	}
	spin_unlock_bh(&s_entry_key_info_lock);
	return false;
}

static void save_entry_key_info_for_reverse(const struct dns_query_entry *e)
{
	struct dns_entry_key_info *k = kzalloc(sizeof(*k), GFP_ATOMIC);
	int cnt;

	if (!k) {
		pr_info("[%s]: ERROR: Failed to allocate retransmit_info\n", TAG);
		return;
	}
	k->txn_id = e->txn_id;
	k->uid = e->uid;
	k->type = e->type;
	strscpy(k->domain, e->domain, sizeof(k->domain));
	spin_lock_bh(&s_entry_key_info_lock);
	list_add(&k->list, &s_entry_key_info_list);
	cnt = atomic_fetch_inc(&s_entry_key_info_cnt);
	spin_unlock_bh(&s_entry_key_info_lock);
	if (cnt > KEY_INFO_MAX)
		mod_timer(&s_entry_key_info_cleanup_timer, jiffies);
	frtx_dbg("saved dns entry key info: txn_id=0x%04x, uid=%u, type=%u, domain=%s\n",
		 k->txn_id, k->uid, k->type, k->domain);
}

/* ---- timeout ---------------------------------------------------------------- */

static void dns_query_retransmit(struct dns_query_entry *e)
{
	u32 uid;
	u16 type;
	int ret;

	ret = request_dns_race(e->domain, strnlen(e->domain, DNS_DOMAIN_LEN), e->uid);
	frtx_dbg("race_is_valid = %d\n", ret);
	if (!ret) {
		frtx_dbg("race send rsp don't need retransmit\n");
		return;
	}

	/* the app retried a query we already re-sent: leave it to the app */
	if (take_entry_key_info(e->txn_id, e->domain, &uid, &type)) {
		frtx_dbg("txn_id=0x%04x already re-sent once\n", e->txn_id);
		return;
	}

	frtx_dbg("dns query fast retransmit for txn_id 0x%04x\n", e->txn_id);
	save_entry_key_info_for_reverse(e);
	if (!e->skb) {
		frtx_dbg("skb have been freed for txn_id 0x%04x\n", e->txn_id);
		return;
	}
	e->skb->mark |= DNS_OPT_RESENT_MARK;
	ret = dns_rtx_skb(&init_net, &e->skb);
	if (ret < 0)
		frtx_dbg("dns query fast retransmit failed for txn_id 0x%04x, ret %d\n",
			 e->txn_id, ret);
	else if (ret)
		frtx_dbg("dns query fast retransmit not sent (NET_XMIT=%d) for txn_id 0x%04x\n",
			 ret, e->txn_id);
	else
		frtx_dbg("dns query fast retransmit sent for txn_id 0x%04x\n", e->txn_id);
	dns_opt_retransmits++;
	e->sent = true;
}

static void dns_query_event_handler(struct timer_list *t)
{
	struct dns_query_entry *e, *tmp;
	unsigned long now = jiffies;
	struct rb_node *node;
	bool rearmed = false;
	LIST_HEAD(expired);

	if (atomic_cmpxchg(&s_event_queue.state, 1, 2) != 1)
		return;

	spin_lock_bh(&s_dns_entry_lock);
	while ((node = rb_first(&s_event_queue.root))) {
		e = rb_entry(node, struct dns_query_entry, rbnode);
		frtx_dbg("dns_query_event_handler: txn_id 0x%04x, expire_jiffies=%lu, now=%lu\n",
			 e->txn_id, e->expire_jiffies, now);
		if (time_before(now, e->expire_jiffies)) {
			atomic_set(&s_event_queue.state, 0);
			frtx_dbg("rb first node expire_jiffies > now, timer should restart\n");
			event_queue_arm(e->expire_jiffies);
			rearmed = true;
			break;
		}
		frtx_dbg("collect expired dns query entry, txn_id 0x%04x\n", e->txn_id);
		rb_erase(node, &s_event_queue.root);
		RB_CLEAR_NODE(node);
		hash_del(&e->hnode);
		list_add(&e->expired, &expired);
	}
	spin_unlock_bh(&s_dns_entry_lock);

	list_for_each_entry_safe(e, tmp, &expired, expired) {
		list_del(&e->expired);
		dns_query_retransmit(e);
		free_dns_query_entry(e);
	}
	if (!rearmed)
		atomic_set(&s_event_queue.state, 0);
}

/* ---- hooks ----------------------------------------------------------------- */

/* UDP to/from port 53, linear; returns the UDP header or NULL */
static struct udphdr *frtx_dns_udp(struct sk_buff *skb)
{
	struct udphdr *uh;
	u8 proto;

	if (skb->protocol == htons(ETH_P_IPV6))
		proto = ipv6_hdr(skb)->nexthdr;
	else if (skb->protocol == htons(ETH_P_IP))
		proto = ip_hdr(skb)->protocol;
	else
		return NULL;
	if (proto != IPPROTO_UDP)
		return NULL;
	uh = udp_hdr(skb);
	if (uh->source != htons(53) && uh->dest != htons(53))
		return NULL;
	return uh;
}

/* DNS header checks shared by both hooks; returns the header or NULL */
static u8 *frtx_dns_hdr(struct sk_buff *skb, bool response)
{
	struct udphdr *uh;
	u8 *dns;

	if (skb_linearize(skb)) {
		pr_info("[%s]: skb linearized failed\n", TAG);
		return NULL;
	}
	uh = udp_hdr(skb);
	if (skb->len < 28 || ntohs(uh->len) < 4)
		return NULL;
	dns = (u8 *)(uh + 1);
	if (!!(dns[2] & 0x80) != response)	/* QR */
		return NULL;
	return dns;
}

static unsigned int dns_fast_retransmit_dns_query(void *priv, struct sk_buff *skb,
						      const struct nf_hook_state *state)
{
	char domain[DNS_DOMAIN_LEN] = {};
	struct dns_query_entry *e;
	struct udphdr *uh;
	struct sock *sk;
	ns_msg msg;
	ns_rr *rr;
	u8 *dns;
	u32 uid, dlen;
	u16 txn_id;
	int found;

	if (!READ_ONCE(dns_opt_fast_retransmit_enable) || !frtx_dns_udp(skb))
		return NF_ACCEPT;
	if (skb->mark & DNS_OPT_RESENT_MARK)
		return NF_ACCEPT;
	dns = frtx_dns_hdr(skb, false);
	if (!dns)
		return NF_ACCEPT;
	txn_id = get_unaligned_be16(dns);

	spin_lock_bh(&s_dns_entry_lock);
	found = !!find_dns_query_entry(txn_id);
	spin_unlock_bh(&s_dns_entry_lock);
	if (found) {
		frtx_dbg("find_dns_query_entry: txn_id 0x%04x\n", txn_id);
		return NF_ACCEPT;
	}

	sk = skb_to_full_sk(skb);
	if (!sk || !sk_fullsock(sk) || !sk->sk_socket) {
		frtx_dbg("sk is null\n");
		return NF_ACCEPT;
	}
	uid = __kuid_val(sk->sk_uid);
	frtx_dbg("get_uid_from_sock: sk_uid=%u\n", uid);
	if (!uid) {
		frtx_dbg("uid is 0\n");
		return NF_ACCEPT;
	}

	/* parse_dns_data: an A/AAAA question with a sane name */
	uh = udp_hdr(skb);
	dlen = ntohs(uh->len);
	if (dlen <= 8) {
		frtx_dbg("parse_dns_data err\n");
		return NF_ACCEPT;
	}
	dlen -= 8;
	rr = kzalloc(sizeof(*rr), GFP_ATOMIC);
	if (!rr)
		return NF_ACCEPT;
	if (ns_initparse(dns, dlen, &msg) < 0 || ns_parserr(&msg, ns_s_qd, 0, rr) < 0) {
		frtx_dbg("parse_dns_data: ns_parserr err\n");
		goto out_rr;
	}
	if (rr->type != ns_t_a && rr->type != ns_t_aaaa) {
		frtx_dbg("parse_dns_data: not a or aaaa dns\n");
		goto out_rr;
	}
	if (dn_expand(dns, dns + dlen, dns + NS_HFIXEDSZ, domain, sizeof(domain)) <= 0) {
		frtx_dbg("parse_dns_data: dns domain err\n");
		goto out_rr;
	}
	if (strstr(domain, "example.com")) {
		frtx_dbg("Bypass domain: %s for cts test\n", domain);
		goto out_rr;
	}

	e = kzalloc(sizeof(*e), GFP_ATOMIC);
	if (!e) {
		pr_info("[%s]: kzalloc buffer failed for txn_id 0x%04x\n", TAG, txn_id);
		goto out_rr;
	}
	INIT_LIST_HEAD(&e->expired);
	RB_CLEAR_NODE(&e->rbnode);
	e->uid = uid;
	e->type = rr->type;
	strscpy(e->domain, domain, sizeof(e->domain));
	e->txn_id = txn_id;
	e->query_time = ktime_get();
	e->skb = skb_copy(skb, GFP_ATOMIC);
	if (!e->skb) {
		pr_info("[%s]: skb_copy failed for txn_id 0x%04x\n", TAG, txn_id);
		kfree(e);
		goto out_rr;
	}
	e->skb->dev = NULL;
	nf_reset_ct(e->skb);
	nf_ct_set(e->skb, NULL, IP_CT_UNTRACKED);
	e->expire_jiffies = jiffies + (s_dns_rtt_stats.srtt_us ?
		usecs_to_jiffies(min_t(u32, s_dns_rtt_stats.srtt_us, FRTX_MAX_RTO_US)) :
		usecs_to_jiffies(FRTX_MAX_RTO_US));

	spin_lock_bh(&s_dns_entry_lock);
	event_queue_insert(e);
	hash_add(s_txn_id_hash_table, &e->hnode, txn_id);
	spin_unlock_bh(&s_dns_entry_lock);
	frtx_dbg("completed register and insert rb tree for txn_id 0x%04x, expire_jiffies=%lu\n",
		 txn_id, e->expire_jiffies);
out_rr:
	kfree(rr);
	return NF_ACCEPT;
}

static void dns_rtt_update(u32 m)
{
	s32 dm;

	if (!s_dns_rtt_stats.srtt_us) {
		s_dns_rtt_stats.srtt_us = m << 3;
		s_dns_rtt_stats.mdev_us = m << 1;
		s_dns_rtt_stats.mdev_max_us = s_dns_rtt_stats.mdev_us;
	} else {
		dm = (s32)(m - (s_dns_rtt_stats.srtt_us >> 3));
		s_dns_rtt_stats.srtt_us += dm;
		if (dm < 0) {
			dm = -dm - (s_dns_rtt_stats.mdev_us >> 2);
			if (dm > 0)
				dm >>= 3;
		} else {
			dm -= s_dns_rtt_stats.mdev_us >> 2;
		}
		s_dns_rtt_stats.mdev_us += dm;
		if (s_dns_rtt_stats.mdev_us > s_dns_rtt_stats.mdev_max_us) {
			s_dns_rtt_stats.mdev_max_us = s_dns_rtt_stats.mdev_us;
			if (s_dns_rtt_stats.mdev_max_us > s_dns_rtt_stats.rttvar_us)
				s_dns_rtt_stats.rttvar_us = s_dns_rtt_stats.mdev_max_us;
		}
	}
	if (s_dns_rtt_stats.srtt_us < 2)
		s_dns_rtt_stats.srtt_us = 1;
	frtx_dbg("srtt_us: %u us, mdev_us: %u us, mdev_max_us: %u us\n",
		 s_dns_rtt_stats.srtt_us, s_dns_rtt_stats.mdev_us,
		 s_dns_rtt_stats.mdev_max_us);
}

static unsigned int dns_fast_retransmit_dns_query_response(void *priv,
							       struct sk_buff *skb,
							       const struct nf_hook_state *state)
{
	struct dns_query_entry *e;
	u16 txn_id;
	u32 rtt;
	u8 *dns;

	if (!READ_ONCE(dns_opt_fast_retransmit_enable) || !frtx_dns_udp(skb))
		return NF_ACCEPT;
	dns = frtx_dns_hdr(skb, true);
	if (!dns)
		return NF_ACCEPT;
	txn_id = get_unaligned_be16(dns);

	spin_lock_bh(&s_dns_entry_lock);
	e = find_dns_query_entry(txn_id);
	if (!e) {
		frtx_dbg("find_dns_query_entry failed for txn_id 0x%04x\n", txn_id);
		spin_unlock_bh(&s_dns_entry_lock);
		return NF_ACCEPT;
	}
	hash_del(&e->hnode);
	event_queue_remove(e);
	spin_unlock_bh(&s_dns_entry_lock);

	rtt = div_u64(ktime_get() - e->query_time, NSEC_PER_USEC);
	dns_rtt_update(rtt);
	frtx_dbg("completed dns response for txn_id 0x%04x, rtt_us %u\n\n", e->txn_id, rtt);
	free_dns_query_entry(e);
	return NF_ACCEPT;
}

static const struct nf_hook_ops dns_fast_retransmit_netfilter_ops[] = {
	{ .hook = dns_fast_retransmit_dns_query, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_POST_ROUTING, .priority = 101 },
	{ .hook = dns_fast_retransmit_dns_query_response, .pf = NFPROTO_IPV4,
	  .hooknum = NF_INET_LOCAL_IN, .priority = 1 },
	{ .hook = dns_fast_retransmit_dns_query, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_POST_ROUTING, .priority = 101 },
	{ .hook = dns_fast_retransmit_dns_query_response, .pf = NFPROTO_IPV6,
	  .hooknum = NF_INET_LOCAL_IN, .priority = 1 },
};

/* ---- init / exit ------------------------------------------------------------ */

int dns_fast_retransmit_init(void)
{
	int ret;

	s_event_queue.root = RB_ROOT;
	atomic_set(&s_event_queue.state, 0);
	timer_setup(&s_event_queue.timer, dns_query_event_handler, 0);
	/* housekeeping only: never wake an idle CPU for it */
	timer_setup(&s_entry_key_info_cleanup_timer, retransmit_info_cleanup_timer_fn,
		    TIMER_DEFERRABLE);
	mod_timer(&s_entry_key_info_cleanup_timer, jiffies + KEY_INFO_TTL);

	ret = nf_register_net_hooks(&init_net, dns_fast_retransmit_netfilter_ops,
				    ARRAY_SIZE(dns_fast_retransmit_netfilter_ops));
	if (ret) {
		pr_err("[%s]: nf_register_net_hooks fail:ret=%d\n", TAG, ret);
		del_timer_sync(&s_entry_key_info_cleanup_timer);
		return ret;
	}
	return 0;
}

void dns_fast_retransmit_exit(void)
{
	struct dns_query_entry *e;
	struct hlist_node *tmp;
	struct rb_node *node;
	int bkt;

	nf_unregister_net_hooks(&init_net, dns_fast_retransmit_netfilter_ops,
				ARRAY_SIZE(dns_fast_retransmit_netfilter_ops));
	del_timer_sync(&s_entry_key_info_cleanup_timer);
	del_timer_sync(&s_event_queue.timer);

	spin_lock_bh(&s_dns_entry_lock);
	atomic_set(&s_event_queue.state, 0);
	while ((node = rb_first(&s_event_queue.root))) {
		rb_erase(node, &s_event_queue.root);
		RB_CLEAR_NODE(node);
	}
	hash_for_each_safe(s_txn_id_hash_table, bkt, tmp, e, hnode) {
		hash_del(&e->hnode);
		free_dns_query_entry(e);
	}
	spin_unlock_bh(&s_dns_entry_lock);
	entry_key_info_flush();
}

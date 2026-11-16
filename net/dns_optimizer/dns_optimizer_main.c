// SPDX-License-Identifier: GPL-2.0-only
/*
 * DNS optimizer: the race (dns_race.c) and fast retransmit
 * (dns_fast_retransmit.c) parts of the OnePlus 15
 * oplus_network_dns_optimizer.ko, controlled through
 * /proc/sys/net/dns_optimizer/:
 *
 *   race              1: answer a stalled A/AAAA query with an empty NOERROR
 *                        once the other family has an address
 *   fast_retransmit   1: re-send an unanswered query after min(8 * RTT, 2 s)
 *   debug             1: log every decision
 *   race_answered     (read-only) forged answers delivered
 *   retransmits       (read-only) queries re-sent
 */
#include <linux/module.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>

#include "dns_optimizer.h"

int dns_opt_race_enable = 1;
int dns_opt_fast_retransmit_enable = 1;
int dns_opt_debug;
int dns_opt_race_answered;
int dns_opt_retransmits;

static struct ctl_table_header *dns_opt_sysctl_hdr;

static int dns_opt_race_handler(struct ctl_table *table, int write,
				void *buffer, size_t *lenp, loff_t *ppos)
{
	int old = dns_opt_race_enable;
	int ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);

	if (!ret && write && old != dns_opt_race_enable)
		dns_race_set_enable(dns_opt_race_enable);
	return ret;
}

static struct ctl_table dns_opt_sysctl_table[] = {
	{
		.procname	= "race",
		.data		= &dns_opt_race_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= dns_opt_race_handler,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "fast_retransmit",
		.data		= &dns_opt_fast_retransmit_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "debug",
		.data		= &dns_opt_debug,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "race_answered",
		.data		= &dns_opt_race_answered,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "retransmits",
		.data		= &dns_opt_retransmits,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static int __init dns_optimizer_init(void)
{
	int ret;

	ret = dns_race_init();
	if (ret)
		return ret;
	ret = dns_fast_retransmit_init();
	if (ret)
		goto err_race;
	dns_opt_sysctl_hdr = register_net_sysctl(&init_net, "net/dns_optimizer",
						 dns_opt_sysctl_table);
	if (!dns_opt_sysctl_hdr) {
		ret = -ENOMEM;
		goto err_frtx;
	}
	return 0;

err_frtx:
	dns_fast_retransmit_exit();
err_race:
	dns_race_exit();
	return ret;
}

static void __exit dns_optimizer_exit(void)
{
	unregister_net_sysctl_table(dns_opt_sysctl_hdr);
	dns_fast_retransmit_exit();
	dns_race_exit();
}

late_initcall(dns_optimizer_init);
module_exit(dns_optimizer_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("DNS A/AAAA race answer and fast retransmit");

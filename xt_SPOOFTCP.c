#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/version.h>
#include <linux/percpu.h>
#include <linux/delay.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/ip6_route.h>
#include <net/tcp.h>
#include <net/addrconf.h>

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack.h>
#endif

#include "xt_SPOOFTCP.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#define nf_reset(a) nf_reset_ct(a)
#endif

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("LGA1150");
MODULE_DESCRIPTION("Xtables: Send spoofed TCP packets");
MODULE_ALIAS("ipt_SPOOFTCP");
MODULE_ALIAS("ip6t_SPOOFTCP");

static DEFINE_PER_CPU(bool, spooftcp_active);

static const char *const PAYLOAD_BUFF = "GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n";

static struct tcphdr * spooftcp_tcphdr_put(struct sk_buff *nskb, const struct tcphdr *otcph, const struct xt_spooftcp_info *info)
{
	struct tcphdr *tcph;
	u_int8_t * tcpopt;
	u_int8_t optoff;

	skb_reset_transport_header(nskb);
	tcph = (struct tcphdr *)skb_put(nskb, sizeof(struct tcphdr));
	memset(tcph, 0, sizeof(struct tcphdr));
	tcph->doff = sizeof(struct tcphdr)/4;
	tcph->source = otcph->source;
	tcph->dest = otcph->dest;
	/* Set flags */
	((u_int8_t *)tcph)[13] = info->tcp_flags;
	if (info->corrupt_seq) 
		tcph->seq = ~otcph->seq;
	else
		tcph->seq = otcph->seq;

	if (info->corrupt_ack)
		tcph->ack_seq = ~otcph->ack_seq;
	else
		tcph->ack_seq = otcph->ack_seq;

	tcpopt = (u_int8_t *)tcph + sizeof(struct tcphdr);
	optoff = 0;

	/* Fill MD5 option */
	if (info->md5) {
		skb_put(nskb, OPT_MD5_SIZE);
		tcpopt[optoff + 0] = OPT_MD5_KIND;
		tcpopt[optoff + 1] = OPT_MD5_SIZE;
		memset(tcpopt + optoff + 2, 0, OPT_MD5_SIZE - 2);
		optoff += OPT_MD5_SIZE;
	}

	/* Fill TS option */
	if (info->ts) {
		skb_put(nskb, OPT_TS_SIZE);
		tcpopt[optoff + 0] = OPT_TS_KIND;
		tcpopt[optoff + 1] = OPT_TS_SIZE;
		memset(tcpopt + optoff + 2, 0, OPT_TS_SIZE - 2);
		optoff += OPT_TS_SIZE;
	}

	/* Padding with EOL (Kind = 0) */
	if (optoff % 4) {
		skb_put(nskb, ALIGN(optoff, 4) - optoff);
		memset(tcpopt + optoff, 0, ALIGN(optoff, 4) - optoff);
		optoff = ALIGN(optoff, 4);
	}

	/* Adjust tcph->doff */
	tcph->doff += optoff/4;

	/* Fill data */
	if (info->payload_len) {
		skb_put(nskb, info->payload_len);
		strncpy(tcpopt + optoff, PAYLOAD_BUFF, info->payload_len);
	}

	return tcph;
}

static unsigned int spooftcp_tg4(struct sk_buff *oskb, const struct xt_action_param *par)
{
	const struct iphdr *oiph;
	struct tcphdr otcphb;
	struct tcphdr *otcph;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	struct net *net;
#endif
	struct dst_entry *dst;
	struct sk_buff *nskb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	const struct xt_spooftcp_info *info = par->targinfo;

	if (unlikely(__this_cpu_read(spooftcp_active)))
		return XT_CONTINUE;

	oiph = ip_hdr(oskb);

	if (unlikely(par->fragoff))
		return XT_CONTINUE;

	if (unlikely(skb_rtable(oskb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST)))
		return XT_CONTINUE;

	otcph = skb_header_pointer(oskb, par->thoff, sizeof(struct tcphdr),
			   &otcphb);

	if (unlikely(!otcph))
		return XT_CONTINUE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	net = xt_net(par);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	net = par->net;
#endif

	dst = dst_clone(skb_dst(oskb));
	if (unlikely(dst->error)) {
		dst_release(dst);
		return XT_CONTINUE;
	}

	nskb = alloc_skb(sizeof(struct iphdr) + sizeof(struct tcphdr) +
			 ALIGN((info->md5 ? OPT_MD5_SIZE : 0) + (info->ts ? OPT_TS_SIZE : 0), 4) +
			 LL_MAX_HEADER + info->payload_len,
			 GFP_ATOMIC);

	if (unlikely(!nskb)) {
		net_dbg_ratelimited("cannot alloc skb\n");
		dst_release(dst);
		return XT_CONTINUE;
	}			 

	skb_dst_set(nskb, dst);
	skb_reserve(nskb, LL_MAX_HEADER);

	skb_put(nskb, sizeof(struct iphdr));
	skb_reset_network_header(nskb);
	iph = ip_hdr(nskb);

	iph->version	= 4;
	iph->ihl	= sizeof(struct iphdr) / 4;
	iph->tos	= 0;
	iph->id		= 0;
	iph->frag_off	= htons(IP_DF);
	iph->protocol	= IPPROTO_TCP;
	iph->check	= 0;

	if (info->masq) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
		iph->saddr	= inet_select_addr(xt_out(par), 0, RT_SCOPE_UNIVERSE);
#else
		iph->saddr	= inet_select_addr(par->out, 0, RT_SCOPE_UNIVERSE);
#endif
	} else {
		iph->saddr	= oiph->saddr;
	}

	iph->daddr	= oiph->daddr;
	if (info->ttl)
		iph->ttl = info->ttl;
	else
		iph->ttl = oiph->ttl;

	nskb->protocol = htons(ETH_P_IP);

	tcph = spooftcp_tcphdr_put(nskb, otcph, info);

	tcph->check = ~tcp_v4_check(sizeof(struct tcphdr) + info->payload_len +
				  ALIGN((info->md5 ? OPT_MD5_SIZE : 0) + (info->ts ? OPT_TS_SIZE : 0), 4),
				  iph->saddr, iph->daddr, 0);
	nskb->ip_summed = CHECKSUM_PARTIAL;
	nskb->csum_start = (unsigned char *)tcph - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);
	if (info->corrupt_chksum)
		tcph->check = ~tcph->check;

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	/* Do not track this spoofed packet */
#	if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	nf_reset(nskb);
	nf_ct_set(nskb, NULL, IP_CT_UNTRACKED);
#	else
	nf_conntrack_put(nskb->nfct);
	nskb->nfct     = &nf_ct_untracked_get()->ct_general;
	nskb->nfctinfo = IP_CT_NEW;
	nf_conntrack_get(nskb->nfct);
#	endif
#endif

	__this_cpu_write(spooftcp_active, true);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	ip_local_out(net, nskb->sk, nskb);
#else
	ip_local_out(nskb);
#endif
	__this_cpu_write(spooftcp_active, false);
	if (info->delay)
		mdelay(info->delay);

	return XT_CONTINUE;
}

static unsigned int spooftcp_tg6(struct sk_buff *oskb, const struct xt_action_param *par)
{
	const struct ipv6hdr *oip6h;
	unsigned int otcplen;
	struct tcphdr otcphb;
	struct tcphdr *otcph;
	struct net *net;
	struct dst_entry *dst;
	unsigned int hh_len;
	struct sk_buff *nskb;
	struct ipv6hdr *ip6h;
	const struct xt_spooftcp_info *info = par->targinfo;
	struct tcphdr *tcph;

	if (unlikely(__this_cpu_read(spooftcp_active)))
		return XT_CONTINUE;

	oip6h = ipv6_hdr(oskb);

	if (unlikely((!(ipv6_addr_type(&oip6h->saddr) & IPV6_ADDR_UNICAST)) ||
	    (!(ipv6_addr_type(&oip6h->daddr) & IPV6_ADDR_UNICAST)))) {
		pr_warn("addr is not unicast.\n");
		return XT_CONTINUE;
	}

	otcplen = oskb->len - par->thoff;

	otcph = skb_header_pointer(oskb, par->thoff, sizeof(struct tcphdr),
				   &otcphb);

	if (unlikely(!otcph))
		return XT_CONTINUE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	net = xt_net(par);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	net = par->net;
#else
	net = dev_net(par->out);
#endif

	dst = dst_clone(skb_dst(oskb));
	if (unlikely(dst->error)) {
		dst_release(dst);
		return XT_CONTINUE;
	}

	hh_len = (dst->dev->hard_header_len + 15)&~15;

	nskb = alloc_skb(hh_len + 15 + dst->header_len + sizeof(struct ipv6hdr)
			 + sizeof(struct tcphdr) + dst->trailer_len + info->payload_len +
			 ALIGN((info->md5 ? OPT_MD5_SIZE : 0) + (info->ts ? OPT_TS_SIZE : 0), 4),
			 GFP_ATOMIC);

	if (unlikely(!nskb)) {
		net_dbg_ratelimited("cannot alloc skb\n");
		dst_release(dst);
		return XT_CONTINUE;
	}			 

	skb_dst_set(nskb, dst);
	skb_reserve(nskb, hh_len + dst->header_len);

	skb_put(nskb, sizeof(struct ipv6hdr));
	skb_reset_network_header(nskb);
	ip6h = ipv6_hdr(nskb);
	ip6_flow_hdr(ip6h, 0, 0);
	ip6h->hop_limit = info->ttl ? info->ttl : oip6h->hop_limit;
	ip6h->nexthdr = IPPROTO_TCP;

	if (info->masq) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
		ipv6_dev_get_saddr(net, xt_out(par), &oip6h->daddr, 0, &ip6h->saddr);
#else
		ipv6_dev_get_saddr(net, par->out, &oip6h->daddr, 0, &ip6h->saddr);
#endif
	} else {
		ip6h->saddr = oip6h->saddr;
	}

	ip6h->daddr = oip6h->daddr;
	nskb->protocol = htons(ETH_P_IPV6);

	tcph = spooftcp_tcphdr_put(nskb, otcph, info);

	tcph->check = csum_ipv6_magic(&ipv6_hdr(nskb)->saddr,
				      &ipv6_hdr(nskb)->daddr,
				      sizeof(struct tcphdr) + info->payload_len + ALIGN((info->md5 ? OPT_MD5_SIZE : 0) + (info->ts ? OPT_TS_SIZE : 0), 4),
				      IPPROTO_TCP,
				      csum_partial(tcph,
						   sizeof(struct tcphdr) + info->payload_len + ALIGN((info->md5 ? OPT_MD5_SIZE : 0) + (info->ts ? OPT_TS_SIZE : 0), 4), 0));

	if (info->corrupt_chksum)
		tcph->check = ~tcph->check;

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	/* Do not track this spoofed packet */
#	if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
	nf_reset(nskb);
	nf_ct_set(nskb, NULL, IP_CT_UNTRACKED);
#	else
	nf_conntrack_put(nskb->nfct);
	nskb->nfct     = &nf_ct_untracked_get()->ct_general;
	nskb->nfctinfo = IP_CT_NEW;
	nf_conntrack_get(nskb->nfct);
#	endif
#endif
	__this_cpu_write(spooftcp_active, true);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	ip6_local_out(net, nskb->sk, nskb);
#else
	ip6_local_out(nskb);
#endif
	__this_cpu_write(spooftcp_active, false);
	if (info->delay)
		mdelay(info->delay);

	return XT_CONTINUE;
}

static struct xt_target spooftcp_tg_regs[] __read_mostly = {
	{
		.family		= NFPROTO_IPV4,
		.name		= "SPOOFTCP",
		.target		= spooftcp_tg4,
		.targetsize 	= sizeof(struct xt_spooftcp_info),
		.hooks		= 1 << NF_INET_POST_ROUTING,
		.proto		= IPPROTO_TCP,
		.me		= THIS_MODULE,
	},
	{
		.family		= NFPROTO_IPV6,
		.name		= "SPOOFTCP",
		.target		= spooftcp_tg6,
		.targetsize 	= sizeof(struct xt_spooftcp_info),
		.hooks		= 1 << NF_INET_POST_ROUTING,
		.proto		= IPPROTO_TCP,
		.me		= THIS_MODULE,
	}
};

static int __init spooftcp_tg_init(void)
{
	return xt_register_targets(spooftcp_tg_regs, ARRAY_SIZE(spooftcp_tg_regs));
}

static void __exit spooftcp_tg_exit(void)
{
	xt_unregister_targets(spooftcp_tg_regs, ARRAY_SIZE(spooftcp_tg_regs));
}

module_init(spooftcp_tg_init);
module_exit(spooftcp_tg_exit);

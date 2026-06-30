/*
 * Copyright (c) Sakion Team. All rights reserved.
 * Copyright (c) myflavor <admin@myflv.cn>.
 *
 * File name: rekernel_x_netfilter.c
 * Description: ReKernel-X netfilter hook — measures inbound TCP payload for
 *              monitored user-app uids (IPv4/IPv6).
 * Author: nep_timeline@outlook.com, myflavor <admin@myflv.cn>
 */
#include "rekernel_x_log.h"
#include "rekernel_x.h"
#include <linux/printk.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <linux/rcupdate.h>

static inline uid_t line_sock2uid(struct sock *sk)
{
	if (sk && sk->sk_socket)
		return SOCK_INODE(sk->sk_socket)->i_uid.val;
	else
		return 0;
}

/*
 * Parse TCP payload length from an IPv4 packet.
 * Returns 0 on success, -1 if the packet should be passed through.
 */
static int parse_tcp_ipv4(struct sk_buff *skb, __u8 *proto, int *data_len)
{
	struct iphdr *iph;
	unsigned int ip_hdr_len;
	struct tcphdr *th;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return -1;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return -1;

	ip_hdr_len = iph->ihl << 2;
	if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
		return -1;

	iph = ip_hdr(skb);
	th = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
	*data_len = ntohs(iph->tot_len) - ip_hdr_len - (th->doff << 2);

	if (*data_len <= 0 && !th->syn && !th->fin && !th->rst)
		return -1;

	*proto = REKERNEL_X_NET_PROTO_IPV4;
	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
/*
 * Parse TCP payload length from an IPv6 packet.
 * Returns 0 on success, -1 if the packet should be passed through.
 */
static int parse_tcp_ipv6(struct sk_buff *skb, __u8 *proto, int *data_len)
{
	unsigned int thoff = 0;
	unsigned short frag_off = 0;
	struct ipv6hdr *iph6;
	struct tcphdr *th;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return -1;

	if (ipv6_find_hdr(skb, &thoff, -1, &frag_off, NULL) != IPPROTO_TCP)
		return -1;

	if (!pskb_may_pull(skb, thoff + sizeof(struct tcphdr)))
		return -1;

	iph6 = ipv6_hdr(skb);
	th = (struct tcphdr *)(skb_network_header(skb) + thoff);
	*data_len = ntohs(iph6->payload_len) - (thoff - sizeof(struct ipv6hdr))
	          - (th->doff << 2);

	if (*data_len <= 0 && !th->syn && !th->fin && !th->rst)
		return -1;

	*proto = REKERNEL_X_NET_PROTO_IPV6;
	return 0;
}
#endif

static unsigned int rekernel_x_pkg_ipv4_ipv6_in(void *priv, struct sk_buff *skb,
	const struct nf_hook_state *state)
{
	struct sock *sk;
	uid_t uid;
	int data_len;
	__u8 proto;

	if (!skb || !skb->len || !state)
		return NF_ACCEPT;

	if (state->hook != NF_INET_LOCAL_IN || !state->in)
		return NF_ACCEPT;

	sk = skb_to_full_sk(skb);
	if (!sk || !sk_fullsock(sk))
		return NF_ACCEPT;

	uid = line_sock2uid(sk);
	if (uid < MIN_USERAPP_UID)
		return NF_ACCEPT;

	rcu_read_lock();
	if (!net_uid_monitored_rcu(uid)) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}
	rcu_read_unlock();

	if (ip_hdr(skb)->version == 4) {
		if (parse_tcp_ipv4(skb, &proto, &data_len) < 0)
			return NF_ACCEPT;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (ip_hdr(skb)->version == 6) {
		if (parse_tcp_ipv6(skb, &proto, &data_len) < 0)
			return NF_ACCEPT;
#endif
	} else {
		return NF_ACCEPT;
	}

	rekernel_x_debug_log("Receive net data! target=%d\n", uid);
	if (rekernel_x_netlink_ready()) {
		struct rekernel_x_event event = {
			.type = REKERNEL_X_EVT_NETWORK,
			.u.network = {
				.proto = proto,
				.target_uid = uid,
				.data_len = data_len,
			},
		};
		sendMessage(&event);
	}

	return NF_ACCEPT;
}

/* Only monitor input network packages */
static struct nf_hook_ops rekernel_x_nf_ops[] = {
	{
		.hook     = rekernel_x_pkg_ipv4_ipv6_in,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_SELINUX_LAST + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook     = rekernel_x_pkg_ipv4_ipv6_in,
		.pf       = NFPROTO_IPV6,
		.hooknum  = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_SELINUX_LAST + 1,
	}
#endif
};

static bool re_netfilter_registered;

static void __unregister_netfilter(void)
{
	struct net *net;

	rtnl_lock();
	for_each_net(net) {
		nf_unregister_net_hooks(net, rekernel_x_nf_ops, ARRAY_SIZE(rekernel_x_nf_ops));
	}
	rtnl_unlock();

	net_uid_destroy();
}

void unregister_netfilter(void)
{
	if (re_netfilter_registered) {
		__unregister_netfilter();
		re_netfilter_registered = false;
	}
}

int register_netfilter(void)
{
	int rc = LINE_SUCCESS;
	struct net *net = NULL;

	net_uid_init();

	rtnl_lock();
	for_each_net(net) {
		rc = nf_register_net_hooks(net, rekernel_x_nf_ops, ARRAY_SIZE(rekernel_x_nf_ops));
		if (rc != LINE_SUCCESS) {
			rekernel_x_err_log("register netfilter hooks failed, rc=%d\n", rc);
			break;
		}
	}
	rtnl_unlock();

	if (rc != LINE_SUCCESS) {
		__unregister_netfilter();
		return LINE_ERROR;
	}

	re_netfilter_registered = true;
	return LINE_SUCCESS;
}

#include "../hd/general.h"

static unsigned int packet_filter_ipv4(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	if (ipv4_is_lock()) {return NF_DROP;}
	struct iphdr* ip_h = ip_hdr(skb);
	u8 proto_type = check_protocol();
	switch (proto_type)
	{
		case ONLY_TCP:
			//LOG(KERN_INFO, "ONLY_TCP");
			if (ip_h->protocol == IPPROTO_TCP) {return NF_ACCEPT;}
			return NF_DROP;
			//else {LOG(KERN_INFO, "skip: %pI4 (not TCP)", &ip_h->saddr); return NF_DROP;}
			break;
		case ONLY_UDP:
			//LOG(KERN_INFO, "ONLY_UDP");
			if (ip_h->protocol == IPPROTO_UDP) {return NF_ACCEPT;}
			return NF_DROP;
			//else {LOG(KERN_INFO, "skip: %pI4 (not UDP)", &ip_h->saddr); return NF_DROP;}
			break;
		case ONLY_ICMP:
			//LOG(KERN_INFO, "ONLY_UCMP");
			if (ip_h->protocol == IPPROTO_ICMP) {return NF_ACCEPT;}
			return NF_DROP;
			//else {LOG(KERN_INFO, "skip: %pI4 (not ICMP)", &ip_h->saddr); return NF_DROP;}
			break;
		case EXCEPT_TCP:
			//LOG(KERN_INFO, "EXCEPT_TCP");
			if (ip_h->protocol == IPPROTO_TCP) {return NF_DROP;}
			break;
		case EXCEPT_UDP:
			//LOG(KERN_INFO, "EXCEPT_UDP");
			if (ip_h->protocol == IPPROTO_UDP) {return NF_DROP;}
			break;
		case EXCEPT_ICMP:
			//LOG(KERN_INFO, "EXCEPT_ICMP");
			if (ip_h->protocol == IPPROTO_ICMP) {return NF_DROP;}
			break;
		case ALL_PROTO:
			//LOG(KERN_INFO, "ALL_PROTO");
			if (ip_h->protocol == IPPROTO_ICMP || ip_h->protocol == IPPROTO_TCP || ip_h->protocol == IPPROTO_UDP) {return NF_DROP;}
			break;
		case NOT_PROTOCOL_FILTER:
			//LOG(KERN_INFO, "NOT_PROTOCOL_FILTER");
			if (check_ipv4_arr(ip_h->saddr))
			{
				//LOG(KERN_INFO, "skip: %pI4", &ip_h->saddr);
				return NF_DROP;
			}
			break;

	}
	//LOG(KERN_INFO, "Hooked packet from: %pI4", &ip_h->saddr);

	return NF_ACCEPT;
}

static struct nf_hook_ops ipv4_pegasus_nf_hook_ops =
{
	.hook 		= packet_filter_ipv4,
	.pf 		= PF_INET,		// v4
	.hooknum  	= NF_INET_PRE_ROUTING,
	.priority 	= NF_IP_PRI_FIRST,
};



static unsigned int packet_filter_ipv6(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	if (ipv6_is_lock()) {return NF_DROP;}
	struct ipv6hdr* ipv6_h = ipv6_hdr(skb);


	u8 proto_type = check_protocol();
	switch (proto_type)
	{
		case ONLY_TCP:
			//LOG(KERN_INFO, "ONLY_TCP");
			if (ipv6_h->nexthdr == IPPROTO_TCP) {return NF_ACCEPT;}
			return NF_DROP;
			//else {LOG(KERN_INFO, "skip: %pI6 (not TCP)", &ipv6_h->saddr); return NF_DROP;}
			break;
		case ONLY_UDP:
			//LOG(KERN_INFO, "ONLY_UDP");
			if (ipv6_h->nexthdr == IPPROTO_UDP) {return NF_ACCEPT;}
			return NF_DROP;
			//else {LOG(KERN_INFO, "skip: %pI6 (not UDP)", &ipv6_h->saddr); return NF_DROP;}
			break;
		case ONLY_ICMP:
			//LOG(KERN_INFO, "ONLY_UCMP");
			if (ipv6_h->nexthdr == IPPROTO_ICMP) {return NF_ACCEPT;}
			return NF_DROP;
			//else {LOG(KERN_INFO, "skip: %pI6 (not ICMP)", &ipv6_h->saddr); return NF_DROP;}
			break;
		case EXCEPT_TCP:
			//LOG(KERN_INFO, "EXCEPT_TCP");
			if (ipv6_h->nexthdr == IPPROTO_TCP) {return NF_DROP;}
			break;
		case EXCEPT_UDP:
			//LOG(KERN_INFO, "EXCEPT_UDP");
			if (ipv6_h->nexthdr == IPPROTO_UDP) {return NF_DROP;}
			break;
		case EXCEPT_ICMP:
			//LOG(KERN_INFO, "EXCEPT_ICMP");
			if (ipv6_h->nexthdr == IPPROTO_ICMP) {return NF_DROP;}
			break;
		case ALL_PROTO:
			//LOG(KERN_INFO, "ALL_PROTO");
			if (ipv6_h->nexthdr == IPPROTO_ICMP || ipv6_h->nexthdr == IPPROTO_TCP || ipv6_h->nexthdr == IPPROTO_UDP) {return NF_DROP;}
			break;
		case NOT_PROTOCOL_FILTER:
			//LOG(KERN_INFO, "NOT_PROTOCOL_FILTER");
			if (check_ipv6_arr(&ipv6_h->saddr))
			{
				//LOG(KERN_INFO, "skip: %pI6", &ipv6_h->saddr);
				return NF_DROP;
			}
			break;

	}


	//LOG(KERN_INFO, "Hooked packet from: %pI6", &ipv6_h->saddr);
	return NF_ACCEPT;
}

static struct nf_hook_ops ipv6_pegasus_nf_hook_ops =
{
	.hook 		= packet_filter_ipv6,
	.pf 		= PF_INET6,	// v6
	.hooknum  	= NF_INET_PRE_ROUTING,
	.priority 	= NF_IP_PRI_FIRST,
};




void init_filter(void)
{
	nf_register_net_hook(&init_net, &ipv4_pegasus_nf_hook_ops);
	nf_register_net_hook(&init_net, &ipv6_pegasus_nf_hook_ops);
}


void exit_filter(void)
{
	nf_unregister_net_hook(&init_net, &ipv4_pegasus_nf_hook_ops);
	nf_unregister_net_hook(&init_net, &ipv6_pegasus_nf_hook_ops);
}



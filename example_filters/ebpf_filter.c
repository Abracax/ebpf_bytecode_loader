#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_tunnel.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <stddef.h>
#include "bpf_helpers.h"
#include "bpf_legacy.h"

#ifndef __section
#define __section(NAME) \
	__attribute__((section(NAME), used))
#endif

#define cursor_advance(_cursor, _len) \
      ({ void *_tmp = _cursor; _cursor += _len; _tmp; })

/* Helper macro to print out debug messages */
#define printk(fmt, ...)                               \
	(                                                  \
		{                                              \
			char ____fmt[] = fmt;                      \
			bpf_trace_printk(____fmt, sizeof(____fmt), \
							 ##__VA_ARGS__);           \
		})

char __license[] __section("license") = "GPL";

__section("icmp_filter") int classifier_icmp(struct __sk_buff *skb)
{
	// data is at start of ethernet header
	// (data+14) is start of IP header
	// (data+34) is start of ICMP header
	//
	//
	//
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
	     return 0;

	if ((load_byte(skb, sizeof(struct ethhdr)) & 0xF) != 4)
	     return 0;

	if (load_byte(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol)) != 1)
	     return 0;

	if (load_half(skb, sizeof(struct ethhdr) + sizeof(struct iphdr)) != 0)
	     return 0;
    
	if (load_half(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + 4) != 5566)
	     return 0;
//	void *data = (void *)(long)skb->data;
//	void *data_end = (void *)(long)skb->data_end;
//	struct ethhdr *eth = data;
//	struct iphdr *iph = data + 14;
//	struct icmphdr *icmph = data + 34;
//
//	if (data + 34 > data_end)
//        return 0;
//
//	if (eth->h_proto != __constant_htons(ETH_P_IP))
//        return 0;
//
//	if (iph->version != 4 || iph->protocol != 1)
//		return 0;
////
	// check for ICMP echo reply
//	switch(icmph->type) {
//		case 0: printk("ICMP Echo Reply Info: "); break;
//		case 3: printk("ICMP Destination Unreachable Info: "); break;
//		case 5: printk("ICMP Redirect Message Info: "); break;
//		case 8: printk("ICMP Echo Request Info: "); break;
//		case 11: printk("ICMP Time Exceeded Info: "); break;
//		case 30: printk("ICMP Traceroute Info: "); break;
//		default: return TC_ACT_OK;
//	}

//	printk("id=%d seq=%d code=%d", htons(icmph->un.echo.id), htons(icmph->un.echo.sequence), icmph->code);
	

	return -1;
}

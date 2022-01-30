#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include <linux/pkt_cls.h>
#include "bpf_helpers.h"

#ifndef __section
#define __section(NAME) \
	__attribute__((section(NAME), used))
#endif

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
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct iphdr *iph = (data + 14);
	struct icmphdr *icmph = (data + 34);

	// check out of bounds
	if ((void *)&iph[1] > data_end)
		return TC_ACT_OK;

	// check out of bounds
	if ((void *)&icmph[1] > data_end)
		return TC_ACT_OK;

	if (iph->version != 4 || iph->protocol != 1)
		return TC_ACT_OK;

	// check for ICMP echo reply
	switch(icmph->type) {
		case 0: printk("ICMP Echo Reply Info: "); break;
		case 3: printk("ICMP Destination Unreachable Info: "); break;
		case 5: printk("ICMP Redirect Message Info: "); break;
		case 8: printk("ICMP Echo Request Info: "); break;
		case 11: printk("ICMP Time Exceeded Info: "); break;
		case 30: printk("ICMP Traceroute Info: "); break;
		default: return TC_ACT_OK;
	}

	printk("id=%d seq=%d code=%d", htons(icmph->un.echo.id), htons(icmph->un.echo.sequence), icmph->code);
	

	return TC_ACT_OK;
}

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_tunnel.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <stddef.h>
#include <stdint.h>
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
	(                                                  \ {                                              \
			char ____fmt[] = fmt;                      \
			bpf_trace_printk(____fmt, sizeof(____fmt), \
							 ##__VA_ARGS__);           \
		})

char __license[] __section("license") = "GPL";

#define ETHHDR_LEN 14
#define ETHHDR_HPROTO_OFFSET 12
#define IPHDR_LEN_MIN 20
#define IPHDR_LEN_MAX 24
#define IPHDR_VERSION_OFF ETHHDR_LEN
#define IPHDR_PROTO_OFF ETHHDR_LEN + 9
#define ICMPHDR_OFF ETHHDR_LEN+IPHDR_LEN_MIN 
#define ICMPHDR_TYPE_OFF ICMPHDR_OFF 
#define ICMPHDR_ID_OFF ICMPHDR_OFF + 4 

__section("icmp_filter") int32_t classifier_icmp(struct __sk_buff *skb)
{
	// Memory buffer is at start of ethernet header
	
	// Incoming IP packet
	if (load_half(skb, ETHHDR_HPROTO_OFFSET) != __constant_htons(ETH_P_IP))
	     return 0;

    // Check version field of ip header 
	if ((load_byte(skb, ETHHDR_LEN) & 0xF) != 4)
	     return 0;

    // Check IP packet protocol for ICMP
	if (load_byte(skb, IPHDR_PROTO_OFF) != 1)
	     return 0;

    // Check ICMP type for reply
	if (load_half(skb, ICMPHDR_TYPE_OFF) != 0)
	     return 0;
    
    // Check ICMP id
	if (load_half(skb, ICMPHDR_ID_OFF) != 5566)
	     return 0;

	return 65535; 
//	if (load_byte(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol)) != 1)
//	     return 0;
//
//	if (load_half(skb, sizeof(struct ethhdr) + sizeof(struct iphdr)) != 0)
//	     return 0;
//    
//	if (load_half(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + 4) != 5566)
//	     return 0;
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
	

}

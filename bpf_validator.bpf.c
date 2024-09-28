// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <net/if.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_validator.h"

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_TCP 6
#define ETH_HLEN 14
#define INITIAL_VAL 0

// #define DEBUG
// #define TRACE

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, __u64);
    __uint(max_entries, 60999);
} port_timers SEC(".maps");

// Taken from uapi/linux/tcp.h
struct __tcphdr
{
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff)
{
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb)
{
	
	__u64 event_timestamp = bpf_ktime_get_boot_ns();

	#ifdef TRACE
		const char socket_handler_timestamp_str[]  = "socket timestamp: %lu";
		bpf_trace_printk(socket_handler_timestamp_str, sizeof(socket_handler_timestamp_str), event_timestamp);
	#endif

	struct so_event *e;
	__u8 verlen;
	__u16 proto;
	__u32 nhoff = ETH_HLEN;
	__u32 ip_proto = 0;
	__u32 tcp_hdr_len = 0;
	__u16 tlen;
	__u32 payload_offset = 0;
	__u32 payload_length = 0;
	__u8 hdr_len;

	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP){
		#ifdef TRACE
			const char proto_ne_eth_ip_str[]  = "proto ne ETH_P_IP: %d - %d";
			bpf_trace_printk(proto_ne_eth_ip_str, sizeof(proto_ne_eth_ip_str), proto, ETH_P_IP);
		#endif

		return 0;
	}

	if (ip_is_fragment(skb, nhoff)){
		#ifdef TRACE
			const char ip_is_fragment_str[]  = "ip_is_fragment(skb, nhoff)";
			bpf_trace_printk(ip_is_fragment_str, sizeof(ip_is_fragment_str));
		#endif

		return 0;
	}

	if (skb->pkt_type != PACKET_HOST){
		#ifdef TRACE
			const char pkt_type_ne_packet_host_str[]  = "skb->pkt_type ne PACKET_HOST";
			bpf_trace_printk(pkt_type_ne_packet_host_str, sizeof(pkt_type_ne_packet_host_str));
		#endif
		
		return 0;
	}

	// ip4 header lengths are variable
	// access ihl as a u8 (linux/include/linux/skbuff.h)
	bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
	hdr_len &= 0x0f;
	hdr_len *= 4;

	#ifdef TRACE
		const char fmt_min_size_str[]  = "verify hlen meets minimum size requirements";
		bpf_trace_printk(fmt_min_size_str, sizeof(fmt_min_size_str));
	#endif

	/* verify hlen meets minimum size requirements */
	if (hdr_len < sizeof(struct iphdr))
	{
		return 0;
	}

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);

	if (ip_proto != IPPROTO_TCP)
	{
		return 0;
	}

	tcp_hdr_len = nhoff + hdr_len;
	bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, tot_len), &tlen, sizeof(tlen));

	__u8 doff;
	bpf_skb_load_bytes(skb, tcp_hdr_len + offsetof(struct __tcphdr, ack_seq) + 4, &doff, sizeof(doff)); // read the first byte past __tcphdr->ack_seq, we can't do offsetof bit fields
	doff &= 0xf0;																						// clean-up res1
	doff >>= 4;																							// move the upper 4 bits to low
	doff *= 4;																							// convert to bytes length

	payload_offset = ETH_HLEN + hdr_len + doff;
	payload_length = __bpf_ntohs(tlen) - hdr_len - doff;

	#ifdef TRACE
		const char fmt_verify_payload_str[]  = "verify payload payload_offset and payload_length: %d, %d";
		bpf_trace_printk(fmt_verify_payload_str, sizeof(fmt_verify_payload_str), payload_offset, payload_length);
	#endif

	char line_buffer[7];
	if (payload_length < 7 || payload_offset < 0)
	{
		return 0;
	}
	bpf_skb_load_bytes(skb, payload_offset, line_buffer, 7);
	bpf_printk("%d len %d buffer: %s", payload_offset, payload_length, line_buffer);
	if (bpf_strncmp(line_buffer, 3, "GET") != 0 &&
		bpf_strncmp(line_buffer, 4, "POST") != 0 &&
		bpf_strncmp(line_buffer, 3, "PUT") != 0 &&
		bpf_strncmp(line_buffer, 6, "DELETE") != 0 &&
		bpf_strncmp(line_buffer, 4, "HTTP") != 0)
	{
		return 0;
	}

	union port_union {
		__be32 port32;
		__be16 port16[2];
	} ports;

	bpf_skb_load_bytes(skb, nhoff + hdr_len, &ports, 4);

	char ifname[IF_NAMESIZE];
	
	char sstr[16] = {}, dstr[16] = {}; //remove src dst address and only filter on ports

	if (skb->pkt_type != PACKET_HOST)
	 	return 0;

	if (ip_proto < 0 || ip_proto >= IPPROTO_MAX)
	 	return 0;

	//TODO:: libbpf: failed to find BTF for extern 'if_indextoname' 
	// if (!if_indextoname(skb->ifindex, ifname))
	//   	return 0;


	__u32 port = 0;

	bpf_skb_load_bytes(skb, nhoff + hdr_len, &(ports), 4);

	if ( __bpf_ntohs(ports.port16[0]) != SRV_PORT && __bpf_ntohs(ports.port16[1]) != SRV_PORT ) {
		//Do nothing - not a packet we are interested in
		return 0;
	}


	//TODO:: make this dynamic / configurable
	if ( __bpf_ntohs(ports.port16[1]) == SRV_PORT) {
		
		port = __bpf_ntohs(ports.port16[0]);

		#ifdef TRACE
			const char payload_port_snd_str[]  = "port: %d";
			bpf_trace_printk(payload_port_snd_str, sizeof(payload_port_snd_str), port);
		#endif

		#ifdef TRACE
			const char port_snd_timestamp_str[]  = "port send timestamp: %lu";
			bpf_trace_printk(port_snd_timestamp_str, sizeof(port_snd_timestamp_str), event_timestamp);
		#endif

	 	bpf_map_update_elem(&port_timers, &port, &event_timestamp, BPF_EXIST);
	  	return 0;

	} else {
		
		port = __bpf_ntohs(ports.port16[1]);

		#ifdef TRACE
			const char payload_port_rcv_str[]  = "port: %d";
			bpf_trace_printk(payload_port_rcv_str, sizeof(payload_port_rcv_str), port);
		#endif

		__u64 *val = bpf_map_lookup_elem(&port_timers, &port);

		#ifdef DEBUG
			const char port_timestamp_str[]  = "port timestamp diff: %lu";
			bpf_trace_printk(port_timestamp_str, sizeof(port_timestamp_str), val);
		#endif

		if(val){
			__u64 timestamp_delta = event_timestamp - *val;

			#ifdef DEBUG
				const char port_timestamp_delta_str[]  = "timestamp delta: %d";
			 	bpf_trace_printk(port_timestamp_delta_str, sizeof(port_timestamp_delta_str), timestamp_delta);
			#endif


			e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

			if (!e)
				return 0;

			e->ktime_ns = timestamp_delta;	

			bpf_ringbuf_submit(e, 0);

			bpf_map_update_elem(&port_timers, &port, &initial_val, BPF_EXIST);
		}

	}

	return skb->len;
}


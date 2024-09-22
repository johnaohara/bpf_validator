// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#ifndef __BPF_VALIDATOR_H
#define __BPF_VALIDATOR_H

#define MAX_BUF_SIZE 256

struct so_event {
	__be32 src_addr;
	__be32 dst_addr;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	__u32 ip_proto;
	__u32 pkt_type;
	__u32 ifindex;
	__u64 ktime_ns;
	// __u32 payload_length;
    // __u8 payload[MAX_BUF_SIZE];
};

volatile __u64 timestamps[60999] = { [0 ... 60998] = 0 };
__u64 initial_timestamp = 0;
__u64 final_timestamp = 0;
__u64 events = 0;

struct hdr_histogram* histogram;


#define SRV_PORT 8000

void printHdrHisto();

#endif /* __BPF_VALIDATOR_H */

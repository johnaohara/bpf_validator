// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#ifndef __BPF_VALIDATOR_H
#define __BPF_VALIDATOR_H

#define MAX_BUF_SIZE 2048
#define BILLION  1000000000L;

struct so_event {
	__u64 ktime_ns;
};

__u16 initial_val = 0;

double initial_timestamp = 0;
double final_timestamp = 0;
__u64 events = 0;
struct timespec cur_time;

struct hdr_histogram* histogram;


#define SRV_PORT 8000

void printHdrHisto();

#endif /* __BPF_VALIDATOR_H */

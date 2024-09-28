// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bpf_validator.h"
#include "bpf_validator.skel.h"
#include <hdr/hdr_histogram.h>
#include <time.h>

// #define DEBUG

static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static inline void ltoa(uint32_t addr, char *dst)
{
	snprintf(dst, 16, "%u.%u.%u.%u", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
		 (addr >> 8) & 0xFF, (addr & 0xFF));
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct so_event *e = data;

	if( clock_gettime( CLOCK_REALTIME, &cur_time) == -1 ) {
		perror( "clock gettime" );
		return EXIT_FAILURE;
	}

	final_timestamp = cur_time.tv_sec + (double) cur_time.tv_nsec / (double)BILLION;


	if ( initial_timestamp == 0 ){
		initial_timestamp = final_timestamp;
	}


	hdr_record_value(
		histogram,
		e->ktime_ns);
	events = events + 1;

	return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
	printHdrHisto();
}


void printHdrHisto(){
	printf("\n\nPrinting HdrHistogram stats:\n\n");
	// Print out the values of the histogram
	hdr_percentiles_print(
		histogram,
		stdout,  // File to write to
		5,  // Granularity of printed values
		1000000,  // Multiplier for results
		CLASSIC);  // Format CLASSIC/CSV supported.
	printf("\n");
	printf("50.0th Percentile: %f\n", hdr_value_at_percentile(histogram, 50.0) / 1000000.0);
	printf("90.0th Percentile: %f\n", hdr_value_at_percentile(histogram, 90.0) / 1000000.0);
	printf("99.0th Percentile: %f\n", hdr_value_at_percentile(histogram, 99.0) / 1000000.0);
	printf("99.9th Percentile: %f\n", hdr_value_at_percentile(histogram, 99.9) / 1000000.0);
	printf("99.99th Percentile: %f\n", hdr_value_at_percentile(histogram, 99.99) / 1000000.0);

	double time_span = (final_timestamp - initial_timestamp)  ;

	printf("\n%llu requests in %fs\n", events, time_span );
	printf("Av Throughput: %f req/sec\n", events / time_span);

}


int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bpf_validator_bpf *skel;
	int err, prog_fd, sock;

	const char* interface = "lo";
	// Initialise the histogram
	hdr_init(
		1,  
		INT64_C(3600000000), 
		3,  // Number of significant figures
		&histogram);


	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF programs*/
	skel = bpf_validator_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Create raw socket for localhost interface */
	sock = open_raw_sock(interface);
	if (sock < 0) {
		err = -2;
		fprintf(stderr, "Failed to open raw socket\n");
		goto cleanup;
	}

	/* Attach BPF program to raw socket */
	prog_fd = bpf_program__fd(skel->progs.socket_handler);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		err = -3;
		fprintf(stderr, "Failed to attach to raw socket\n");
		goto cleanup;
	}

	/* Process events */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
		sleep(1);
	}

cleanup:
	ring_buffer__free(rb);
	bpf_validator_bpf__destroy(skel);
	return -err;
}
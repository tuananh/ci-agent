#pragma once

enum ev_type {
	EV_TCP_EGRESS = 1,
	EV_UDP_EGRESS = 2,
};

#define MAX_COMM_LEN 16
#define MAX_HOSTNAME_LEN 256
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

struct event {
	__u64 ts_nsec;
	__u32 type;
	__u32 cpu;
	__u32 pid;
	__u32 tgid;
	char comm[MAX_COMM_LEN];
	
	/* Network information */
	__u8 family;  /* AF_INET or AF_INET6 */
	__u8 protocol; /* IPPROTO_TCP or IPPROTO_UDP */
	__u16 sport;
	__u16 dport;
	__u32 saddr[4];  /* IPv4: saddr[0], IPv6: all 4 words */
	__u32 daddr[4];  /* IPv4: daddr[0], IPv6: all 4 words */
	__u64 bytes_sent;
};

/* DNS mapping: IP address -> hostname */
struct dns_mapping_key {
	__u32 ip[4];  /* IPv4: ip[0], IPv6: all 4 words */
	__u8 family;  /* AF_INET or AF_INET6 */
};

struct dns_mapping_value {
	char hostname[MAX_HOSTNAME_LEN];
	__u64 timestamp;
};

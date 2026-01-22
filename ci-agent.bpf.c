#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ci-agent.h"

/* Socket address families */
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

/* IP protocols */
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

/* Ethernet protocol types */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

/* Map to store IP -> hostname mappings from DNS responses */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct dns_mapping_key);
	__type(value, struct dns_mapping_value);
} dns_map SEC(".maps");

static __always_inline __u16 bpf_ntohs(__u16 val)
{
	return ((val & 0x00ff) << 8) | ((val & 0xff00) >> 8);
}

static __always_inline __u32 bpf_ntohl(__u32 val)
{
	return ((val & 0x000000ff) << 24) |
	       ((val & 0x0000ff00) << 8) |
	       ((val & 0x00ff0000) >> 8) |
	       ((val & 0xff000000) >> 24);
}

static __always_inline void fill_network_info(struct event *e, struct sock *sk, size_t size)
{
	struct inet_sock *inet = (struct inet_sock *)sk;
	__u16 family;
	__be32 saddr4, daddr4;
	__be16 sport, dport;
	
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->family = family;
	e->bytes_sent = size;
	
	if (family == AF_INET) {
		/* IPv4 */
		saddr4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
		daddr4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		sport = BPF_CORE_READ(inet, inet_sport);
		dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
		
		e->saddr[0] = bpf_ntohl(saddr4);
		e->daddr[0] = bpf_ntohl(daddr4);
		e->sport = bpf_ntohs(sport);
		e->dport = bpf_ntohs(dport);
		
		/* Clear IPv6 fields */
		e->saddr[1] = 0;
		e->saddr[2] = 0;
		e->saddr[3] = 0;
		e->daddr[1] = 0;
		e->daddr[2] = 0;
		e->daddr[3] = 0;
	} else if (family == AF_INET6) {
		/* IPv6 */
		sport = BPF_CORE_READ(inet, inet_sport);
		dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
		
		/* Read IPv6 addresses - they're stored as 4 u32 words */
		bpf_core_read(&e->saddr[0], sizeof(__u32), 
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[0]);
		bpf_core_read(&e->saddr[1], sizeof(__u32), 
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[1]);
		bpf_core_read(&e->saddr[2], sizeof(__u32), 
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[2]);
		bpf_core_read(&e->saddr[3], sizeof(__u32), 
			      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32[3]);
		
		bpf_core_read(&e->daddr[0], sizeof(__u32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[0]);
		bpf_core_read(&e->daddr[1], sizeof(__u32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[1]);
		bpf_core_read(&e->daddr[2], sizeof(__u32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[2]);
		bpf_core_read(&e->daddr[3], sizeof(__u32),
			      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32[3]);
		
		e->sport = bpf_ntohs(sport);
		e->dport = bpf_ntohs(dport);
	}
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(on_tcp_sendmsg,
	     struct sock *sk,
	     struct msghdr *msg,
	     size_t size)
{
	if (!sk)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EV_TCP_EGRESS;
	e->ts_nsec = bpf_ktime_get_ns();
	e->cpu = bpf_get_smp_processor_id();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->protocol = IPPROTO_TCP;
	
	fill_network_info(e, sk, size);
	
	/* Look up hostname from DNS map */
	struct dns_mapping_key key = {0};
	if (e->family == AF_INET) {
		key.ip[0] = e->daddr[0];
		key.family = AF_INET;
	} else if (e->family == AF_INET6) {
		key.ip[0] = e->daddr[0];
		key.ip[1] = e->daddr[1];
		key.ip[2] = e->daddr[2];
		key.ip[3] = e->daddr[3];
		key.family = AF_INET6;
	}
	
	/* Note: We can't store hostname in event struct directly in BPF */
	/* Userspace will look it up from the map */
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* DNS capture is done in userspace (ci-agentd-dns.c) */
/* The DNS map is populated by userspace and read by BPF hooks below */

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_sendmsg,
	     struct sock *sk,
	     struct msghdr *msg,
	     size_t len)
{
	if (!sk)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EV_UDP_EGRESS;
	e->ts_nsec = bpf_ktime_get_ns();
	e->cpu = bpf_get_smp_processor_id();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->tgid = (__u32)bpf_get_current_pid_tgid();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->protocol = IPPROTO_UDP;
	
	fill_network_info(e, sk, len);
	
	bpf_ringbuf_submit(e, 0);
	return 0;
}

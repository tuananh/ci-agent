#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include "ci-agent.h"
#include "ci-agent.skel.h"
#include "ci-agentd-broadcast.h"
#include "ci-agentd-dns.h"

enum fd_tag {
	FD_RINGBUF = 1,
	FD_LISTENER = 2,
};

static volatile sig_atomic_t stop;

static void sigint_handler(int signo)
{
	(void) signo;
	stop = 1;
}

static void format_ipv4(char *buf, size_t len, __u32 addr)
{
	struct in_addr in;
	in.s_addr = htonl(addr);
	inet_ntop(AF_INET, &in, buf, len);
}

static void format_ipv6(char *buf, size_t len, const __u32 *addr)
{
	struct in6_addr in6;
	memcpy(&in6.s6_addr32, addr, sizeof(in6.s6_addr32));
	inet_ntop(AF_INET6, &in6, buf, len);
}

static int get_executable_path(pid_t pid, char *buf, size_t len)
{
	char path[64];
	ssize_t n;

	snprintf(path, sizeof(path), "/proc/%u/exe", pid);
	n = readlink(path, buf, len - 1);
	if (n < 0) {
		/* Process might have exited, fall back to comm */
		return -1;
	}
	buf[n] = '\0';
	return 0;
}


struct event_handler_ctx {
	struct ci_agent_broadcaster *broadcaster;
	struct bpf_map *dns_map;
};

static int eventloop_register(int ep_fd, int fd, enum fd_tag tag)
{
	struct epoll_event ev = {
		.events = EPOLLIN,
		.data.u32 = tag,
	};
	return epoll_ctl(ep_fd, EPOLL_CTL_ADD, fd, &ev);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct event_handler_ctx *handler_ctx = ctx;
	struct ci_agent_broadcaster *broadcaster = handler_ctx->broadcaster;
	struct bpf_map *dns_map = handler_ctx->dns_map;
	char saddr_str[INET6_ADDRSTRLEN];
	char daddr_str[INET6_ADDRSTRLEN];
	char exe_path[PATH_MAX];
	char hostname[MAX_HOSTNAME_LEN] = {0};
	const char *proto_str;
	const char *exe_display;
	const char *hostname_display = NULL;

	(void) data_sz;

	if (e->type == EV_TCP_EGRESS) {
		proto_str = "TCP";
	} else if (e->type == EV_UDP_EGRESS) {
		proto_str = "UDP";
	} else {
		return 0;
	}

	if (e->family == AF_INET) {
		format_ipv4(saddr_str, sizeof(saddr_str), e->saddr[0]);
		format_ipv4(daddr_str, sizeof(daddr_str), e->daddr[0]);
	} else if (e->family == AF_INET6) {
		format_ipv6(saddr_str, sizeof(saddr_str), e->saddr);
		format_ipv6(daddr_str, sizeof(daddr_str), e->daddr);
	} else {
		return 0;
	}

	/* Get full executable path */
	if (get_executable_path(e->pid, exe_path, sizeof(exe_path)) == 0) {
		exe_display = exe_path;
	} else {
		/* Fall back to comm if we can't read the path */
		exe_display = e->comm;
	}

	/* Look up hostname from DNS map */
	if (dns_map) {
		struct dns_mapping_key key = {0};
		struct dns_mapping_value value = {0};
		
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
		
		int map_fd = bpf_map__fd(dns_map);
		if (map_fd >= 0 && bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
			/* Found in DNS map - even if hostname is empty, this means DNS was captured */
			if (value.hostname[0] != '\0') {
				strncpy(hostname, value.hostname, sizeof(hostname) - 1);
				hostname[sizeof(hostname) - 1] = '\0';
				hostname_display = hostname;
			} else {
				/* DNS entry exists but hostname not extracted - show empty */
				hostname_display = "(empty)";
			}
		}
	}

	if (hostname_display) {
		ci_agent_broadcaster_send(broadcaster,
			"EGRESS ts=%llu pid=%u tgid=%u exe=%s proto=%s src=%s:%u dst=%s:%u (%s) bytes=%llu\n",
			(unsigned long long)e->ts_nsec,
			e->pid,
			e->tgid,
			exe_display,
			proto_str,
			saddr_str,
			e->sport,
			daddr_str,
			e->dport,
			hostname_display,
			(unsigned long long)e->bytes_sent);
	} else {
		ci_agent_broadcaster_send(broadcaster,
			"EGRESS ts=%llu pid=%u tgid=%u exe=%s proto=%s src=%s:%u dst=%s:%u bytes=%llu\n",
			(unsigned long long)e->ts_nsec,
			e->pid,
			e->tgid,
			exe_display,
			proto_str,
			saddr_str,
			e->sport,
			daddr_str,
			e->dport,
			(unsigned long long)e->bytes_sent);
	}

	return 0;
}

int main(void)
{
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	struct ci_agent_broadcaster *broadcaster = NULL;
	int err = ci_agent_broadcaster_init(&broadcaster, "/run/ci-agent.sock");
	if (err != 0)
	{
		fprintf(stderr, "initializing listener failed: %s\n", strerror(-err));
		return 1;
	}

	struct ci_agent_bpf *skel = ci_agent_bpf__open();
	if (!skel) {
		fprintf(stderr, "open skeleton failed: %s\n", strerror(errno));
		return 1;
	}
	err = ci_agent_bpf__load(skel);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		ci_agent_bpf__destroy(skel);
		return 1;
	}
	err = ci_agent_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(-err));
		fprintf(stderr, "Note: If a previous instance was killed, you may need to:\n");
		fprintf(stderr, "  1. Wait a few seconds for kernel to clean up\n");
		fprintf(stderr, "  2. Or reboot to clear stuck BPF attachments\n");
		ci_agent_bpf__destroy(skel);
		ci_agent_broadcaster_fini(broadcaster);
		return 1;
	}

	fprintf(stderr, "ci-agentd started successfully\n");

	/* Start DNS sniffer thread */
	int dns_map_fd = bpf_map__fd(skel->maps.dns_map);
	if (dns_map_fd >= 0) {
		if (dns_sniffer_start(dns_map_fd) == 0) {
			fprintf(stderr, "DNS sniffer started\n");
		} else {
			fprintf(stderr, "Warning: DNS sniffer failed to start (need CAP_NET_RAW)\n");
		}
	}

	struct event_handler_ctx handler_ctx = {
		.broadcaster = broadcaster,
		.dns_map = skel->maps.dns_map,
	};

	struct ring_buffer *rb =
	    ring_buffer__new(bpf_map__fd(skel->maps.events),
			     handle_event, &handler_ctx, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
		ci_agent_bpf__destroy(skel);
		ci_agent_broadcaster_fini(broadcaster);
		return 1;
	}

	int rb_fd = ring_buffer__epoll_fd(rb);
	if (rb_fd < 0)
	{
		fprintf(stderr, "ring_buffer__epoll_fd: %s\n", strerror(errno));
		ring_buffer__free(rb);
		ci_agent_bpf__destroy(skel);
		ci_agent_broadcaster_fini(broadcaster);
		return 1;
	}

	int ep_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0)
	{
		fprintf(stderr, "epoll_create1: %s\n", strerror(errno));
		ring_buffer__free(rb);
		ci_agent_bpf__destroy(skel);
		ci_agent_broadcaster_fini(broadcaster);
		return 1;
	}

	if (eventloop_register(ep_fd, rb_fd, FD_RINGBUF) < 0)
	{
		ring_buffer__free(rb);
		ci_agent_bpf__destroy(skel);
		ci_agent_broadcaster_fini(broadcaster);
		return 1;
	}

	int lfd = ci_agent_broadcaster_fd(broadcaster);
	if (eventloop_register(ep_fd, lfd, FD_LISTENER) < 0)
	{
		fprintf(stderr, "epoll_ctl listener: %s\n", strerror(errno));
		ring_buffer__free(rb);
		ci_agent_bpf__destroy(skel);
		ci_agent_broadcaster_fini(broadcaster);
		return 1;
	}

	while (!stop) {
		struct epoll_event events[8];

		int n = epoll_wait(ep_fd, events, 8, -1);
		if (n < 0)
		{
			if (errno == EINTR) {
				/* Check stop flag after signal interruption */
				if (stop)
					break;
				continue;
			}

			fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
			break;
		}

		for (int i = 0; i < n; i++)
		{
			switch (events[i].data.u32)
			{
				case FD_RINGBUF:
				{
					int r = ring_buffer__poll(rb, 0);
					if (r < 0)
						fprintf(stderr, "process ringbuf: %s\n", strerror(errno));
					break;
				}

				case FD_LISTENER:
				{
					int r = ci_agent_broadcaster_accept(broadcaster);
					if (r < 0)
						fprintf(stderr, "accept: %s\n", strerror(r));
					break;
				}

				default:
					break;
			}
		}
	}

	fprintf(stderr, "ci-agentd shutting down...\n");

	dns_sniffer_stop_thread();
	ring_buffer__free(rb);
	ci_agent_bpf__destroy(skel);
	ci_agent_broadcaster_fini(broadcaster);

	return 0;
}

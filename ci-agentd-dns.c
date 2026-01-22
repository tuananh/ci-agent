#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <bpf/bpf.h>
#include "ci-agent.h"

/* DNS header structure */
struct dns_header {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
};

/* DNS question structure */
struct dns_question {
	char qname[256];
	__u16 qtype;
	__u16 qclass;
};

static volatile int dns_sniffer_stop = 0;
static int dns_map_fd = -1;

/* Parse DNS QNAME (domain name) from packet */
static int parse_dns_qname(const unsigned char *packet, int offset, int max_len, char *qname, int qname_size)
{
	int pos = offset;
	int qname_pos = 0;
	
	while (pos < max_len && qname_pos < qname_size - 1) {
		if (packet[pos] == 0) {
			/* End of name */
			qname[qname_pos] = '\0';
			return pos + 1;
		}
		
		if (packet[pos] & 0xc0) {
			/* Compression pointer - skip for now */
			return pos + 2;
		}
		
		__u8 label_len = packet[pos];
		if (label_len == 0 || pos + label_len >= max_len)
			break;
		
		pos++;
		
		if (qname_pos > 0) {
			qname[qname_pos++] = '.';
		}
		
		for (int i = 0; i < label_len && pos < max_len && qname_pos < qname_size - 1; i++) {
			qname[qname_pos++] = packet[pos++];
		}
	}
	
	qname[qname_pos] = '\0';
	return pos;
}

/* Parse DNS response and extract IP -> hostname mappings */
static void parse_dns_response(const unsigned char *packet, int packet_len, int dns_offset)
{
	if (packet_len < dns_offset + sizeof(struct dns_header))
		return;
	
	struct dns_header *dns_hdr = (struct dns_header *)(packet + dns_offset);
	
	/* Check if it's a response */
	__u16 flags = ntohs(dns_hdr->flags);
	if (!(flags & 0x8000))
		return; /* Not a response */
	
	__u16 ancount = ntohs(dns_hdr->ancount);
	if (ancount == 0)
		return; /* No answers */
	
	/* Parse question section to get hostname */
	int pos = dns_offset + sizeof(struct dns_header);
	char hostname[256] = {0};
	
	if (pos < packet_len) {
		pos = parse_dns_qname(packet, pos, packet_len, hostname, sizeof(hostname));
		pos += 4; /* Skip QTYPE and QCLASS */
	}
	
	if (hostname[0] == '\0')
		return; /* Couldn't extract hostname */
	
	/* Parse answer records */
	for (int i = 0; i < ancount && pos + 10 < packet_len; i++) {
		/* Skip NAME (compression pointer or full name) */
		if (packet[pos] & 0xc0) {
			pos += 2;
		} else {
			/* Skip variable length name */
			while (pos < packet_len && packet[pos] != 0) {
				if (packet[pos] & 0xc0) {
					pos += 2;
					break;
				}
				__u8 label_len = packet[pos];
				if (pos + label_len + 1 >= packet_len)
					break;
				pos += label_len + 1;
			}
			if (pos < packet_len && packet[pos] == 0)
				pos++;
		}
		
		if (pos + 10 >= packet_len)
			break;
		
		__u16 type = (packet[pos] << 8) | packet[pos + 1];
		pos += 2;
		__u16 class = (packet[pos] << 8) | packet[pos + 1];
		pos += 2;
		pos += 4; /* Skip TTL */
		__u16 rdlength = (packet[pos] << 8) | packet[pos + 1];
		pos += 2;
		
		if (class != 1) /* IN */
			continue;
		
		if (pos + rdlength > packet_len)
			break;
		
		/* Extract A record (IPv4) */
		if (type == 1 && rdlength == 4) {
			/* IP is already in network byte order in DNS packet */
			__u32 ip = (packet[pos] << 24) | (packet[pos + 1] << 16) |
				   (packet[pos + 2] << 8) | packet[pos + 3];
			
			struct dns_mapping_key key = {0};
			key.ip[0] = ip; /* Already in network byte order */
			key.family = AF_INET;
			
			struct dns_mapping_value value = {0};
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			value.timestamp = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
			strncpy(value.hostname, hostname, MAX_HOSTNAME_LEN - 1);
			value.hostname[MAX_HOSTNAME_LEN - 1] = '\0';
			
			if (dns_map_fd >= 0) {
				bpf_map_update_elem(dns_map_fd, &key, &value, BPF_ANY);
			}
		}
		
		/* Extract AAAA record (IPv6) */
		if (type == 28 && rdlength == 16 && pos + 16 <= packet_len) {
			struct dns_mapping_key key = {0};
			/* IPv6 addresses in DNS are in network byte order */
			key.ip[0] = (packet[pos] << 24) | (packet[pos + 1] << 16) |
				    (packet[pos + 2] << 8) | packet[pos + 3];
			key.ip[1] = (packet[pos + 4] << 24) | (packet[pos + 5] << 16) |
				    (packet[pos + 6] << 8) | packet[pos + 7];
			key.ip[2] = (packet[pos + 8] << 24) | (packet[pos + 9] << 16) |
				    (packet[pos + 10] << 8) | packet[pos + 11];
			key.ip[3] = (packet[pos + 12] << 24) | (packet[pos + 13] << 16) |
				    (packet[pos + 14] << 8) | packet[pos + 15];
			key.family = AF_INET6;
			
			struct dns_mapping_value value = {0};
			struct timespec ts;
			clock_gettime(CLOCK_MONOTONIC, &ts);
			value.timestamp = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
			strncpy(value.hostname, hostname, MAX_HOSTNAME_LEN - 1);
			value.hostname[MAX_HOSTNAME_LEN - 1] = '\0';
			
			if (dns_map_fd >= 0) {
				bpf_map_update_elem(dns_map_fd, &key, &value, BPF_ANY);
			}
		}
		
		pos += rdlength;
	}
}

/* Process captured packet */
static void process_packet(const unsigned char *packet, int packet_len)
{
	if (packet_len < sizeof(struct iphdr) + sizeof(struct udphdr))
		return;
	
	struct iphdr *ip_hdr = (struct iphdr *)packet;
	
	if (ip_hdr->version != 4)
		return;
	
	if (ip_hdr->protocol != IPPROTO_UDP)
		return;
	
	int ip_hdr_len = ip_hdr->ihl * 4;
	if (packet_len < ip_hdr_len + sizeof(struct udphdr))
		return;
	
	struct udphdr *udp_hdr = (struct udphdr *)(packet + ip_hdr_len);
	
	/* Check if source port is 53 (DNS server) */
	__u16 sport = ntohs(udp_hdr->source);
	if (sport != 53)
		return;
	
	/* Parse DNS response */
	int dns_offset = ip_hdr_len + sizeof(struct udphdr);
	parse_dns_response(packet, packet_len, dns_offset);
}

/* DNS sniffer thread - uses packet socket to capture DNS packets */
static void *dns_sniffer_thread(void *arg)
{
	(void) arg;
	
	/* Create packet socket to capture UDP packets */
	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (sock < 0) {
		fprintf(stderr, "Failed to create packet socket: %s (need CAP_NET_RAW)\n", strerror(errno));
		return NULL;
	}
	
	unsigned char buffer[4096];
	
	while (!dns_sniffer_stop) {
		ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				fprintf(stderr, "recvfrom failed: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		
		/* Skip Ethernet header (14 bytes) */
		if (len < 14)
			continue;
		
		process_packet(buffer + 14, len - 14);
	}
	
	close(sock);
	return NULL;
}

/* Start DNS sniffer thread */
int dns_sniffer_start(int map_fd)
{
	dns_map_fd = map_fd;
	dns_sniffer_stop = 0;
	
	pthread_t thread;
	if (pthread_create(&thread, NULL, dns_sniffer_thread, NULL) != 0) {
		fprintf(stderr, "Failed to create DNS sniffer thread: %s\n", strerror(errno));
		return -1;
	}
	
	pthread_detach(thread);
	return 0;
}

/* Stop DNS sniffer */
void dns_sniffer_stop_thread(void)
{
	dns_sniffer_stop = 1;
}

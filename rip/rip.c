#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include "microps.h"
#include "util.h"
#include "raw.h"
#include "net.h"
#include "ethernet.h"
#include "udp.h"
#include "dhcp.h"

/* RIPv1 source code */

#define RIP_REQUEST 0x1
#define RIP_RESPONSE 0x2
#define RIP_TRACEON 0x3
#define RIP_TRACEOFF 0x4

#define RIP_VERSION_1 0x1

#define RIP_ADDRESS_FAMILY_IP 0x02

#define RIP_MESSAGE_MIN_LEN 24

#define DEBUG_ADDRESS "192.18.10.0"
#define SEND_ADDRESS "255.255.255.255"
#define RIP_PORT 520

struct netdev *dev;
int sock, res;

typedef struct {
	uint16_t afi; /* address family identifier */
	uint16_t _zero1;
	uint32_t netaddr;
    uint64_t _zero2;
	uint32_t metric;
} __attribute__ ((packed)) RIP_entry_t;

typedef struct {
	uint8_t command;
	uint8_t version;
	uint16_t _zero;
} __attribute__ ((packed)) RIP_t;

/* This implementation is not good */
/* TODO: one-way list? */
RIP_entry_t table[100];
uint16_t num;

int
init(void)
{
	char *ifname = "enp0s20f0u1", *ipaddr = "192.168.1.3", *netmask = "255.255.255.0", *gateway = "192.168.1.1";
	struct netif *netif;

	if(microps_init() < 0) {
		fprintf(stderr, "microps dead...\n");
		return -1;
	}
	dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
	if(!dev) {
		fprintf(stderr, "netdev_alloc() failed\n");
		return -1;
	}
	strncpy(dev->name, ifname, sizeof(dev->name) - 1);
	if(dev->ops->open(dev, RAWDEV_TYPE_AUTO) < 0) {
		fprintf(stderr, "dev->ops->open() failed\n");
		return -1;
	}
	netif = ip_netif_register(dev, ipaddr, netmask, gateway);
	if(!netif) {
		fprintf(stderr, "ip_netif_register() failed\n");
		return -1;
	}
	dev->ops->run(dev);
	return 0;
}

void
cleanup(void)
{
	microps_cleanup();
}

void
rip_dump(uint8_t *buf, size_t n)
{
	RIP_t *p;
	RIP_entry_t *e;
	uint8_t entry_cnt, i;
	char iaddr[IP_ADDR_STR_LEN];

	entry_cnt = (n - 4) / 20;
	p = (RIP_t *)buf;

	fprintf(stderr, "Hello! My name is RIP! Nice to meet you!\n");
	fprintf(stderr, "command: %x\n", p->command);
	fprintf(stderr, "version: %x\n", p->version);

	e = (RIP_entry_t *)(buf + 4);

	for(i = 0; i < entry_cnt; ++i) {
		fprintf(stderr, "--- entry: %x ---\n", i);
		fprintf(stderr, "AFI: %x\n", ntoh16(e[i].afi));
		fprintf(stderr, "netaddr: %s\n", ip_addr_ntop(&e[i].netaddr, iaddr, sizeof(iaddr)));
		fprintf(stderr, "metric: %x\n", ntoh32(e[i].metric));
	}
}

int
rip_rx(void)
{
	ssize_t len;
	uint8_t buf[65536];
	ip_addr_t peer_addr;
	uint16_t peer_port;

	fprintf(stderr, "waiting for RIP...\n");
	len = udp_api_recvfrom(sock, buf, sizeof(buf), &peer_addr, &peer_port, -1);
	if(len <= 0) {
		return -1;
	}
	rip_dump(buf, len);

	return 0;
}

int
rip_tx(void)
{
	uint8_t *buf;
	RIP_t *header;
	RIP_entry_t *entry;
	uint32_t netaddr;

	uint16_t peer_port = hton16(RIP_PORT);
	ip_addr_t peer;
	char debug[IP_ADDR_STR_LEN] = DEBUG_ADDRESS, send[IP_ADDR_STR_LEN] = SEND_ADDRESS;
	size_t psize;

	psize = sizeof(RIP_t) + sizeof(RIP_entry_t) * 1;

	buf = malloc(psize);
	if(!buf) {
		fprintf(stderr, "malloc() failed.\n");
		goto ERROR;
	}
	bzero(buf, psize); /* zero clear */

	header = (RIP_t *)buf;
	header->command = RIP_RESPONSE;
	header->version = RIP_VERSION_1;

	entry = (RIP_entry_t *)(buf + 4);
    entry->afi = hton16(RIP_ADDRESS_FAMILY_IP);
	ip_addr_pton(debug, &netaddr);
	entry->netaddr = netaddr;
	entry->metric = hton32(0x1);

	ip_addr_pton(send, &peer);

	printf("size: %d\n", sizeof(RIP_t));
	hexdump(stderr, buf, psize);

	if(udp_api_sendto(sock, buf, psize, &peer, peer_port) < 0) {
		fprintf(stderr, "udp_api_sendto(): failure\n");
		goto ERROR;
	}

	puts("ok");
	free(buf);
	return 0;

ERROR:
	if(buf)
		free(buf);
	return -1;
}

void
tx_handler(void)
{
	rip_tx();
}

int
regular_update(void)
{
	timer_t tid;
	struct sigaction act, oact;
	struct itimerspec itval;

	if(init() < 0) {
		fprintf(stderr, "init() failed.\n");
		goto ERROR;
	}
	sock = udp_api_open();
	if(sock < 0) {
		fprintf(stderr, "udp sock open failed.\n");
		goto ERROR;
	}
	res = udp_api_bind(sock, NULL, hton16(RIP_PORT));
	if(res < 0) {
		fprintf(stderr, "udp sock bind failed.\n");
		goto ERROR;
	}

	memset(&act, 0, sizeof(struct sigaction));
	memset(&oact, 0, sizeof(struct sigaction));

	act.sa_handler = tx_handler;
	act.sa_flags = SA_RESTART;
	if(sigaction(SIGALRM, &act, &oact) < 0) {
		fprintf(stderr, "sigaction() failed.\n");
		return -1;
	}

	itval.it_value.tv_sec = 30; /* [s] */
	itval.it_value.tv_nsec = 0; /* [ns] */
	itval.it_interval.tv_sec = 30;
	itval.it_interval.tv_nsec = 0;
	if(timer_create(CLOCK_REALTIME, NULL, &tid) < 0) {
		fprintf(stderr, "timer_create() failed.\n");
		return -1;
	}
	if(timer_settime(tid, 0, &itval, NULL) < 0) {
		fprintf(stderr, "timer_settime() failed.\n");
		return -1;
	}

	while(1) {
		;
	}

	timer_delete(tid);
	sigaction(SIGALRM, &oact, NULL);
	udp_api_close(sock);
	cleanup();
	return 0;

ERROR:
	if(sock != -1)
		udp_api_close(sock);
	cleanup();
	return -1;
}

int
main(int argc, char *argv[])
{
	if(regular_update() < 0)
		return -1;
	return 0;
}

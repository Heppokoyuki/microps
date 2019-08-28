#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

#define DEBUG_ADDRESS "198.18.10.0"
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

struct rib {
	uint8_t used;
    uint8_t out; /* if route is on this state, metric must be 16 */
	uint32_t dstaddr;
	uint32_t nexthop;
	uint32_t metric;
	time_t time;
};

/* MAX = max entry count per 1 packet */
struct rib routing_table[256];

int
add_rib_entry(RIP_entry_t *e, uint32_t nexthop)
{
	struct rib *route;

	for(route = routing_table; route < array_tailof(routing_table); ++route) {
		if(route->dstaddr == e->netaddr &&
		   route->nexthop == nexthop) {
            if(ntoh32(e->metric) != 16) {
                route->time = time(NULL);
            }
            route->metric = ntoh32(e->metric);
			return -1;
		}
	}

	for(route = routing_table; route < array_tailof(routing_table); ++route) {
		if(!route->used) {
			route->used = 1;
			route->out = 0;
			route->dstaddr = e->netaddr;
			route->nexthop = nexthop;
			route->metric = ntoh32(e->metric);
			route->time = time(NULL);
			return 0;
		}
	}
    return -1;
}

int
get_rib_entry_count(void)
{
    struct rib *route;
    int result = 0;

    for(route = routing_table; route < array_tailof(routing_table); ++route)
        if(route->used)
            result++;

    return result;
}

void
get_rib_used(struct rib *table)
{
    struct rib *route;

    for(route = routing_table; route < array_tailof(routing_table); ++route) {
        if(route->used) {
            table->used = route->used;
            table->out = route->out;
            table->dstaddr = route->dstaddr;
            table->nexthop = route->nexthop;
            table->metric = route->metric;
            table->time = route->time;
            table++;
        }
    }
}

void
update_rib_entry(void)
{
	struct rib *route;

	for(route = routing_table; route < array_tailof(routing_table); ++route) {
		if(route->used) {
			if(!route->out) {
				if(difftime(time(NULL), route->time) > 180 || route->metric == 16) {
					/* Disabling route */
					route->time = time(NULL);
					route->out = 1;
				    route->metric = 16;
				}
			}
			else {
				if(difftime(time(NULL), route->time) > 120)
					/* Good Bye route */
					route->used = 0;
			}
		}
	}
}

void
dump_rib_entry(void)
{
	struct rib *route;
    char iaddr[IP_ADDR_STR_LEN];

	fprintf(stderr, "RIB entry\n");

	for(route = routing_table; route < array_tailof(routing_table); ++route) {
		if(route->used) {
			fprintf(stderr, "--- entry ---\n");
			fprintf(stderr, "out: %d\n", route->out);
			fprintf(stderr, "dstaddr: %s\n", ip_addr_ntop(&route->dstaddr, iaddr, sizeof(iaddr)));
			fprintf(stderr, "nexthop: %s\n", ip_addr_ntop(&route->nexthop, iaddr, sizeof(iaddr)));
			fprintf(stderr, "metric: %d\n", route->metric);
			fprintf(stderr, "time: %f\n", difftime(time(NULL), route->time));
		}
	}
}

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

void
recv_response(uint8_t *buf, size_t n, uint32_t nexthop)
{
	RIP_entry_t *e;
	uint8_t entry_cnt, i;

	entry_cnt = (n - 4) / 20;
	e = (RIP_entry_t *)(buf + 4);

	for(i = 0; i < entry_cnt; ++i) {
		add_rib_entry(e + i, nexthop);
	}
}

int
rip_rx(void)
{
	ssize_t len;
	uint8_t buf[65536];
	ip_addr_t peer_addr;
	uint16_t peer_port;
	RIP_t *header;

	/** time out **/
	len = udp_api_recvfrom(sock, buf, sizeof(buf), &peer_addr, &peer_port, 30);
	if(len <= 0) {
		return -1;
	}
	rip_dump(buf, len);

	header = (RIP_t *)buf;
	if(header->version != RIP_VERSION_1)
		return -1;

	switch(header->command) {
	case RIP_RESPONSE:
		recv_response(buf, len, peer_addr);
		break;
	default:
		return -1;
	}

	return 0;
}

int
rip_tx(void)
{
	uint8_t *buf;
	RIP_t *header;
	RIP_entry_t *entry;
    int i, ec;
	uint16_t peer_port = hton16(RIP_PORT);
	ip_addr_t peer;
	char debug[IP_ADDR_STR_LEN] = DEBUG_ADDRESS, send[IP_ADDR_STR_LEN] = SEND_ADDRESS;
	size_t psize;
    struct rib *table;

    ec = get_rib_entry_count();

    if(!ec) return -1;

	psize = sizeof(RIP_t) + sizeof(RIP_entry_t) * ec;

	buf = malloc(psize);
	if(!buf) {
		fprintf(stderr, "malloc() failed.\n");
		goto ERROR;
	}
	bzero(buf, psize); /* zero clear */

    table = malloc(sizeof(struct rib) * ec);
    if(!table) {
        fprintf(stderr, "malloc() failed.\n");
        goto ERROR;
    }
    get_rib_used(table);

	header = (RIP_t *)buf;
	header->command = RIP_RESPONSE;
	header->version = RIP_VERSION_1;

	entry = (RIP_entry_t *)(buf + 4);

    for(i = 0; i < ec; ++i) {
        entry[i].afi = hton16(RIP_ADDRESS_FAMILY_IP);
        entry[i].netaddr = table[i].dstaddr;
        entry[i].metric = hton32(table[i].metric);
    }

	ip_addr_pton(send, &peer);

	printf("size: %d\n", sizeof(RIP_t));
	hexdump(stderr, buf, psize);

	if(udp_api_sendto(sock, buf, psize, &peer, peer_port) < 0) {
		fprintf(stderr, "udp_api_sendto(): failure\n");
		goto ERROR;
	}

	puts("ok");
	free(buf);
    free(table);
	return 0;

ERROR:
	if(buf)
		free(buf);
    if(table)
        free(table);
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

	while(1) {
		rip_rx();
        rip_tx();
        update_rib_entry();
		dump_rib_entry();
	}

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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

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
    struct netif *nif;
};

struct interface {
    char *ifname;
    char *ipaddr;
    char *netmask;
    char *gateway;
};

static struct interface ifces[] = {
    {
        .ifname = "enp0s20f0u3",
        .ipaddr = "192.168.10.3",
        .netmask = "255.255.255.0",
        .gateway = NULL
    },
    {
        .ifname = "enp0s20f0u1u1",
        .ipaddr = "192.168.1.3",
        .netmask = "255.255.255.0",
        .gateway = NULL
    }
};

#define DEBUG_NETMASK "255.255.255.0"

/* MAX = max entry count per 1 packet */
struct rib routing_table[256];
struct netif *netif[2];

void
fetch_rib_fib(struct rib *route)
{
    ip_addr_t n;
    char iaddr[IP_ADDR_STR_LEN];

    ip_addr_pton(DEBUG_NETMASK, &n);
    ip_route_add(route->dstaddr, n, route->nexthop, route->nif);
    fprintf(stderr, "inserting fib...\n");
    fprintf(stderr, "dstaddr: %s\n", ip_addr_ntop(&route->dstaddr, iaddr, sizeof(iaddr)));
    fprintf(stderr, "netmask: %s\n", ip_addr_ntop(&n, iaddr, sizeof(iaddr)));
    fprintf(stderr, "nexthop: %s\n", ip_addr_ntop(&route->nexthop, iaddr, sizeof(iaddr)));
    fprintf(stderr, "nif: %p\n", route->nif);
}

int
add_rib_entry(RIP_entry_t *e, uint32_t nexthop, struct netif *nif)
{
	struct rib *route;

	for(route = routing_table; route < array_tailof(routing_table); ++route) {
		if(!route->used) {
			route->used = 1;
			route->out = 0;
			route->dstaddr = e->netaddr;
			route->nexthop = nexthop;
			route->metric = ntoh32(e->metric) + 1;
			route->time = time(NULL);
            route->nif = nif;
            fetch_rib_fib(route);
			return 0;
		}
	}
    return -1;
}

int
add_rib_entry_internally(uint32_t netaddr, struct netif *nif)
{
    struct rib *route;

    for(route = routing_table; route < array_tailof(routing_table); ++route) {
        if(!route->used) {
            route->used = 1;
            route->out = 0;
            route->dstaddr = netaddr;
            route->nexthop = 0; /* me */
            route->metric = 1;
            route->time = 0;
            route->nif = nif;
            return 0;
        }
    }
    return -1;
}

void
update_rib_entry(RIP_entry_t *e, struct rib *route, uint32_t nexthop)
{
    route->nexthop = nexthop;
    route->metric = ntoh32(e->metric);
    route->time = time(NULL);
}

struct rib *
get_entry_exist_rib(RIP_entry_t *e)
{
    struct rib *route;

    for(route = routing_table; route < array_tailof(routing_table); ++route)
        if(route->used && route->dstaddr == e->netaddr)
            return route;
    return NULL;
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
update_rib(void)
{
	struct rib *route;

	for(route = routing_table; route < array_tailof(routing_table); ++route) {
		if(route->used) {
            if(route->time == 0 && route->nexthop == 0)
                break;
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
ifsetup(struct interface *ifc, struct netif **nif)
{
    struct netdev *dev;
    uint32_t netaddr;
    ip_addr_t unicast, netmask;

    dev = netdev_alloc(NETDEV_TYPE_ETHERNET);
    if (!dev) {
        fprintf(stderr, "netdev_alloc(): error\n");
        return -1;
    }
    strncpy(dev->name, ifc->ifname, sizeof(dev->name) -1);
    if (dev->ops->open(dev, RAWDEV_TYPE_AUTO) == -1) {
        fprintf(stderr, "dev->ops->open(): error\n");
        return -1;
    }
    *nif = ip_netif_register(dev, ifc->ipaddr, ifc->netmask, ifc->gateway);
    if (!*nif) {
        fprintf(stderr, "ip_register_interface(): error\n");
        return -1;
    }
    dev->ops->run(dev);

    ip_addr_pton(ifc->ipaddr, &unicast);
    ip_addr_pton(ifc->netmask, &netmask);
    netaddr = unicast & netmask;
    add_rib_entry_internally(netaddr, *nif);

    return 0;
}

int
init(void)
{
    struct interface *ifc;
    struct netif **nif;

	if(microps_init() < 0) {
		fprintf(stderr, "microps dead...\n");
		return -1;
	}
    if (!ip_set_forwarding(1)) {
        fprintf(stderr, "ip_set_forwarding(): error\n");
        return -1;
    }
    for(ifc = ifces, nif = netif; ifc < array_tailof(ifces); ++ifc, ++nif) {
        if(ifsetup(ifc, nif) < 0) {
            fprintf(stderr, "ifsetup() failed.\n");
            return -1;
        }
    }
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
recv_response(uint8_t *buf, size_t n, uint32_t nexthop, struct netif *nif)
{
	RIP_entry_t *e;
    RIP_entry_t *f;
    struct rib *route;
	uint8_t entry_cnt, i;

    if(nif == NULL) return;

	entry_cnt = (n - 4) / 20;
	e = (RIP_entry_t *)(buf + 4);

	for(i = 0; i < entry_cnt; ++i) {
        f = e + i;
        route = get_entry_exist_rib(f);
        fprintf(stderr, "%p, %d\n", route, ntoh32(f->metric));
        if(route == NULL && ntoh32(f->metric) < 16) {
            fprintf(stderr, "hoge\n");
            add_rib_entry(f, nexthop, nif);
        }
        else {
            if(route->nexthop == nexthop) {
                update_rib_entry(f, route, nexthop);
            }
            else if(route->metric > ntoh32(f->metric)){
                update_rib_entry(f, route, nexthop);
            }
        }
	}
}

void *
rip_rx(void *sock)
{
	ssize_t len;
	uint8_t buf[65536];
	ip_addr_t peer_addr;
	uint16_t peer_port;
	RIP_t *header;

	/** time out **/
	len = udp_api_recvfrom(*(int *)sock, buf, sizeof(buf), &peer_addr, &peer_port, 30);
	if(len <= 0) {
		return;
	}
	rip_dump(buf, len);

	header = (RIP_t *)buf;
	if(header->version != RIP_VERSION_1)
		return;

	switch(header->command) {
	case RIP_RESPONSE:
        fprintf(stderr, "iface: %p\n", udp_api_get_iface_from_socket(*(int *)sock));
		recv_response(buf, len, peer_addr, udp_api_get_iface_from_socket(*(int *)sock));
		break;
	default:
		return;
	}
}

void *
rip_tx(void *sock)
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

    if(!ec) return;

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

	if(udp_api_sendto(*(int *)sock, buf, psize, &peer, peer_port) < 0) {
		fprintf(stderr, "udp_api_sendto(): failure\n");
		goto ERROR;
	}

	puts("ok");
	free(buf);
    free(table);
	return;

ERROR:
	if(buf)
		free(buf);
    if(table)
        free(table);
	return;
}

int
regular_update(void)
{
    int sock[2], res, i;
    pthread_t thread[2];

	if(init() < 0) {
		fprintf(stderr, "init() failed.\n");
		goto ERROR;
	}

    for(i = 0; i < 2; ++i) {
        sock[i] = udp_api_open();
        if(sock[i] < 0) {
            fprintf(stderr, "udp sock open failed.\n");
            goto ERROR;
        }
        fprintf(stderr, "%d: %p\n", i, netif[i]);
        res = udp_api_bind_iface(sock[i], netif[i], hton16(RIP_PORT));
        if(res < 0) {
            fprintf(stderr, "%d udp sock bind failed.\n", i);
            goto ERROR;
        }
    }

	while(1) {
        for(i = 0; i < 2; ++i)
            pthread_create(&thread[i], NULL, &rip_rx, &sock[i]);
        for(i = 0; i < 2; ++i)
            pthread_join(thread[i], NULL); /** wait **/

        /* for(i = 0; i < 2; ++i) */
        /*     pthread_create(&thread[i], NULL, &rip_tx, &sock[i]); */
        /* for(i = 0; i < 2; ++i) */
        /*     pthread_join(thread[i], NULL); /\** wait **\/ */

        for(i = 0; i < 2; ++i)
            rip_tx(&sock[i]);

        update_rib();
		dump_rib_entry();
	}

    for(i = 0; i < 2; ++i)
        udp_api_close(sock[i]);
	cleanup();
	return 0;

ERROR:
    for(i = 0; i < 2; ++i)
        if(sock[i] != -1)
            udp_api_close(sock[i]);
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

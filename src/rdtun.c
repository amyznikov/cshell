/*
 * rdtun.c
 *
 *  Created on: Feb 9, 2018
 *      Author: amyznikov
 */

#include <unistd.h>
#include <cuttle/debug.h>
#include <cuttle/ccarray.h>
#include <cuttle/cothread/scheduler.h>
#include <arpa/inet.h>
#include "rdtun.h"
#include "checksum.h"
#include "ip-pkt.h"


static ccarray_t rtable; /* <struct rtable_item> */
struct sockaddr_in g_microsrv_bind_address;

static ssize_t rtable_find_resp(struct in_addr addr, in_port_t port)
{
  size_t i, n;
  for ( i = 0, n = ccarray_size(&rtable); i < n; ++i ) {
    struct rtable_item * item = ccarray_peek(&rtable, i);
    if ( item->resp.sin_addr.s_addr == addr.s_addr && item->resp.sin_port == port ) {
      return i;
    }
  }
  return -1;
}


struct rtable_item * rtable_get_resp(struct in_addr addr, in_port_t port)
{
  ssize_t pos = rtable_find_resp(addr, port);
  return pos < 0 ? NULL : ccarray_peek(&rtable, pos);
}

static void rtable_add_route(struct in_addr srcaddr, in_port_t srcport,
    struct in_addr dstaddr, in_port_t dstport,
    struct in_addr respaddr, in_port_t respport )
{
  struct sockaddr_in src, dst, resp;
  memset(&src, 0, sizeof(src));
  memset(&dst, 0, sizeof(dst));
  memset(&resp, 0, sizeof(resp));

  src.sin_addr = srcaddr;
  src.sin_port = srcport;

  dst.sin_addr = dstaddr;
  dst.sin_port = dstport;

  resp.sin_addr = respaddr;
  resp.sin_port = respport;

  ssize_t pos = rtable_find_resp(resp.sin_addr, resp.sin_port);
  if ( pos < 0 ) {
    CF_WARNING("rtable_find_resp() fails for %s:%u", inet_ntoa(resp.sin_addr), ntohs(resp.sin_port));
    ccarray_push_back(&rtable, &(struct rtable_item ) {
          .src = src,
          .dst = dst,
          .resp = resp,
        });
  }
  else {
    struct rtable_item * item = ccarray_peek(&rtable, pos);
    item->src = src;
    item->dst = dst;
  }
}

/* cothread version of rdtun() ip forwaring */
static int cordtun(void * arg, uint32_t events)
{
  int tunfd = (int)(ssize_t)(arg);

  const size_t MAX_PKT_SIZE = 4 * 1024;    // MUST BE >= MAX POSSIBLE MTU
  uint32_t pktbuf[MAX_PKT_SIZE / sizeof(uint32_t)];
  ssize_t pktsize;

  struct ip * ip;
  size_t iphsize;
  struct tcphdr * tcp;
  size_t tcphsize;
  void * tcppld;
  size_t pldsize;
  ssize_t cb;
  const struct rtable_item * item;

  CF_DEBUG("ENTER. EVEBTS = 0x%0X", events);
  while ( (pktsize = read(tunfd, pktbuf, sizeof(pktbuf))) > 0 ) {

    CF_DEBUG("parsepkt");
    if ( !parsepkt(pktbuf, pktsize, &ip, &iphsize, &tcp, &tcphsize, &tcppld, &pldsize) ) {
      CF_NOTICE("PKT not parsed\n");
      continue;
    }

    if ( !tcp ) {
      CF_NOTICE("Not a TCP\n");
      continue;
    }

    //  dumppkt("R", ip, iphsize, tcp, tcphsize, tcppld, pldsize);

    if ( ip->ip_src.s_addr == g_microsrv_bind_address.sin_addr.s_addr
        && tcp->source == g_microsrv_bind_address.sin_port ) {

      CF_NOTICE("Reply FROM internal server");

      if ( (item = rtable_get_resp(ip->ip_dst, tcp->dest)) ) {
        ip->ip_src.s_addr = item->dst.sin_addr.s_addr;
        tcp->source = item->dst.sin_port;
        ip->ip_dst.s_addr = item->src.sin_addr.s_addr;
        tcp->dest = item->src.sin_port;
      }
    }
    else {

      struct in_addr resp_addrs = { ip->ip_dst.s_addr };
      in_port_t resp_port = tcp->source;

      CF_NOTICE("Redirect TO internal server");
      rtable_add_route(ip->ip_src, tcp->source, ip->ip_dst, tcp->dest, resp_addrs, resp_port);

      ip->ip_src.s_addr = ip->ip_dst.s_addr;
      // tcp->source = tcp->dest;

      ip->ip_dst.s_addr = g_microsrv_bind_address.sin_addr.s_addr;
      tcp->dest = g_microsrv_bind_address.sin_port;
    }

    update_ip_checksum(ip);
    update_tcp_checksum(ip);

    // dumppkt("W", ip, iphsize, tcp, tcphsize, tcppld, pldsize);

    if ( (cb = co_write(tunfd, ip, ntohs(ip->ip_len))) <= 0 ) {
      CF_FATAL("write(tunfd) fails: %s", strerror(errno));
    }
  }

  return 0;
}


bool start_rdtun_cothread(int tunfd, const struct sockaddr_in * microsrv_bind_address)
{
  g_microsrv_bind_address = *microsrv_bind_address;

  if ( !ccarray_init(&rtable, 65535, sizeof(struct rtable_item)) ) {
    CF_FATAL("ccarray_init(rtable) fails: %s", strerror(errno));
    return false;
  }

  so_set_non_blocking(tunfd, 1);

  if ( !co_schedule_io(tunfd, EPOLLIN, cordtun, (void *) (ssize_t) (tunfd), 1024 * 1024) ) {
    CF_FATAL("co_schedule_io(rdtun) fails: %s", strerror(errno));
    return false;
  }
  return true;
}

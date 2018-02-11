/*
 * rdtun.c
 *
 *  Created on: Feb 9, 2018
 *      Author: amyznikov
 */

#include <unistd.h>
#include <cuttle/debug.h>
#include <cuttle/ccarray.h>
#include <cuttle/sockopt.h>
#include <cuttle/cothread/scheduler.h>
//#include </inet.h>
#include <arpa/inet.h>
#include "rdtun.h"
#include "checksum.h"
#include "ip-pkt.h"

#define CO_STACK_SIZE   (16*1024*1024)


static ccarray_t g_tunnel_route_table; /* <struct tunnel_route_table_item> */
struct sockaddr_in g_tcp_dst_address;


// sockaddr_in stupid comparator
static int rspcmp(const struct tunnel_route_table_item * item, const struct sockaddr_in * rsp)
{
  if ( item->rsp.sin_addr.s_addr < rsp->sin_addr.s_addr ) {
    return -1;
  }
  if ( item->rsp.sin_addr.s_addr > rsp->sin_addr.s_addr ) {
    return +1;
  }
  if ( item->rsp.sin_port < rsp->sin_port ) {
    return -1;
  }
  if ( item->rsp.sin_port > rsp->sin_port ) {
    return +1;
  }
  return 0;
}

struct tunnel_route_table_item * rtable_get_rsp(struct in_addr addr, in_port_t port)
{
  const struct sockaddr_in rsp = {
    .sin_family = AF_INET,
    .sin_addr = addr,
    .sin_port = port,
    .sin_zero = {}
  };

  const size_t size = ccarray_size(&g_tunnel_route_table);
  const size_t pos = ccarray_lowerbound(&g_tunnel_route_table, 0, size, (cmpfunc_t)rspcmp, &rsp);

  if ( pos < size ) {
    struct tunnel_route_table_item * item = ccarray_peek(&g_tunnel_route_table, pos);
    if ( rspcmp(item, &rsp) == 0 ) {
      return item;
    }
  }
  return NULL;
}


static void rtable_add_route(struct in_addr srcaddr, in_port_t srcport,
    struct in_addr dstaddr, in_port_t dstport,
    struct in_addr rspaddr, in_port_t rspport )
{
  const struct sockaddr_in src = {
    .sin_family = AF_INET,
    .sin_addr = srcaddr,
    .sin_port = srcport,
    .sin_zero = {}
  };

  const struct sockaddr_in dst = {
    .sin_family = AF_INET,
    .sin_addr = dstaddr,
    .sin_port = dstport,
    .sin_zero = {}
  };

  const struct sockaddr_in rsp = {
    .sin_family = AF_INET,
    .sin_addr = rspaddr,
    .sin_port = rspport,
    .sin_zero = {}
  };

  struct tunnel_route_table_item * item;

  const size_t size = ccarray_size(&g_tunnel_route_table);
  const size_t pos = ccarray_lowerbound(&g_tunnel_route_table, 0, size, (cmpfunc_t) rspcmp, &rsp);

  if ( pos >= size ) {
    ccarray_push_back(&g_tunnel_route_table,
        &(struct tunnel_route_table_item ) {
          .src = src,
          .dst = dst,
          .rsp = rsp
        });
  }
  else if ( rspcmp(item = ccarray_peek(&g_tunnel_route_table, pos), &rsp) != 0 ) {
    ccarray_insert(&g_tunnel_route_table, pos,
        &(struct tunnel_route_table_item ) {
          .src = src,
          .dst = dst,
          .rsp = rsp,
        });
  }
  else {
    item->src = src;
    item->dst = dst;
  }
}



/* cothread version of rdtun() ip forwaring */
static int rdtun(void * arg, uint32_t events)
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
  const struct tunnel_route_table_item * item;

//  CF_DEBUG("***********************\n"
//      "ENTER. tunfd=%d EVENTS = 0x%0X", tunfd, events);

  if ( events & EPOLLERR ) {
    CF_FATAL("FATAL EPOLLERR ENCOUNTERED!!!");
  }

  while ( (pktsize = read(tunfd, pktbuf, sizeof(pktbuf))) > 0 ) {

    CF_DEBUG("parsepkt: %zd bytes", pktsize);
    if ( !parsepkt(pktbuf, pktsize, &ip, &iphsize, &tcp, &tcphsize, &tcppld, &pldsize) ) {
      CF_NOTICE("NOT PARSED\n");
      continue;
    }

    if ( !tcp ) {
      CF_NOTICE("NOT A TCP\n");
      continue;
    }

    //  dumppkt("R", ip, iphsize, tcp, tcphsize, tcppld, pldsize);

    if ( ip->ip_src.s_addr == g_tcp_dst_address.sin_addr.s_addr
        && tcp->source == g_tcp_dst_address.sin_port ) {

      CF_NOTICE("Reply FROM internal server");

      if ( (item = rtable_get_rsp(ip->ip_dst, tcp->dest)) ) {
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

      ip->ip_dst.s_addr = g_tcp_dst_address.sin_addr.s_addr;
      tcp->dest = g_tcp_dst_address.sin_port;
    }

    update_ip_checksum(ip);
    update_tcp_checksum(ip);

    // dumppkt("W", ip, iphsize, tcp, tcphsize, tcppld, pldsize);

    //if ( (cb = co_write(tunfd, ip, ntohs(ip->ip_len))) <= 0 ) {
    if ( (cb = write(tunfd, ip, ntohs(ip->ip_len))) <= 0 ) {
      CF_FATAL("write(tunfd) fails: %s", strerror(errno));
    }
  }

//  CF_DEBUG("read(): %zd bytes", pktsize);
//  CF_DEBUG("LEAVE\n==================");

  return 0;
}


bool start_rdtun(int tunfd, const struct sockaddr_in * tcp_dst_address)
{
  g_tcp_dst_address = *tcp_dst_address;

  if ( !ccarray_init(&g_tunnel_route_table, 65535, sizeof(struct tunnel_route_table_item)) ) {
    CF_FATAL("ccarray_init(rtable) fails: %s", strerror(errno));
    return false;
  }

  so_set_non_blocking(tunfd, 1);

  if ( !co_schedule_io(tunfd, EPOLLIN, rdtun, (void *) (ssize_t) (tunfd), CO_STACK_SIZE) ) {
    CF_FATAL("co_schedule_io(rdtun) fails: %s", strerror(errno));
    return false;
  }
  return true;
}

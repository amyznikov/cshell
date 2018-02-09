/*
 * ip-pkt.c
 *
 *  Created on: Feb 8, 2018
 *      Author: amyznikov
 */

#include <stdio.h>
#include <arpa/inet.h>
#include "ip-pkt.h"
#include <cuttle/debug.h>

bool parsepkt(void * buf, size_t size, struct ip ** _ip, size_t * _iphsize,
    struct tcphdr ** _tcp, size_t * _tcphsize, void ** _tcppld, size_t * _pldsize)
{
  struct ip * pkt = NULL;
  struct tcphdr * tcp = NULL;
  ssize_t pktsize, iphsize, tcphsize;

  if ( _ip ) {
    *_ip = NULL;
  }
  if ( _iphsize ) {
    *_iphsize = 0;
  }
  if ( _tcp ) {
    *_tcp = NULL;
  }
  if ( _tcphsize ) {
    *_tcphsize = 0;
  }
  if ( _tcppld ) {
    *_tcppld = NULL;
  }
  if ( _pldsize ) {
    *_pldsize = 0;
  }

  if ( (pkt = buf)->ip_v != 4  ) {
    CF_DEBUG("NOT IPv4");
    return false;
  }

  if ( size != (pktsize = ntohs(pkt->ip_len)) ) {
    CF_DEBUG("Invalid pkt size");
    return false;
  }


  if ( _ip ) { // ip header pointer
    *_ip = pkt;
  }

  iphsize = pkt->ip_hl * 4; // ip header size in bytes
  if ( _iphsize ) {
    * _iphsize = iphsize;
  }

  if ( pkt->ip_p != IPPROTO_TCP ) {
    CF_DEBUG(" Not a TCP: pkt->ip_p=%u", pkt->ip_p);
  }
  else{

    tcp = (struct tcphdr *) (((uint8_t*) pkt) + iphsize);
    if ( _tcp ) {
      *_tcp = tcp;
    }

    tcphsize = tcp->doff * 4;
    if ( _tcphsize ) {
      *_tcphsize = tcphsize;
    }

    if ( _tcppld ) {
      *_tcppld = ((uint8_t*) tcp) + tcphsize;
    }

    if ( _pldsize ) {
      ssize_t hdrsize = pkt->ip_hl * 4 + tcp->doff * 4;
      *_pldsize = pktsize > hdrsize ? pktsize - hdrsize : 0;
    }
  }

  return true;
}

void dumppkt(const char * prefix,
    const struct ip * ip,
    size_t iphsize,
    const struct tcphdr * tcp,
    size_t tcphsize,
    void * tcppld,
    size_t pldsize)
{
  (void)(iphsize);
  (void)(tcphsize);

  char srcaddrs[256], dstaddrs[256];

  sprintf(srcaddrs, "%s:%u", inet_ntoa(ip->ip_src), ntohs(tcp->source));
  sprintf(dstaddrs, "%s:%u", inet_ntoa(ip->ip_dst), ntohs(tcp->dest));

  CF_NOTICE("%s %s --> %s  ip_len=%u IP-CHK=%u TCP-CHK=%u SYN=%u FIN=%u RST=%u ACK=%u SEQ=%u DOFF=%u",
      prefix,
      srcaddrs, dstaddrs,
      ntohs(ip->ip_len),
      ntohs(ip->ip_sum),
      ntohs(tcp->check),
      tcp->syn, tcp->fin, tcp->rst, tcp->ack,
      tcp->seq,
      tcp->doff);
  if ( pldsize > 0 ) {
    // *((char*)tcppld + pldsize) = 0;
    CF_DEBUG("%s PLD='%s'", prefix, (char*)tcppld);
  }
}

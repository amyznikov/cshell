/*
 * ip-pkt.h
 *
 *  Created on: Feb 8, 2018
 *      Author: amyznikov
 */

#pragma once

#ifndef ___ip_pkt_h___
#define ___ip_pkt_h___

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>


#ifdef __cplusplus
extern "C" {
#endif

/*************************************************************************************
 * pktbuf: pointer to begin of memory buffer with IP packet
 * size  : size of ip packet pointed by pktbuf
 */
bool parsepkt(void * pktbuf, size_t size,
    struct ip ** _ip, size_t * _iphsize,
    struct tcphdr ** _tcp, size_t * _tcphsize,
    void ** _tcppld, size_t * _pldsize);


void dumppkt(const char * prefix,
    const struct ip * ip,
    size_t iphsize,
    const struct tcphdr * tcp,
    size_t tcphsize,
    void * tcppld,
    size_t pldsize);


#ifdef __cplusplus
}
#endif

#endif /* ___ip_pkt_h___ */

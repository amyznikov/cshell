/*
 * checksum.h
 *
 *  Created on: Feb 7, 2018
 *      Author: amyznikov
 */

#pragma once

#ifndef ___checksums_h___
#define ___checksums_h___

#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


#ifdef __cplusplus
extern "C" {
#endif


/** Update IP header checksum
 * http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
 */
void update_ip_checksum(struct ip * pkt);

/**
 * update TCP checksum for IP packet (IPPROTO_TCP is assumed)
 *  https://en.wikipedia.org/wiki/Transmission_Control_Protocol
 */
void update_tcp_checksum(struct ip * pkt);


/*
 * TCP checksum calculation function
 * https://en.wikipedia.org/wiki/Transmission_Control_Protocol
 */
uint16_t tcp_checksum(const void * buf, int nbytes);



#ifdef __cplusplus
}
#endif

#endif /* ___checksums_h___ */

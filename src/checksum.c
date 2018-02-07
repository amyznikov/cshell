/*
 * checksum.c
 *
 *  Created on: Feb 7, 2018
 *      Author: amyznikov
 */
#include <stddef.h>
#include <string.h>
#include "checksum.h"


/*
 * IP header checksum calculation function
 * http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
 */
void update_ip_checksum(struct ip * pkt)
{
  // Cast the data pointer to one that can be indexed.
  char * data = (char*) pkt;
  size_t length = pkt->ip_hl * 4;

  // Initialise the accumulator.
  uint32_t acc = 0xffff;

  pkt->ip_sum = 0;

  // Handle complete 16-bit blocks.
  for ( size_t i = 0; i + 1 < length; i += 2 ) {
    uint16_t word;
    memcpy(&word, data + i, 2);
    acc += ntohs(word);
    if ( acc > 0xffff ) {
      acc -= 0xffff;
    }
  }

  // Handle any partial block at the end of the data.
  if ( length & 1 ) {
    uint16_t word = 0;
    memcpy(&word, data + length - 1, 1);
    acc += ntohs(word);
    if ( acc > 0xffff ) {
      acc -= 0xffff;
    }
  }

  // Return the checksum in network byte order.
  pkt->ip_sum = htons(~acc);
}


/*
 * TCP checksum calculation function
 * https://en.wikipedia.org/wiki/Transmission_Control_Protocol
 */
uint16_t tcp_checksum(const void * buf, int nbytes)
{
  const uint16_t * ptr = buf;
  uint16_t oddbyte;
  uint16_t answer;
  long sum;

  sum = 0;
  while ( nbytes > 1 ) {
    sum += *ptr++;
    nbytes -= 2;
  }
  if ( nbytes == 1 ) {
    oddbyte = 0;
    *((u_char*) &oddbyte) = *(u_char*) ptr;
    sum += oddbyte;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum = sum + (sum >> 16);
  answer = ~sum;

  return (answer);
}

/*
 * For TCP pseudoheader format see
 *  https://en.wikipedia.org/wiki/Transmission_Control_Protocol
 */
void update_tcp_checksum(struct ip * pkt)
{
  // pointer to tcp header
  struct tcphdr * tcp = (struct tcphdr *) (((uint8_t*) pkt) + pkt->ip_hl * 4);

  // total tcp segment size (tcp header + payload)
  size_t tcpsize = ntohs(pkt->ip_len) - pkt->ip_hl * 4;

#pragma pack(push,1)
  struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
    uint8_t tcpdata[tcpsize];
  } ph;
#pragma pack(pop)

  ph.source_address = pkt->ip_src.s_addr;
  ph.dest_address = pkt->ip_dst.s_addr;
  ph.placeholder = 0;
  ph.protocol = pkt->ip_p;
  ph.tcp_length = htons(tcpsize);

  tcp->check = 0;
  memcpy(ph.tcpdata, tcp, tcpsize);
  tcp->check = tcp_checksum(&ph, sizeof(ph));    // offsetof(struct pseudo_header, tcpdata) + tcpsize
}

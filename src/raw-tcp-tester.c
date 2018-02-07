/*
 * Based on
 *  http://www.binarytides.com/raw-sockets-c-code-linux/
 *  Raw TCP packets
 *    Silver Moon (m00n.silv3r@gmail.com)
 */
#include<unistd.h>
#include<stdio.h> //for printf
#include<string.h> //memset
#include<sys/socket.h>    //for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<arpa/inet.h>
#include<pthread.h>
#include"sockopt.h"
#include"debug.h"




static void * mircosrv_thread(void * arg)
{
  int so1, so2;
  struct sockaddr_in sin;

  (void)(arg);

  pthread_detach(pthread_self());

  if ( (so1 = so_tcp_listen("192.168.0.107", 6007, &sin)) == -1 ) { // 127.0.0.1
    CF_FATAL("tcp_listen() fails");
    return NULL;
  }

  while ( (so2 = accept(so1, NULL, NULL)) ) {
    CF_DEBUG("accepted!!!!");
    close(so2);
  }

  return NULL;
}

static bool start_mircosrv_thread()
{
  pthread_t pid;
  int status = pthread_create(&pid, NULL, mircosrv_thread, NULL);
  if ( status ) {
    CF_FATAL("pthread_create() fauls: %s", strerror(status));
  }
  return status == 0;
}

/*
 96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
 */
struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

/*
 Generic checksum calculation function
 */
static unsigned short tcp_checksum(unsigned short *ptr, int nbytes)
{
  register long sum;
  unsigned short oddbyte;
  register short answer;

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
  answer = (short) ~sum;

  return (answer);
}

static bool parsepkt(void * buf, size_t size, struct ip ** _ip, size_t * _iphsize,
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

  if ( (pkt = buf)->ip_v != 4 ) {
    CF_DEBUG("NOT IPv4");
    return false;
  }

  if ( size != (pktsize = ntohs(pkt->ip_len)) ) {
    CF_DEBUG("Invalid pkt size: size=%zu pkt->ip_len=%u pktsize = ntohs(pkt->ip_len)=%zd", size, pkt->ip_len, pktsize);
    return false;
  }

  if ( _ip ) {    // ip header pointer
    *_ip = pkt;
  }

  iphsize = pkt->ip_hl * 4;    // ip header size in bytes
  if ( _iphsize ) {
    *_iphsize = iphsize;
  }

  if ( pkt->ip_p != IPPROTO_TCP ) {
    CF_DEBUG(" Not a TCP: pkt->ip_p=%u", pkt->ip_p);
  }
  else {

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
      CF_DEBUG("* _pldsize=%zu", *_pldsize);
    }
  }

  return true;
}

static void dumppkt(void * buf, size_t size)
{
  struct ip * _ip;
  size_t _iphsize;
  struct tcphdr * _tcp;
  size_t _tcphsize;
  void * _tcppld;
  size_t _pldsize;

  if ( !parsepkt(buf, size, &_ip, &_iphsize, &_tcp, &_tcphsize, &_tcppld, &_pldsize) ) {
    CF_FATAL("parsepkt() fails\n");
    return;
  }

  if ( !_tcp ) {
    CF_FATAL("Not a TCP");
    return;
  }

  CF_DEBUG("B SRC=%s:%u", inet_ntoa(_ip->ip_src), ntohs(_tcp->source));
  CF_DEBUG("B DST=%s:%u", inet_ntoa(_ip->ip_dst), ntohs(_tcp->dest));
  CF_DEBUG("B CHK=%u", ntohs(_ip->ip_sum));
  CF_DEBUG("B SYN=%u", _tcp->syn);
  CF_DEBUG("B ACK=%u", _tcp->ack);
  CF_DEBUG("B SEQ=%u\n", _tcp->seq);
}

//Datagram to represent the packet
static void gendgram(char datagram[4096], const char * source_ip, uint16_t source_port, const char * dest_ip, uint16_t dest_port )
{
  char *data, *pseudogram;

  struct sockaddr_in src_sin;
  struct sockaddr_in dst_sin;

  //zero out the packet buffer
  memset(datagram, 0, 4096);
  so_sockaddr_in(source_ip, source_port, &src_sin);
  so_sockaddr_in(dest_ip, dest_port, &dst_sin );

  //IP header
  struct iphdr *iph = (struct iphdr *) datagram;

  //TCP header
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
  struct pseudo_header psh;

  //Data part
  data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
  strcpy(data, "");

  //Fill in the IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data));
  iph->id = htonl(54321);    //Id of this packet
  iph->frag_off = 0;
  iph->ttl = 255;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      //Set to 0 before calculating checksum
  iph->saddr = src_sin.sin_addr.s_addr; // Spoof the source ip address
  iph->daddr = dst_sin.sin_addr.s_addr;

  //Ip checksum
  iph->check = 0;// csum((unsigned short *) datagram, ntohs(iph->tot_len));

  //TCP Header
  tcph->source = src_sin.sin_port;// htons(1234);
  tcph->dest = dst_sin.sin_port;// htons(80);
  tcph->seq = 123456;
  tcph->ack_seq = 0;
  tcph->doff = 5;    //tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->window = htons(5840); /* maximum allowed window size */
  tcph->check = 0;    //leave checksum 0 now, filled later by pseudo header
  tcph->urg_ptr = 0;

  //Now the TCP checksum
  psh.source_address = src_sin.sin_addr.s_addr;// inet_addr(source_ip);
  psh.dest_address = dst_sin.sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));

  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
  pseudogram = malloc(psize);

  memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));

  tcph->check = tcp_checksum((unsigned short*) pseudogram, psize);
}


int main(void)
{
  cf_set_logfilename("stderr");
  cf_set_loglevel(CF_LOG_DEBUG);


  if ( !start_mircosrv_thread() ) {
    CF_FATAL("start_mircosrv_thread() fails");
    return 1;
  }

  //Create a raw socket
  int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
  if ( s == -1 ) {
    //socket creation failed, may be because of non-root privileges
    perror("Failed to create socket");
    exit(1);
  }

  //IP_HDRINCL to tell the kernel that headers are included in the packet
  int one = 1;
  const int *val = &one;
  if ( setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 ) {
    perror("Error setting IP_HDRINCL");
    exit(0);
  }

  //Datagram to represent the packet
  char datagram[4096];
  gendgram(datagram, "127.0.0.1", 6002, "192.168.0.107", 6007 );

  //source_ip[32], *data, *pseudogram;

//  strcpy(source_ip, "127.0.0.1");
//
//  struct sockaddr_in src_sin;
//  memset(&src_sin, 0, sizeof(src_sin));
//  src_sin.sin_family = AF_INET;
//  src_sin.sin_addr.s_addr = inet_addr(source_ip);
//  src_sin.sin_port = htons(6002);
//  if ( bind(s, (struct sockaddr*) &src_sin, sizeof(src_sin)) == -1 ) {
//    CF_FATAL("bind() fails: %s", strerror(errno));
//  }
//
//  {
//  struct sockaddr_in ssin;
//  socklen_t ssin_len = sizeof(ssin);
//  memset(&ssin, 0, sizeof(ssin));
//  getsockname(s, &ssin, &ssin_len);
//  CF_DEBUG("rawfd: %s:%u", inet_ntoa(ssin.sin_addr), ntohs(ssin.sin_port));
//  }
//
//
//  //some address resolution
//  struct sockaddr_in dst_sin;
//  dst_sin.sin_family = AF_INET;
//  dst_sin.sin_port = htons(6001);
//  dst_sin.sin_addr.s_addr = inet_addr("127.0.0.1");
//
//
//
//  //zero out the packet buffer
//  memset(datagram, 0, 4096);
//
//  //IP header
//  struct iphdr *iph = (struct iphdr *) datagram;
//
//  //TCP header
//  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
//  struct pseudo_header psh;
//
//  //Data part
//  data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
//  strcpy(data, ""); // ABCDEFGHIJKLMNOPQRSTUVWXYZ
//
//
//  //Fill in the IP Header
//  iph->ihl = 5;
//  iph->version = 4;
//  iph->tos = 0;
//  iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data));
//  iph->id = htonl(54321);    //Id of this packet
//  iph->frag_off = 0;
//  iph->ttl = 255;
//  iph->protocol = IPPROTO_TCP;
//  iph->check = 0;      //Set to 0 before calculating checksum
//  iph->saddr = inet_addr(source_ip);    //Spoof the source ip address
//  iph->daddr = dst_sin.sin_addr.s_addr;
//
//  //Ip checksum
//  iph->check = 0;//csum((unsigned short *) datagram, ntohs(iph->tot_len));
//
//  //TCP Header
//  tcph->source = src_sin.sin_port;// htons(1234);
//  tcph->dest = dst_sin.sin_port;// htons(80);
//  tcph->seq = 0;
//  tcph->ack_seq = 0;
//  tcph->doff = 5;    //tcp header size
//  tcph->fin = 0;
//  tcph->syn = 1;
//  tcph->rst = 0;
//  tcph->psh = 0;
//  tcph->ack = 0;
//  tcph->urg = 0;
//  tcph->window = htons(5840); /* maximum allowed window size */
//  tcph->check = 0;    //leave checksum 0 now, filled later by pseudo header
//  tcph->urg_ptr = 0;
//
//  //Now the TCP checksum
//  psh.source_address = src_sin.sin_addr.s_addr;// inet_addr(source_ip);
//  psh.dest_address = dst_sin.sin_addr.s_addr;
//  psh.placeholder = 0;
//  psh.protocol = IPPROTO_TCP;
//  psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data));
//
//  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
//  pseudogram = malloc(psize);
//
//  memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
//  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));
//
//  tcph->check = csum((unsigned short*) pseudogram, psize);



  //loop if you want to flood :)
  while ( 1 ) {

    sleep(1);

    struct iphdr *iph = (struct iphdr *) datagram;
    struct sockaddr_in dst_sin;

    //zero out the packet buffer
    so_sockaddr_in("127.0.0.1", 6001, &dst_sin );

    CF_DEBUG("\n\ndatagram: %u bytes", ntohs(iph->tot_len));
    dumppkt(datagram, ntohs(iph->tot_len));
    CF_DEBUG("\n");

    //Send the packet
    if ( sendto(s, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *) &dst_sin, sizeof(dst_sin)) < 0 ) {
      perror("sendto failed");
    }
    //Data send successfully
    else {
      printf("Packet Sent. Length : %d \n", iph->tot_len);

      struct sockaddr_in sin2;
      socklen_t sin2len = sizeof(sin2);
      uint8_t buf[4096];
      ssize_t cb;

      while ( (cb = recvfrom(s, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr*) &sin2, &sin2len)) > 0 ) {
        CF_DEBUG("\n\nrecvfrom: %s:%u %zd bytes", inet_ntoa(sin2.sin_addr), ntohs(sin2.sin_port), cb);
        dumppkt(buf, cb);
      }
    }
  }

  return 0;
}

//Complete


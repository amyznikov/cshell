/*
 * cshell-client.c
 *  Created on: Feb 4, 2018
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "sockopt.h"
#include "debug.h"


#ifndef CSHELL_VERSION
# define CSHELL_VERSION "0.0.0"
#endif

static const char VERSION[] = CSHELL_VERSION;








/**************************************************************************
 * create_tunnel()
 * allocates or reconnects to a tun device.
 *
 *  node : "/dev/net/tun"
 **************************************************************************/
static int open_tunnel_device(const char * node, char iface[IFNAMSIZ], int flags)
{
  struct ifreq ifr;
  int fd;

  if ( (fd = open(node, O_RDWR)) < 0 ) {
    CF_FATAL("open(%s) fauls: %s", node, strerror(errno));
    return -1;
  }


  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = flags;
  if ( iface && *iface ) {
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));
  }


  if ( ioctl(fd, TUNSETIFF, &ifr) == -1 ) {
    CF_FATAL("ioctl(fd=%d, TUNSETIFF) fails: %s", fd, strerror(errno));
    close(fd), fd = -1;
  }
  else if ( iface ) {
    strncpy(iface, ifr.ifr_name, IFNAMSIZ);
  }

  return fd;
}

// mask: "255.255.255.0"
static bool set_tunnel_ip(const char * iface, const char * addrs, const char * mask)
{
  struct ifreq ifr;
  int so = -1;
  bool fOk = false;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

  if ( (so = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ) {
    CF_FATAL("socket(AF_INET, SOCK_DGRAM, 0) fails: %s", strerror(errno));
    goto __end;
  }



  if ( addrs ) {

    struct sockaddr_in * sin = &ifr.ifr_addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, addrs, &sin->sin_addr);


    if ( ioctl(so, SIOCSIFADDR, &ifr) == -1 ) {
      CF_FATAL("ioctl(so=%d, SIOCSIFADDR, '%s') fails: %s", so, addrs, strerror(errno));
      goto __end;
    }
  }




  if ( mask ) {

    struct sockaddr_in * sin = &ifr.ifr_netmask;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, mask, &sin->sin_addr);

    if ( ioctl(so, SIOCSIFNETMASK, &ifr) == -1 ) {
      CF_FATAL("ioctl(so=%d, SIOCSIFNETMASK, '%s') fails: %s", so, mask, strerror(errno));
      goto __end;
    }
  }



  fOk = true;

__end:

  if ( so != -1 ) {
    close(so);
  }

  return fOk;
}


// IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP
static bool set_tunnel_flags(const char * iface, int flags)
{
  struct ifreq ifr;
  int so = -1;
  bool fOk = false;

  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name));

  if ( (so = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ) {
    CF_FATAL("socket(AF_INET, SOCK_DGRAM, 0) fails: %s", strerror(errno));
    goto __end;
  }

  ifr.ifr_flags = flags;
  if ( ioctl(so, SIOCSIFFLAGS, &ifr) == -1 ) {
    CF_FATAL("ioctl(so=%d, SIOCSIFFLAGS) fails: %s", so, strerror(errno));
    goto __end;
  }

  fOk = true;

  __end :
  if ( so != -1 ) {
    close(so);
  }

  return fOk;
}


///////////////////////////////////////////////////////////////////////////////////

static inline bool epoll_add(int epollfd, int so, uint32_t events)
{
  int status = epoll_ctl(epollfd, EPOLL_CTL_ADD, so,
      &(struct epoll_event ) {
            .data.fd = so,
            .events = (events | ((events & EPOLLONESHOT) ? 0 : EPOLLET))
          });

  return status == 0;
}


static inline bool epoll_remove(int epollfd, int so)
{
  return epoll_ctl(epollfd, EPOLL_CTL_DEL, so, NULL) == 0;
}


static ssize_t read_n(int so, void * buf, ssize_t n)
{
  ssize_t cb, left = n;

  while ( left > 0 ) {

    if ( (cb = read(so, buf, left)) < 0 ) {
      CF_FATAL("read(so=%d) fails: %s", so, strerror(errno));
      return -1;
    }

    if ( cb == 0 ) {
      CF_FATAL("Unexpected EOF while reading from so=%d. %s", so, strerror(errno));
      return 0;
    }

    left -= cb;
    buf += cb;
  }

  return n;
}


/////////////////////////////////////////////////////////////////////////////


static int tcp_listen(const char * addrs, uint16_t port)
{
  bool fOk = false;
  struct sockaddr_in sin;
  int so = -1;

  if ((so = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1 ) {
    CF_FATAL("socket() fails: %d", strerror(errno));
    goto __end;
  }

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  inet_pton(AF_INET, addrs, &sin.sin_addr);
  sin.sin_port = htons(port);

  if ( !so_set_reuse_addrs(so, true) ) {
    CF_WARNING("so_set_reuse_addrs() fails: %d", strerror(errno));
  }

  if ( bind(so, &sin, sizeof(sin)) == -1 ) {
    CF_FATAL("socket() fails: %d", strerror(errno));
    goto __end;
  }

  if ( listen(so, SOMAXCONN) == -1 ) {
    CF_FATAL("listen() fails: %d", strerror(errno));
    goto __end;
  }

  fOk = true;

__end:

  if ( !fOk ) {
    if ( so != -1 ) {
      close(so), so = -1;
    }
  }

  return so;
}



/////////////////////////////////////////////////////////////////////////////

static const char * protoname(int protocol_id)
{
  switch ( protocol_id ) {
  case IPPROTO_ICMP :
    return "ICMP";
  case IPPROTO_TCP :
    return "TCP";
  case IPPROTO_UDP :
    return "UDP";
  default :
    return "OTHER";
  }
}


static void handle_packet_from_tunnel_4(struct ip * pkt)
{
  void * pld = NULL;
  CF_DEBUG("IP4: PROTOCOL: %s (%d)\n", protoname(pkt->ip_p), pkt->ip_p);
  CF_DEBUG("IP4: HEADER LENGTH: %u, sizeof(ip)=%zu\n", pkt->ip_hl * 4, sizeof(struct ip));
  CF_DEBUG("IP4: TYPE OF SERVICE: 0x%x\n", pkt->ip_tos);
//  CF_DEBUG("IP4: Identification: 0x%x\n", ntohs(pkt->ip_id));
//  CF_DEBUG("IP4: Fragment offset: 0x%x\n", ntohs(pkt->ip_off));
  CF_DEBUG("IP4: TTL: %d\n", pkt->ip_ttl);

  CF_DEBUG("IP4: SRC: %s\n", inet_ntoa(pkt->ip_src));
  CF_DEBUG("IP4: DST: %s\n", inet_ntoa(pkt->ip_dst));
  CF_DEBUG("IP4: HDR CHECKSUM: %u\n", ntohs(pkt->ip_sum));
  CF_DEBUG("IP4: packet length (both data and header): %u\n", htons(pkt->ip_len));

  pld = pkt + pkt->ip_hl * 4;

  switch(pkt->ip_p) {
    case IPPROTO_TCP: {
      const struct tcphdr * tcp = pld;
      CF_DEBUG("TCP4: src port = %u", ntohs(tcp->source));
      CF_DEBUG("TCP4: dst port = %u", ntohs(tcp->dest));
      CF_DEBUG("TCP4: seq = %u", ntohl(tcp->seq));
      CF_DEBUG("TCP4: ack_seq = %u", ntohl(tcp->ack_seq));
      break;
    }

    case IPPROTO_UDP: {
      const struct udphdr * udp = pld;
      CF_DEBUG("UDP4:");
      break;
    }

    case IPPROTO_ICMP: {
      const struct icmphdr * icmp = pld;
      CF_DEBUG("ICMP4:");
      break;
    }
  }

}

static void handle_packet_from_tunnel_6(struct ip6_hdr * pkt)
{
  void * pld = NULL;
}

static void handle_packet_from_tunnel(uint8_t pktbuf[], size_t size)
{
  CF_DEBUG("---------------------------------------------------");
  CF_DEBUG("IP: size=%zu", size);
  CF_DEBUG("IP: VERSION: 0x%0X\n", ((struct ip * )pktbuf)->ip_v);

  switch (((struct ip * )pktbuf)->ip_v) {
  case 4:
    handle_packet_from_tunnel_4((struct ip *) pktbuf);
    break;

  case 6:
    handle_packet_from_tunnel_6((struct ip6_hdr *) pktbuf);
    break;
  }
}


static void process_tunnel_packets(int tunfd)
{
  static const int MAX_EPOLL_EVENTS = 100;

  struct epoll_event events[MAX_EPOLL_EVENTS];
  struct epoll_event * e;
  int epollfd = -1;

  int i, n;
  ssize_t cb;
  bool fail = false;

  int so_tcpsrv = -1;


  /* create epoll listener */
  if ( (epollfd = epoll_create1(0)) == -1 ) {
    CF_FATAL("epoll_create1() fails: %s", strerror(errno));
    goto __end;
  }


  /* manage tunfd to listen input packets */
  if ( !epoll_add(epollfd, tunfd, EPOLLIN) ) {
    CF_FATAL("epoll_(epollfd=%d, tunfd=%d) fails: %s", epollfd, tunfd, strerror(errno));
    goto __end;
  }


  if ( (so_tcpsrv = tcp_listen("127.0.0.1", 6444)) ) {
    CF_FATAL("tcp_listen() fails: %s", strerror(errno));
    goto __end;
  }


  // fixme: may be ignore errno == EINTR ?
  while ( (n = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1)) >= 0 && !fail ) {

    for ( i = 0; i < n ; ++i ) {

      e = &events[i];

      if ( e->data.fd == tunfd ) {

        if ( e->events & EPOLLIN ) {

          const size_t MAX_PKT_SIZE = 2 * 1024; // MUST BE >= MAX POSSIBLE MTU

          uint8_t pkt[MAX_PKT_SIZE];

          // data from tun device
          // fixme: read and write to network socket

          if ( (cb = read(tunfd, pkt, sizeof(pkt))) < 0 ) {
            CF_FATAL("read(pkt) from tunfd=%d fails: %s", tunfd, strerror(errno));
            fail = true;
            break;
          }

          handle_packet_from_tunnel(pkt, cb);
        }
      }
      else if ( e->data.fd == so_tcpsrv ) {
        if ( e->events & EPOLLIN ) {

          CF_DEBUG("new TCP connection requested");

          int so = accept(so_tcpsrv, NULL, 0);

          if ( so == -1 ) {
            CF_FATAL("accept fails: %s", strerror(errno));
          }
          else {
            CF_FATAL("accepted OK");
            close(so);
          }
        }
      }
    }
  }

__end:

  if ( epollfd != -1 ) {
    close(epollfd);
  }
}



int main(int argc, char *argv[])
{

  static const char node[] = "/dev/net/tun";
  char iface[256] = ""; /* network interface name, will auto generated */
  int tunfd = -1;





  /* configurable flag for background / foreground mode */
  bool daemon_mode = true;




  /* ip address assigned to tun interface */
  char ifaceip[IFNAMSIZ] = "";
  char ifacemask[IFNAMSIZ] = "255.255.255.0";
  int ifaceflags = IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP;

  int i;



  /* parse command line */
  for ( i = 1; i < argc; ++i ) {

    //////////////////////////////////////////////////////////////////////////////////////////////
    if ( strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0 ) {
      printf("cshell-client %s\n\n", VERSION);
      printf("USAGE\n");
      printf("  cshell-client [OPTIONS]\n\n");
      printf("OPTIONS:\n");
      printf(" --no-daemon, -n\n");
      printf("      don't fork, run in foreground mode\n");
      printf(" --ip IPv4\n");
      printf("      temporary debug test to assing IP address for tun dev\n");
      printf(" --iface <iface-name>\n");
      printf("      temporary debug test to assing IP address for tun dev\n");
      return 0;
    }


    //////////////////////////////////////////////////////////////////////////////////////////////
    if ( strcmp(argv[i], "--no-daemon") == 0 || strcmp(argv[i], "-n") == 0 ) {
      daemon_mode = false;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--ip") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }
      strncpy(ifaceip, argv[i], sizeof(ifaceip));
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--iface") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }
      strncpy(iface, argv[i], sizeof(iface));
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else {
      fprintf(stderr, "Invalid argument %s\n", argv[i]);
      return 1;
    }
  }






  /* fork() and become daemon */
  if ( daemon_mode ) {

    pid_t pid;

    switch ( (pid = fork()) ) {

    case -1 :
      fprintf(stderr, "fork() fails: %s", strerror(errno));
      return 1;

    case 0 :
      // in child, continue initialization
      break;

    default :
      // parrent, fnish
      fprintf(stderr, "switched to background mode: pid=%d\n", pid);
      return 0;
    }
  }




  /* setup debug stuff */
  if ( daemon_mode ) {
    cf_set_logfilename("cshell-client.log");
  }
  else {
    cf_set_logfilename("stderr");
  }

  cf_set_loglevel(CF_LOG_DEBUG);





  /* open tunnel device */
  if ( (tunfd = open_tunnel_device(node, iface, IFF_TUN | IFF_NO_PI)) < 0 ) {
    CF_FATAL("create_tunnel('%s') fails: %s", node, strerror(errno));
    return 1;
  }




  /* assign IP to tun interface */
  if ( *ifaceip && !set_tunnel_ip(iface, ifaceip, ifacemask) ) {
    CF_FATAL("set_tunnel_ip(iface=%s, ip=%s, mask=%s) fails: %s", iface, ifaceip, ifacemask, strerror(errno));
    return 1;
  }


  /* activate interface */
  if ( !set_tunnel_flags(iface, ifaceflags) ) {
    CF_FATAL("set_tunnel_flags(iface=%s, ifaceflags=0x%0X) fails: %s", iface, ifaceflags, strerror(errno));
    return 1;
  }


  /* run event loop */
  //process_tunnel_packets(tunfd);

  {
    int listen_so = tcp_listen(ifaceip, 6444);
    if ( listen_so == -1 ) {
      CF_FATAL("tcp_listen() fails");
      return 1;
    }

    CF_DEBUG("Listen started!!!!");
    int so = accept(listen_so, NULL, 0);

    CF_DEBUG("Accepted NEW TCP connection");

    char buf[4*1024] = "";

    ssize_t cb = recv(so, buf, sizeof(buf)-1, 0);

    printf("%s\n", buf);




    close(so);



  }




  return 0;
}

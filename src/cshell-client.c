/*
 * cshell-client.c
 *  Created on: Feb 4, 2018
 *
 *  http://www.binarytides.com/raw-sockets-c-code-linux/
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

#include <pthread.h>

#include "sockopt.h"
#include "checksum.h"
#include "ccarray.h"
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

    struct sockaddr_in * sin = (struct sockaddr_in *)&ifr.ifr_addr;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    inet_pton(AF_INET, addrs, &sin->sin_addr);


    if ( ioctl(so, SIOCSIFADDR, &ifr) == -1 ) {
      CF_FATAL("ioctl(so=%d, SIOCSIFADDR, '%s') fails: %s", so, addrs, strerror(errno));
      goto __end;
    }
  }




  if ( mask ) {

    struct sockaddr_in * sin = (struct sockaddr_in *)&ifr.ifr_netmask;
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
            .events = events // (events | ((events & EPOLLONESHOT) ? 0 : EPOLLET))
          });

  return status == 0;
}


static inline bool epoll_remove(int epollfd, int so)
{
  return epoll_ctl(epollfd, EPOLL_CTL_DEL, so, NULL) == 0;
}

/////////////////////////////////////////////////////////////////////////////

static char g_bindaddrs[256];
struct sockaddr_in g_tcpserver_address;

struct sockaddr_in g_master_server_address;



static void * microsrv_client_thread(void * arg)
{
  int so1 = (int)(ssize_t)(arg);
  int so2 = -1;

  CF_DEBUG("Try to connect to smaster %s:%u", inet_ntoa(g_master_server_address.sin_addr), ntohs(g_master_server_address.sin_port));

  if ( (so2 = so_tcp_connect(&g_master_server_address)) == -1 ) {
    CF_FATAL("so_tcp_connect() fails: %s", strerror(errno));

    char buf[4096] = "";
    ssize_t cb1, cb2;
    recv(so1, buf, sizeof(buf) - 1, MSG_DONTWAIT);

    char msg[1024] = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=ISO-8859-1\r\n"
        "\r\n"
        "<HTML> Can not connect master server</HTML>\r\n";

    send(so1, msg, strlen(msg), 0);
    close (so1);
  }
  else {


    static const int MAX_EPOLL_EVENTS = 100;
    struct epoll_event events[MAX_EPOLL_EVENTS];
    struct epoll_event * e;
    int epollfd = -1;
    bool fail = false;

    char buf[4096] = "";
    ssize_t cb1, cb2;
    int i, n;


    /* create epoll listener */
    if ( (epollfd = epoll_create1(0)) == -1 ) {
      CF_FATAL("epoll_create1() fails: %s", strerror(errno));
    }


    /* manage so to listen input packets */
    if ( !epoll_add(epollfd, so1, EPOLLIN) ) {
      CF_FATAL("epoll_(epollfd=%d, so1=%d) fails: %s", epollfd, so1, strerror(errno));
    }
    if ( !epoll_add(epollfd, so2, EPOLLIN) ) {
      CF_FATAL("epoll_(epollfd=%d, so2=%d) fails: %s", epollfd, so2, strerror(errno));
    }


    CF_DEBUG("so1 = %d", so1);
    CF_DEBUG("so2 = %d", so2);

    while ( (n = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1)) >= 0 && !fail ) {

      CF_DEBUG("epoll: n=%d", n);

      for ( i = 0; i < n; ++i ) {

        e = &events[i];

        CF_DEBUG("epoll: events[i=%d] = 0x%0X fd=%d", i, e->events, e->data.fd);

        if ( e->events & EPOLLIN ) {

          if ( e->data.fd == so1 ) {
            if ( (cb1 = recv(so1, buf, sizeof(buf), 0)) <= 0 ) {
              CF_FATAL("recv(so1) fails: %s", strerror(errno));
              fail = true;
              break;
            }

            if ( (cb2 = send(so2, buf, cb1, 0)) != cb1 ) {
              CF_FATAL("send(so2) fails: %s", strerror(errno));
              fail = true;
              break;
            }
          }
          else if ( e->data.fd == so2 ) {
            if ( (cb2 = recv(so2, buf, sizeof(buf), 0)) <= 0 ) {
              CF_FATAL("recv(so2) fails: %s", strerror(errno));
              fail = true;
              break;
            }

            if ( (cb1 = send(so1, buf, cb2, 0)) != cb2 ) {
              CF_FATAL("send(so1) fails: %s", strerror(errno));
              fail = true;
              break;
            }
          }
        }
      }
    }

    CF_DEBUG("\n==========================\n");
    close(so1);
    close(so2);
    close(epollfd);
    CF_DEBUG("CONNECTIONS CLOSED");
    CF_DEBUG("\n==========================\n");
  }


  pthread_detach(pthread_self());
  return NULL;
}

static void * mircosrv_thread(void * arg)
{
  struct sockaddr_in addrsfrom;
  socklen_t addrslen = sizeof(addrsfrom);

  int so1, so2;
  int status;

  pthread_detach(pthread_self());

  if ( (so1 = so_tcp_listen(g_bindaddrs, 6001, &g_tcpserver_address)) == -1 ) { // 10.10.100.1
    CF_FATAL("tcp_listen() fails");
    return NULL;
  }

  while ( (so2 = accept(so1, &addrsfrom, &addrslen)) != -1 ) {

    CF_CRITICAL("ACCEPTED FROM %s:%u", inet_ntoa(addrsfrom.sin_addr), ntohs(addrsfrom.sin_port));

    pthread_t pid;
    status = pthread_create(&pid, NULL, microsrv_client_thread, (void*)(ssize_t)(so2));
    if ( status ) {
      CF_FATAL("pthread_create() fails: %s", strerror(status));
    }
  }

  CF_CRITICAL("accept() fails!");

  return NULL;
}




static bool start_mircosrv_thread(const char * bindaddrs)
{
  pthread_t pid;
  int status;

  strcpy(g_bindaddrs, bindaddrs);

  status = pthread_create(&pid, NULL, mircosrv_thread, NULL);
  if ( status ) {
    CF_FATAL("pthread_create() fauls: %s", strerror(status));
  }

  return status == 0;
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


///////////////////

struct rtable_item {
  struct sockaddr_in src, dst, resp;
};
static ccarray_t rtable; /* <struct rtable_item> */

static ssize_t rtable_find_resp(struct in_addr respaddr, in_port_t respport)
{
  size_t i, n;
  for ( i = 0, n = ccarray_size(&rtable); i < n; ++i ) {
    struct rtable_item * item = ccarray_peek(&rtable, i);
    if ( item->resp.sin_addr.s_addr == respaddr.s_addr && item->resp.sin_port == respport ) {
      return i;
    }
  }
  return -1;
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

//    CF_WARNING("RTABLE Added src %s:%u", inet_ntoa(src.sin_addr), ntohs(src.sin_port));
//    CF_WARNING("RTABLE Added dst %s:%u", inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
//    CF_WARNING("RTABLE Added resp %s:%u", inet_ntoa(resp.sin_addr), ntohs(resp.sin_port));
  }
  else {
    struct rtable_item * item = ccarray_peek(&rtable, pos);
//    CF_WARNING("rtable_find_resp() already exists for %s:%u", inet_ntoa(src.sin_addr), ntohs(src.sin_port));
//    CF_WARNING("Update src to %s:%u", inet_ntoa(src.sin_addr), ntohs(src.sin_port));
//    CF_WARNING("Update dst to %s:%u", inet_ntoa(dst.sin_addr), ntohs(dst.sin_port));
    item->src = src;
    item->dst = dst;
  }
}

///////////////////


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

static void dumppkt2(const char * prefix,
    const struct ip * ip,
    size_t iphsize,
    const struct tcphdr * tcp,
    size_t tcphsize,
    void * tcppld,
    size_t pldsize)
{
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

/* read from tunnel, update destination and send to raw socket */
static ssize_t rdtun(int tunfd)
{
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

  if ( (pktsize = read(tunfd, pktbuf, sizeof(pktbuf))) < 0 ) {
    CF_FATAL("read(srcfd=%d) fails: %s", tunfd, strerror(errno));
    return -1;
  }

//  CF_DEBUG("\n\n-----------------------------\n"
//      "srcfd=%d dstfd=%d pktsize=%zu",
//      tunfd, rawfd, pktsize);

  if ( !parsepkt(pktbuf, pktsize, &ip, &iphsize, &tcp, &tcphsize, &tcppld, &pldsize) ) {
    CF_NOTICE("PKT not parsed\n");
    return 0;
  }

  if ( !tcp ) {
    // CF_NOTICE("Not a TCP\n");
    return 0;
  }

  //dumppkt2("R", ip, iphsize, tcp, tcphsize, tcppld, pldsize);

  if ( ip->ip_src.s_addr == g_tcpserver_address.sin_addr.s_addr && tcp->source == g_tcpserver_address.sin_port ) {

    //CF_NOTICE("Reply FROM internal server");

    ssize_t pos = rtable_find_resp(ip->ip_dst, tcp->dest);
    if ( pos < 0 ) {
      //CF_FATAL("rtable_find_dest() fails for dst=%s:%u", inet_ntoa(ip->ip_dst), ntohs(tcp->dest));
    }
    else {
      const struct rtable_item * item = ccarray_peek(&rtable, pos);
      //CF_DEBUG("item found!");

      ip->ip_src.s_addr = item->dst.sin_addr.s_addr;
      tcp->source = item->dst.sin_port;
      ip->ip_dst.s_addr = item->src.sin_addr.s_addr;
      tcp->dest = item->src.sin_port;
    }
  }
  else {

    //CF_NOTICE("Redirect TO internal server");

    struct in_addr resp_addrs = {ip->ip_dst.s_addr};
    in_port_t resp_port = tcp->source;

    rtable_add_route(ip->ip_src, tcp->source, ip->ip_dst, tcp->dest, resp_addrs, resp_port);

    ip->ip_src.s_addr = ip->ip_dst.s_addr;
    // tcp->source = tcp->dest;

    ip->ip_dst.s_addr = g_tcpserver_address.sin_addr.s_addr;
    tcp->dest = g_tcpserver_address.sin_port;
  }


  update_ip_checksum(ip);
  update_tcp_checksum(ip);

  // dumppkt2("W", ip, iphsize, tcp, tcphsize, tcppld, pldsize);

  cb = write(tunfd, ip, ntohs(ip->ip_len));
  if ( cb <= 0 ) {
    CF_FATAL("write(tunfd) fails: %s", strerror(errno));
  }

  CF_DEBUG("\n");

  return cb;
}





static void process_tunnel_packets(int tunfd1)
{
  static const int MAX_EPOLL_EVENTS = 100;

  struct epoll_event events[MAX_EPOLL_EVENTS];
  struct epoll_event * e;
  int epollfd = -1;

  //int rawfd = -1;

  int i, n;
  bool fail = false;


  /* create epoll listener */
  if ( (epollfd = epoll_create1(0)) == -1 ) {
    CF_FATAL("epoll_create1() fails: %s", strerror(errno));
    goto __end;
  }


  /* manage tunfd to listen input packets */
  if ( !epoll_add(epollfd, tunfd1, EPOLLIN) ) {
    CF_FATAL("epoll_(epollfd=%d, tunfd=%d) fails: %s", epollfd, tunfd1, strerror(errno));
    goto __end;
  }

  // fixme: may be ignore errno == EINTR ?
  while ( (n = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1)) >= 0 && !fail ) {

    for ( i = 0; i < n ; ++i ) {

      e = &events[i];

      if ( e->data.fd == tunfd1 ) {
        if ( e->events & EPOLLIN ) {
          rdtun(tunfd1);
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
  char iface1[256] = ""; /* network interface name, will auto generated */
  int tunfd1 = -1;

//  char iface2[256] = ""; /* network interface name, will auto generated */
//  int tunfd2 = -1;

//  int tcpfd = -1;
  char tbind[256] = "10.10.100.1";



  /* configurable flag for background / foreground mode */
  bool daemon_mode = true;


  /* ip address assigned to tun interface */
  char ifaceip1[IFNAMSIZ] = "";
  char ifacemask1[IFNAMSIZ] = "255.255.255.0";
  int ifaceflags1 = IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP;// | IFF_POINTOPOINT;// | IFF_MULTICAST | IFF_NOARP;

//  char ifaceip2[IFNAMSIZ] = "";
//  char ifacemask2[IFNAMSIZ] = "255.255.255.0";
//  int ifaceflags2 = IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP;// | IFF_POINTOPOINT; // | IFF_MULTICAST | IFF_NOARP;

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
      printf(" --ip1 IPv4\n");
      printf("      temporary debug test to assing IP address for tun dev\n");
      printf(" --ip2 IPv4\n");
      printf("      temporary debug test to assing IP address for tun dev\n");
      printf(" --iface1 <iface-name 1>\n");
      printf("      temporary debug test to assing IP address for tun dev\n");
      printf(" --iface2 <iface-name 2>\n");
      printf("      temporary debug test to assing IP address for tun dev\n");
      return 0;
    }


    //////////////////////////////////////////////////////////////////////////////////////////////
    if ( strcmp(argv[i], "--no-daemon") == 0 || strcmp(argv[i], "-n") == 0 ) {
      daemon_mode = false;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--ip1") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }
      strncpy(ifaceip1, argv[i], sizeof(ifaceip1));
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--smaster") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }

      char saddrs[256] = "";
      uint16_t port = 6010;

      if ( sscanf(argv[i], "%255[^:]:%hu", saddrs, &port) < 1 ) {
        fprintf(stderr, "Invalid argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }

      so_sockaddr_in(saddrs, port, &g_master_server_address);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--iface1") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }
      strncpy(iface1, argv[i], sizeof(iface1));
    }

//    else if ( strcmp(argv[i], "--iface2") == 0 ) {
//      if ( ++i >= argc ) {
//        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
//      }
//      strncpy(iface2, argv[i], sizeof(iface1));
//    }

    else if ( strcmp(argv[i], "--tbind") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }
      strncpy(tbind, argv[i], sizeof(tbind));
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


  ccarray_init(&rtable, 1024, sizeof(struct rtable_item));



  /* open tunnel device */
  if ( (tunfd1 = open_tunnel_device(node, iface1, IFF_TUN | IFF_NO_PI)) < 0 ) {
    CF_FATAL("create_tunnel('%s') fails: %s", node, strerror(errno));
    return 1;
  }
  /* assign IP to tun interface */
  if ( *ifaceip1 && !set_tunnel_ip(iface1, ifaceip1, ifacemask1) ) {
    CF_FATAL("set_tunnel_ip(iface=%s, ip=%s, mask=%s) fails: %s", iface1, ifaceip1, ifacemask1, strerror(errno));
    return 1;
  }
  /* activate interface */
  if ( !set_tunnel_flags(iface1, ifaceflags1) ) {
    CF_FATAL("set_tunnel_flags(iface=%s, ifaceflags=0x%0X) fails: %s", iface1, ifaceflags1, strerror(errno));
    return 1;
  }


  start_mircosrv_thread(tbind);
  sleep(1);

  CF_DEBUG("iface1='%s'", iface1);
  CF_DEBUG("listening %s:%u", inet_ntoa(g_tcpserver_address.sin_addr), ntohs(g_tcpserver_address.sin_port));


  /* run event loop */
  process_tunnel_packets(tunfd1);



  return 0;
}


#if 0
//
//  {
//    int listen_so = tcp_listen(ifaceip, 6444);
//    if ( listen_so == -1 ) {
//      CF_FATAL("tcp_listen() fails");
//      return 1;
//    }
//
//    CF_DEBUG("Listen started!!!!");
//
//    struct sockaddr_in address_from;
//    socklen_t address_from_len = sizeof(address_from);
//    int so;
//
//
//    while ( (so = accept(listen_so, &address_from, &address_from_len) ) != -1 ) {
//      CF_DEBUG("Accepted NEW TCP connection from: %s:%u", inet_ntoa(address_from.sin_addr), ntohs(address_from.sin_port));
//
//      char buf[4*1024] = "";
//
//      ssize_t cb = recv(so, buf, sizeof(buf)-1, 0);
//
//      printf("%s\n", buf);
//      // close(so);
//    }
//
//  }

static int tunnel(int srcfd, int dstfd, const struct sockaddr_in * tcpdst, int rawfd)
{
  const size_t MAX_PKT_SIZE = 4 * 1024;    // MUST BE >= MAX POSSIBLE MTU
  uint32_t pktbuf[MAX_PKT_SIZE / sizeof(uint32_t)];
  struct ip * pkt;
  struct tcphdr * tcp;
  char * tcppld;
  size_t doff;
  ssize_t cb;
  ssize_t pos;
  size_t pktsize;

  if ( (cb = read(srcfd, pktbuf, sizeof(pktbuf))) < 0 ) {
    CF_FATAL("read(srcfd=%d) fails: %s", srcfd, strerror(errno));
    return -1;
  }


  pkt = (struct ip *) pktbuf;
  if ( pkt->ip_v != 4 ) {
    //CF_DEBUG("IPv6 pkt, ignored");
    return 0;
  }

  if ( pkt->ip_p != IPPROTO_TCP ) {
    CF_DEBUG("Not a TCP, ignored");
    return 0;
  }

  pktsize = ntohs(pkt->ip_len);
  tcp = (struct tcphdr *) (((uint8_t*) pkt) + pkt->ip_hl * 4);
  doff = tcp->doff * 4;
  tcppld = ((uint8_t*) tcp) + doff;

//  if ( (pos = rtable_find_addrs(pkt->ip_src, tcp->source, pkt->ip_dst, tcp->dest)) < 0 ) {
//    rtable_add_route(pkt->ip_src, tcp->source, pkt->ip_dst, tcp->dest);
//    pos = ccarray_size(&rtable) - 1;
//  }

  CF_DEBUG("\n\nTCPDST= %s:%u", inet_ntoa(tcpdst->sin_addr), ntohs(tcpdst->sin_port));
  CF_DEBUG("srcfd=%d dstfd=%d pktsize=%zu", srcfd, dstfd, pktsize);
  CF_DEBUG("B SRC=%s:%u", inet_ntoa(pkt->ip_src), ntohs(tcp->source));
  CF_DEBUG("B DST=%s:%u", inet_ntoa(pkt->ip_dst), ntohs(tcp->dest));
  CF_DEBUG("B CHK=%u", ntohs(pkt->ip_sum));
  CF_DEBUG("B SYN=%u\n", tcp->syn);

  pkt->ip_dst = tcpdst->sin_addr;
  //tcp->dest = tcpdst->sin_port;
  update_ip_checksum(pkt);

  CF_DEBUG("A SRC=%s:%u", inet_ntoa(pkt->ip_src), ntohs(tcp->source));
  CF_DEBUG("A DST=%s:%u", inet_ntoa(pkt->ip_dst), ntohs(tcp->dest));
  CF_DEBUG("A CHK=%u", ntohs(pkt->ip_sum));
  CF_DEBUG("A SYN=%u", tcp->syn);

  //cb = write(srcfd, pkt, pktsize);
  cb = sendto(rawfd, tcp/*pkt*/, pktsize-pkt->ip_hl * 4, 0, tcpdst, sizeof(*tcpdst));
  if ( cb <= 0 ) {
    CF_FATAL("write(tunfd) fails: %s", strerror(errno));
  }

  //handle_packet_from_tunnel(pkt, cb, tunfd1, tcpdst);

  return cb;
}


//Datagram to represent the packet
static void gendgram(char datagram[4096], const char * source_ip, uint16_t source_port, const char * dest_ip, uint16_t dest_port,
    void * tcpopts, size_t tcpoptssize )
{
  char *data, *pseudogram;
  void * optsptr;

  struct sockaddr_in src_sin;
  struct sockaddr_in dst_sin;

  CF_DEBUG("tcpoptssize=%zu", tcpoptssize);
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

  //zero out the packet buffer
  memset(datagram, 0, 4096);
  so_sockaddr_in(source_ip, source_port, &src_sin);
  so_sockaddr_in(dest_ip, dest_port, &dst_sin );

  //IP header
  struct iphdr *iph = (struct iphdr *) datagram;

  //TCP header
  struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));

  //Data part
  optsptr = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
  data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + tcpoptssize;
  strcpy(data, "");

  //Fill in the IP Header
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + tcpoptssize +  strlen(data));
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
  tcph->seq = 0;
  tcph->ack_seq = 0;
  tcph->doff = 5 + tcpoptssize / 4;    //tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->window = htons(5840); /* maximum allowed window size */
  tcph->check = 0;    //leave checksum 0 now, filled later by pseudo header
  tcph->urg_ptr = 0;

  if ( tcpopts ) {
    memcpy(optsptr, tcpopts, tcpoptssize);
  }

  //Now the TCP checksum
  update_tcp_checksum((struct ip *) datagram);

//  struct pseudo_header psh;
//  psh.source_address = src_sin.sin_addr.s_addr;// inet_addr(source_ip);
//  psh.dest_address = dst_sin.sin_addr.s_addr;
//  psh.placeholder = 0;
//  psh.protocol = IPPROTO_TCP;
//  psh.tcp_length = htons(sizeof(struct tcphdr) + tcpoptssize + strlen(data));
//  CF_DEBUG("psh.tcp_length=%u", ntohs(psh.tcp_length));
//
//  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + tcpoptssize + strlen(data);
//  pseudogram = malloc(psize);
//  CF_DEBUG("psize=%d", psize);
//
//  memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
//  memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + tcpoptssize + strlen(data));
//  tcph->check = tcp_checksum(pseudogram, psize);

  CF_DEBUG("tcph->check=%u", tcph->check);
}



#endif

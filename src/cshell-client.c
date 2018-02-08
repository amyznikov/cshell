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
//#include <fcntl.h>
//#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
//#include <linux/if.h>
//#include <linux/if_tun.h>
//#include <netinet/in.h>


#include "pthread_wait.h"
#include "sockopt.h"
#include "tunnel.h"
#include "checksum.h"
#include "ip-pkt.h"
#include "epoll-ctl.h"
#include "so-msg.h"
#include "ccarray.h"
#include "debug.h"


#ifndef CSHELL_VERSION
# define CSHELL_VERSION "0.0.0"
#endif

static const char VERSION[] = CSHELL_VERSION;

// global socket of master server connection
static int smaster_so = -1;



///////////////////////////////////////////////////////////////////////////////////

//struct sockaddr_in g_master_server_address;

static int master_authenticate(const char * master_server_ip, uint16_t master_server_port,
    const char * client_id, /* out */
    /* out */ char tunip[16])
{
  int so = -1;
  bool fOk = false;

  * tunip = 0;

  if ( (so = so_tcp_connect2(master_server_ip, master_server_port)) == -1 ) {
    CF_FATAL("so_tcp_connect2(%s:%u) fails: %s", master_server_ip, master_server_port,
        strerror(errno));
    goto __end;
  }


  /* proto: client must send his ID in first message line */
  if ( so_sprintf(so, "%s\n", client_id) < 1 ) {
    CF_FATAL("so_sprintf(so=%d, client_id='%s') fails: %s", so, client_id, strerror(errno));
    goto __end;
  }


  /* proto: client expect tunip in auth server responce */
  if ( so_recv_line(so, tunip, 16) < 1 ) {
    CF_FATAL("so_recv_line(so=%d, tunip) fails: %s", so, strerror(errno));
    goto __end;
  }


  fOk = true;

__end:

  if ( !fOk ) {
    if ( so != -1 ) {
      so_close(so, false), so = -1;
    }
  }

  return so;
}





///////////////////////////////////////////////////////////////////////////////////

//static char g_bindaddrs[256];
struct sockaddr_in g_microsrv_bind_address;

static void * microsrv_client_thread(void * arg)
{
  int so1 = (int)(ssize_t)(arg);
//  int so2 = -1;

//  CF_DEBUG("Try to connect to smaster %s:%u", inet_ntoa(g_master_server_address.sin_addr), ntohs(g_master_server_address.sin_port));
//
//  if ( (so2 = so_tcp_connect(&g_master_server_address)) == -1 ) {
//    CF_FATAL("so_tcp_connect() fails: %s", strerror(errno));
//
//    char buf[4096] = "";
//    ssize_t cb1, cb2;
//    recv(so1, buf, sizeof(buf) - 1, MSG_DONTWAIT);
//
//    char msg[1024] = "HTTP/1.1 200 OK\r\n"
//        "Content-Type: text/html; charset=ISO-8859-1\r\n"
//        "\r\n"
//        "<HTML> Can not connect master server</HTML>\r\n";
//
//    send(so1, msg, strlen(msg), 0);
//    close (so1);
//  }
//  else {
//
//
//    static const int MAX_EPOLL_EVENTS = 100;
//    struct epoll_event events[MAX_EPOLL_EVENTS];
//    struct epoll_event * e;
//    int epollfd = -1;
//    bool fail = false;
//
//    char buf[4096] = "";
//    ssize_t cb1, cb2;
//    int i, n;
//
//
//    /* create epoll listener */
//    if ( (epollfd = epoll_create1(0)) == -1 ) {
//      CF_FATAL("epoll_create1() fails: %s", strerror(errno));
//    }
//
//
//    /* manage so to listen input packets */
//    if ( !epoll_add(epollfd, so1, EPOLLIN) ) {
//      CF_FATAL("epoll_(epollfd=%d, so1=%d) fails: %s", epollfd, so1, strerror(errno));
//    }
//    if ( !epoll_add(epollfd, so2, EPOLLIN) ) {
//      CF_FATAL("epoll_(epollfd=%d, so2=%d) fails: %s", epollfd, so2, strerror(errno));
//    }
//
//
//    CF_DEBUG("so1 = %d", so1);
//    CF_DEBUG("so2 = %d", so2);
//
//    while ( (n = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1)) >= 0 && !fail ) {
//
//      CF_DEBUG("epoll: n=%d", n);
//
//      for ( i = 0; i < n; ++i ) {
//
//        e = &events[i];
//
//        CF_DEBUG("epoll: events[i=%d] = 0x%0X fd=%d", i, e->events, e->data.fd);
//
//        if ( e->events & EPOLLIN ) {
//
//          if ( e->data.fd == so1 ) {
//            if ( (cb1 = recv(so1, buf, sizeof(buf), 0)) <= 0 ) {
//              CF_FATAL("recv(so1) fails: %s", strerror(errno));
//              fail = true;
//              break;
//            }
//
//            if ( (cb2 = send(so2, buf, cb1, 0)) != cb1 ) {
//              CF_FATAL("send(so2) fails: %s", strerror(errno));
//              fail = true;
//              break;
//            }
//          }
//          else if ( e->data.fd == so2 ) {
//            if ( (cb2 = recv(so2, buf, sizeof(buf), 0)) <= 0 ) {
//              CF_FATAL("recv(so2) fails: %s", strerror(errno));
//              fail = true;
//              break;
//            }
//
//            if ( (cb1 = send(so1, buf, cb2, 0)) != cb2 ) {
//              CF_FATAL("send(so1) fails: %s", strerror(errno));
//              fail = true;
//              break;
//            }
//          }
//        }
//      }
//    }
//
//    CF_DEBUG("\n==========================\n");
//    close(so1);
//    close(so2);
//    close(epollfd);
//    CF_DEBUG("CONNECTIONS CLOSED");
//    CF_DEBUG("\n==========================\n");
//  }

  {

    char buf[4096] = "";
//    ssize_t cb1, cb2;
    recv(so1, buf, sizeof(buf) - 1, MSG_DONTWAIT);

    char msg[1024] = "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=ISO-8859-1\r\n"
        "\r\n"
        "<HTML> DUMMY TEST</HTML>\r\n";

    send(so1, msg, strlen(msg), 0);
  }

  pthread_detach(pthread_self());
  return NULL;
}

static void * mircosrv_thread(void * arg)
{
  pthread_t pid;
  int so1, so2;

  struct sockaddr_in addrsfrom;
  socklen_t addrslen = sizeof(addrsfrom);

  int status;

  pthread_detach(pthread_self());

  so1 = (int) (ssize_t) (arg);

  while ( (so2 = accept(so1, (struct sockaddr*) &addrsfrom, &addrslen)) != -1 ) {

    CF_NOTICE("ACCEPTED FROM %s:%u", inet_ntoa(addrsfrom.sin_addr), ntohs(addrsfrom.sin_port));

    if ( (status = pthread_create(&pid, NULL, microsrv_client_thread, (void*)(ssize_t)(so2))) ) {
      CF_FATAL("pthread_create() fails: %s", strerror(status));
      close(so2);
    }
  }

  CF_CRITICAL("accept() fails!");

  close(so1);

  return NULL;
}

static bool start_mircosrv_thread(const char * bindaddrs)
{
  pthread_t pid;
  int so = -1;
  int status;

  if ( (so = so_tcp_listen(bindaddrs, 6001, &g_microsrv_bind_address)) == -1 ) { // 10.10.100.1
    CF_FATAL("so_tcp_listen(bindaddrs=%s:6001) fails", bindaddrs);
    return false;
  }

  if ( (status = pthread_create(&pid, NULL, mircosrv_thread, (void*) (ssize_t) (so))) ) {
    CF_FATAL("pthread_create() fauls: %s", strerror(status));
    close(so);
    return false;
  }

  return true;
}


/////////////////////////////////////////////////////////////////////////////


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

  //dumppkt("R", ip, iphsize, tcp, tcphsize, tcppld, pldsize);

  if ( ip->ip_src.s_addr == g_microsrv_bind_address.sin_addr.s_addr && tcp->source == g_microsrv_bind_address.sin_port ) {

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

    ip->ip_dst.s_addr = g_microsrv_bind_address.sin_addr.s_addr;
    tcp->dest = g_microsrv_bind_address.sin_port;
  }


  update_ip_checksum(ip);
  update_tcp_checksum(ip);

  // dumppkt("W", ip, iphsize, tcp, tcphsize, tcppld, pldsize);

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

////  int tcpfd = -1;
//  char tbind[256] = "10.10.100.1";



  /* configurable flag for background / foreground mode */
  bool daemon_mode = true;


  // id of this client, must be registered on master server
  char client_id[256] = "";

  /* ip address assigned to tun interface, sent by master server after succesfull authentication */
  char tunip[64] = "";

  /* net mask for tun interface, temporary fixed in this code */
  char ifacemask[IFNAMSIZ] = "255.255.255.0";

  /* flags for tun interface, temporary fixed in this code */
  int ifaceflags = IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP;// | IFF_POINTOPOINT;// | IFF_MULTICAST | IFF_NOARP;

  /* network interface name assigned to tunnel, may be provided by command line or auto generated */
  char tuniface[256] = "";

  /* tun device and file descriptor */
  static const char node[] = "/dev/net/tun";
  int tunfd = -1;


  char master_server_ip[256] = "";
  uint16_t master_server_port = 6010;


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
      printf(" --cid\n");
      printf("      this client id\n");
      printf(" --smaster <ip:port>\n");
      printf("      ip:port of master server\n");
      printf(" --iface <tun-interface-name>\n");
      printf("      optional name of tunnel interface, will auto generated if not specified\n");


      return 0;
    }


    //////////////////////////////////////////////////////////////////////////////////////////////
    if ( strcmp(argv[i], "--no-daemon") == 0 || strcmp(argv[i], "-n") == 0 ) {
      daemon_mode = false;
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--cid") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }
      strncpy(client_id, argv[i], sizeof(client_id) - 1);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--smaster") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }

      if ( sscanf(argv[i], "%255[^:]:%hu", master_server_ip, &master_server_port) < 1 ) {
        fprintf(stderr, "Invalid argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--iface") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }
      strncpy(tuniface, argv[i], sizeof(tuniface) - 1);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else {
      fprintf(stderr, "Invalid argument %s\n", argv[i]);
      return 1;
    }
  }

  cf_set_logfilename("stderr");
  cf_set_loglevel(CF_LOG_DEBUG);



  CF_DEBUG("master_authenticate(master_server=%s:%u, client_id=%s)",
      master_server_ip, master_server_port, client_id);

  smaster_so = master_authenticate(master_server_ip, master_server_port, client_id, tunip);
  if ( smaster_so == -1 ) {
    CF_FATAL("master_authenticate() fails: %s", strerror(errno));
    return 1;
  }




  CF_DEBUG("open_tunnel(node=%s, tuniface=%s, tunip=%s, ifacemask=%s, ifaceflags=0x%0X)",
      node, tuniface, tunip, ifacemask, ifaceflags);

  if ( (tunfd = open_tunnel(node, tuniface, tunip, ifacemask, ifaceflags)) == -1 ) {
    CF_FATAL("open_tunnel(node=%s, tuniface=%s, tunip=%s, ifacemask=%s, ifaceflags=0x%0X) fails: %s",
        node, tuniface, tunip, ifacemask, ifaceflags, strerror(errno));
    so_close(smaster_so, false);
    return 1;
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

    cf_set_logfilename("cshell-client.log");
  }



  ccarray_init(&rtable, 1024, sizeof(struct rtable_item));


  start_mircosrv_thread(tunip);
  sleep(1);

  CF_DEBUG("listening %s:%u", inet_ntoa(g_microsrv_bind_address.sin_addr), ntohs(g_microsrv_bind_address.sin_port));


  /* run event loop */
  process_tunnel_packets(tunfd);


  return 0;
}


#if 0

#endif

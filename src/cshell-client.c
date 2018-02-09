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
#include <sys/socket.h>
#include <arpa/inet.h>

#include <cuttle/pthread_wait.h>
#include <cuttle/sockopt.h>
#include <cuttle/ccarray.h>
#include <cuttle/corpc/server.h>
#include <cuttle/ssl/init-ssl.h>
#include <cuttle/debug.h>


#include "tunnel.h"
#include "checksum.h"
#include "ip-pkt.h"
#include "epoll-ctl.h"
#include "so-msg.h"
#include "smaster.h"


#ifndef CSHELL_VERSION
# define CSHELL_VERSION "0.0.0"
#endif

static const char VERSION[] = CSHELL_VERSION;

static corpc_channel * g_smaster_channel;
static char g_master_server_ip[256] = "";
static uint16_t g_master_server_port = 6010;
static bool g_auth_finished = false;


// id of this client, must be registered on master server
static char g_client_id[256];

/* ip address assigned to tun interface, sent by master server after succesfull authentication */
static char g_tunip[IFNAMSIZ] = "";

/* net mask for tun interface, temporary fixed in this code */
static char g_ifacemask[IFNAMSIZ] = "255.255.255.0";

/* flags for tun interface, temporary fixed in this code */
static int g_ifaceflags = IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP;// | IFF_POINTOPOINT;// | IFF_MULTICAST | IFF_NOARP;

/* network interface name assigned to tunnel, may be provided by command line or auto generated */
static char g_tuniface[256] = "";

/* tun device and file descriptor */
static const char g_node[] = "/dev/net/tun";


struct sockaddr_in g_microsrv_bind_address;


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

static struct rtable_item * rtable_get_resp(struct in_addr respaddr, in_port_t respport)
{
  ssize_t pos = rtable_find_resp(respaddr, respport);
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

/////////////////////////////////////////////////////////////////////////////

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





/////////////////////////////////////////////////////////////////////////////
// SIDE A


static bool get_actual_resource_location(const struct sockaddr_in * addrs,
    /* out */uint64_t * ticket,
    /* out */char actual_resource_location[SM_MAX_ACTUAL_RESOURCE_ADDRESS])
{
  struct resource_request request = {
    .ticket = 0,
    .resource_id = "",
  };

  struct resource_responce responce = {
    .ticket = 0,
    .actual_resource_location = ""
  };

  corpc_stream * st = NULL;
  bool fOk = false;

  st = corpc_open_stream(g_smaster_channel, &(corpc_open_stream_opts ) {
        .service = "smaster",
        .method = "get_resource"
      });

  if ( !st ) {
    CF_FATAL("corpc_open_stream(smaster/get_resource) fails");
    goto __end;
  }


  CF_DEBUG("corpc_stream_write_resource_request(st)");

  sprintf(request.resource_id, "%s:%u", inet_ntoa(addrs->sin_addr), addrs->sin_port);
  if ( !corpc_stream_send_resource_request(st, &request) ) {
    CF_FATAL("corpc_stream_write_resource_request(st) fails");
    goto __end;
  }

  CF_DEBUG("corpc_stream_recv_resource_request(st)");
  if ( !corpc_stream_recv_resource_responce(st, &responce) ) {
    CF_FATAL("corpc_stream_write_resource_request(st) fails");
    goto __end;
  }

  *ticket = responce.ticket;
  strncpy(actual_resource_location, responce.actual_resource_location, SM_MAX_ACTUAL_RESOURCE_ADDRESS);

  if ( responce.ticket == 0 || *responce.actual_resource_location == 0) {
    CF_FATAL("Invalid resource ticket received, requested resource not available");
    goto __end;
  }

  fOk = true;

__end:

  corpc_close_stream(&st);

  return fOk;
}


/////////////////////////////////////////////////////////////////////////////

static void microsrv_client_thread(void * arg)
{
  struct sockaddr_in addrs;
  socklen_t addrssize = sizeof(addrs);

  uint64_t ticket = 0;
  char actual_resource_location[SM_MAX_ACTUAL_RESOURCE_ADDRESS] = "";
  const struct rtable_item * item;

  char buf[1024] = "";

  co_ssl_socket * sslsock2 = NULL;

  int so1 = (int)(ssize_t)(arg);


  getpeername(so1, (struct sockaddr*) &addrs, &addrssize);
  so_set_non_blocking(so1, true);

  CF_NOTICE("ACCEPTED FROM %s:%u", inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port));

  if ( !(item = rtable_get_resp(addrs.sin_addr, addrs.sin_port)) ) {
    sprintf(buf, "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=ISO-8859-1\r\n"
        "\r\n"
        "<HTML><H1>Invalid route detected</H1></HTML>\r\n");
    goto end;
  }


  CF_DEBUG("REQUESTED ROUTE TO %s:%u", inet_ntoa(item->dst.sin_addr), ntohs(item->dst.sin_port));

  if ( !get_actual_resource_location(&addrs, &ticket, actual_resource_location) ) {
    CF_FATAL("get_actual_resource_location() fails");

    sprintf(buf, "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=ISO-8859-1\r\n"
        "\r\n"
        "<HTML><H1>get_actual_resource_location() fails</H1></HTML>\r\n");
    goto end;
  }


  so_sockaddr_in(actual_resource_location, ntohs(addrs.sin_port), &addrs);

  if ( !(sslsock2 = co_ssl_socket_connect_new(&addrs, NULL, SOCK_STREAM, IPPROTO_TCP, 10 * 1000)) ) {
    CF_FATAL("co_ssl_socket_connect_new(%s:%u) fails", inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port));
    sprintf(buf, "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=ISO-8859-1\r\n"
        "\r\n"
        "<HTML><H1>co_ssl_socket_connect_new(%s:%u) fails</H1></HTML>\r\n",
        inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port));
    goto end;
  }



  sprintf(buf, "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=ISO-8859-1\r\n"
      "\r\n"
      "<HTML><H1>get_actual_resource_location() OK</H1></HTML>"
      "<p>ticket=%llu</p>"
      "<p>IP ADDRS=%s</p>"
      "\r\n",
      (unsigned long long)ticket,
      actual_resource_location );


end:

  if ( sslsock2 ) {
    co_ssl_socket_destroy(&sslsock2, false);
  }

  co_send(so1, buf, strlen(buf), 0);
  so_close(so1, false);
}

/////////////////////////////////////////////////////////////////////////////

static int microsrv_accept(void * arg, uint32_t events)
{
  (void)(events);

  int so1 = (int) (ssize_t) (arg);
  int so2;

  while ( (so2 = accept(so1, NULL, NULL)) != -1 ) {

    if ( !co_schedule(microsrv_client_thread, (void*) (ssize_t) (so2), 1024 * 1024) ) {
      CF_FATAL("co_schedule(microsrv_client_thread) fails");
      CF_DEBUG("so_close(so, true)");
      so_close(so2, true);
      CF_DEBUG("R so_close(so, true)");
    }
  }

  return 0;
}


/////////////////////////////////////////////////////////////////////////////

// SIDE B

static void microclient_thread(const char * addrs, uint16_t port)
{
  int so = so_tcp_connect2("127.0.0.1", port);

}


// called by smaster when remote party (side A) requests resource allocation calling get_actual_resource_location()
static void on_smaster_get_resource_requested(corpc_stream * st)
{
  struct resource_request request = {
    .ticket = 0,
    .resource_id = "",
  };

  struct resource_responce responce = {
    .ticket = 0,
    .actual_resource_location = ""
  };

  char tunip[16] = "";
  uint16_t port = 0;

  CF_DEBUG("///////////////////////////////////////////////////////////////////////////");
  CF_DEBUG("ENTER");

  CF_DEBUG("corpc_stream_read_resource_request()");


  /* proto:  smaster sends ticket and tunip:port as resource ID */
  if ( !corpc_stream_recv_resource_request(st, &request) ) {
    CF_FATAL("corpc_stream_read_resource_request() fails");
    goto end;
  }

  if ( request.ticket == 0 ) {
    CF_FATAL("APP BUG: zero ticked received");
    goto end;
  }

  if ( sscanf(request.resource_id, "%15[^:]:%hu", tunip, &port) != 2 ) {
    CF_FATAL("Can't parse requested resource id: '%s'", request.resource_id);
    goto end;
  }

  responce.ticket = request.ticket;
  sprintf(responce.actual_resource_location, "%u", port);

  CF_DEBUG("corpc_stream_send_resource_responce(st)");
  if ( !corpc_stream_send_resource_responce(st, &responce) ) {
    CF_FATAL("corpc_stream_write_resource_request(st2) fails");
    goto end;
  }

  CF_DEBUG("RESPONE SENT");

end: ;

  CF_DEBUG("LEAVE");
  CF_DEBUG("///////////////////////////////////////////////////////////////////////////");
}





/////////////////////////////////////////////////////////////////////////////
// BOTH SIDES

static bool create_master_channel(void)
{
  static corpc_service my_get_resource_service = {
    .name = "get_resource",
    .methods = {
      { .name = "get_resource", .proc = on_smaster_get_resource_requested },
      { .name = NULL },
    }
  };

  static const corpc_service * my_services[] = {
    &my_get_resource_service,
    NULL
  };

  bool fOk = false;

  CF_DEBUG("corpc_channel_open()");

  g_smaster_channel = corpc_channel_open(&(struct corpc_channel_open_args ) {

        .connect_address = g_master_server_ip,
        .connect_port = g_master_server_port,

        .ssl_ctx = NULL,

        .services = my_services,

        .keep_alive = {
          .enable = true,
          .keepidle = 5,
          .keepintvl = 3,
          .keepcnt = 5
        }
      });

  if ( !g_smaster_channel ) {
    CF_FATAL("corpc_channel_open() fails");
    goto end;
  }

  fOk = true;

end :
  if ( !fOk ) {
    CF_DEBUG("C corpc_channel_close()");
    corpc_channel_close(&g_smaster_channel);
  }

  return fOk;
}


static void master_authenticate(void * arg)
{
  (void)(arg);

  struct auth_request request = {
    .cid = "",
  };

  struct auth_responce responce = {
    .tunip = "",
  };

  corpc_stream * auth_stream = NULL;

  bool fOk = false;


  if ( !create_master_channel() ) {
    CF_FATAL("create_master_channel() fails");
    goto end;
  }

  auth_stream = corpc_open_stream(g_smaster_channel, &(corpc_open_stream_opts ) {
        .service = "smaster",
        .method = "authenicate"
      });

  if ( !auth_stream ) {
    CF_FATAL("corpc_open_stream(authenicate) fails");
    goto end;
  }




  /* proto: client must send his ID in first message */

  strncpy(request.cid, g_client_id, sizeof(request.cid) - 1);

  if ( !corpc_stream_send_auth_request(auth_stream, &request) ) {
    CF_CRITICAL("corpc_stream_read_auth_request() fails");
    goto end;
  }




  /* proto: client expect tunip in auth responce */

  if ( !corpc_stream_recv_auth_responce(auth_stream, &responce) ) {
    CF_CRITICAL("corpc_stream_recv_auth_responce() fails");
    goto end;
  }

  if ( !*responce.tunip ) {
    CF_FATAL("Invalid (empty) auth responce");
    goto end;
  }

  strncpy(g_tunip, responce.tunip, sizeof(g_tunip) - 1);


  fOk = true;

end:

  corpc_close_stream(&auth_stream);

  if ( !fOk ) {
    CF_DEBUG("C corpc_channel_close()");
    corpc_channel_close(&g_smaster_channel);
  }

  g_auth_finished = true;
  CF_DEBUG("FINISHED");
}


/////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////




int main(int argc, char *argv[])
{

////  int tcpfd = -1;
//  char tbind[256] = "10.10.100.1";



  /* configurable flag for background / foreground mode */
  bool daemon_mode = true;



  int tunfd = -1;
  int microsrvfd = -1;




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
      strncpy(g_client_id, argv[i], sizeof(g_client_id) - 1);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else if ( strcmp(argv[i], "--smaster") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }

      if ( sscanf(argv[i], "%255[^:]:%hu", g_master_server_ip, &g_master_server_port) < 1 ) {
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
      strncpy(g_tuniface, argv[i], sizeof(g_tuniface) - 1);
    }

    //////////////////////////////////////////////////////////////////////////////////////////////
    else {
      fprintf(stderr, "Invalid argument %s\n", argv[i]);
      return 1;
    }
  }

  cf_set_logfilename("stderr");
  cf_set_loglevel(CF_LOG_DEBUG);

  if ( !ccarray_init(&rtable, 1024, sizeof(struct rtable_item)) ) {
    CF_FATAL("ccarray_init(rtable) fails: %s", strerror(errno));
    return 1;
  }


  if ( !cf_ssl_initialize() ) {
    CF_FATAL("cf_ssl_initialize() fails: %s", strerror(errno));
    return 1;
  }

  if ( !co_scheduler_init(2) ) {
    CF_FATAL("co_scheduler_init() fails: %s", strerror(errno));
    return 1;
  }

  // start smaster authentication, results in opened smaster channel and retrived tunip
  if ( !co_schedule(master_authenticate, NULL, 1024 * 1024) ) {
    CF_FATAL("co_schedule(master_authenticate) fails: %s", strerror(errno));
    return 1;
  }

  // Wait util authentication finished
  while ( !g_auth_finished ) {
    co_sleep(500);
  }

  CF_DEBUG("auth finished: tunip='%s'", g_tunip);
  if ( !*g_tunip ) {
    return 1;
  }




  // Open tunnel and assign received tunip address */

  CF_DEBUG("open_tunnel(node=%s, tuniface=%s, tunip=%s, ifacemask=%s, ifaceflags=0x%0X)",
      g_node, g_tuniface, g_tunip, g_ifacemask, g_ifaceflags);

  if ( (tunfd = open_tunnel(g_node, g_tuniface, g_tunip, g_ifacemask, g_ifaceflags)) == -1 ) {
    CF_FATAL("open_tunnel(node=%s, tuniface=%s, tunip=%s, ifacemask=%s, ifaceflags=0x%0X) fails: %s",
        g_node, g_tuniface, g_tunip, g_ifacemask, g_ifaceflags, strerror(errno));
    return 1;
  }
  CF_DEBUG("Tunnel opened");






  // Schedule micro tcp server

  if ( (microsrvfd = so_tcp_listen(g_tunip, 6001, &g_microsrv_bind_address)) == -1 ) {
    CF_FATAL("so_tcp_listen(bindaddrs=%s:6001) fails", g_tunip);
    return 1;
  }

  so_set_non_blocking(microsrvfd, 1);
  if ( !co_schedule_io(microsrvfd, EPOLLIN, microsrv_accept, (void *) (ssize_t) (microsrvfd), 1024 * 1024) ) {
    CF_FATAL("co_schedule_io(microsrv_accept) fails: %s", strerror(errno));
    return 1;
  }





  // Schedule tunnel ip forwarding

  so_set_non_blocking(tunfd, 1);
  if ( !co_schedule_io(tunfd, EPOLLIN, rdtun, (void *) (ssize_t) (tunfd), 1024 * 1024) ) {
    CF_FATAL("co_schedule_io(rdtun) fails: %s", strerror(errno));
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
      CF_DEBUG("Switched to background mode: pid = %d", pid);
      return 0;
    }

    cf_set_logfilename("cshell-client.log");
  }


  while ( 42 ) {
    co_sleep(100000);
  }

//
//
//
//
//
//
//
//
//
//
//
//
//
//
//  start_mircosrv_thread(tunip);
//  sleep(1);
//
//  CF_DEBUG("listening %s:%u", inet_ntoa(g_microsrv_bind_address.sin_addr), ntohs(g_microsrv_bind_address.sin_port));
//
//
//  /* run event loop */
//  process_tunnel_packets(tunfd);


  return 0;
}


#if 0




///////////////////////////////////////////////////////////////////////////////////

//static char g_bindaddrs[256];

static void * microsrv_client_thread(void * arg)
{
  int so1 = (int)(ssize_t)(arg);

//  so_sprintf(master_so, "RR 10.10.100.50:80\n");
//  so_recv_line(master_so, buf, maxsize);



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

    ssize_t pos = rtable_find_resp(addrsfrom.sin_addr, addrsfrom.sin_port);
    if ( pos < 0 ) {
      CF_FATAL("APP BUG: rtable_find_resp() fails");
      so_close(so2, false);
    }
    else {
      const struct rtable_item * item = ccarray_peek(&rtable, pos);
      CF_DEBUG("REQUESTED ROUTE TO %s:%u", inet_ntoa(item->dst.sin_addr), ntohs(item->dst.sin_port));

      if ( !smaster_queue_push(so2, &item->dst) ) {
        CF_FATAL("FATAL: smaster_queue_push_request() fails");
        so_close(so2, false);
      }
      else {
        CF_DEBUG("so=%d REQUEST QUEUED AS %s:%u", so2, inet_ntoa(item->dst.sin_addr), ntohs(item->dst.sin_port));
      }
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

static void * smaster_msgloop_thread(void * arg)
{
  (void) (arg);

  static const int MAX_EPOLL_EVENTS = 100;
  struct epoll_event events[MAX_EPOLL_EVENTS];
  struct epoll_event * e;
  int epollfd = -1;


  int i, n;
  bool fail = false;

  pthread_detach(pthread_self());


  /* create epoll listener */
  if ( (epollfd = epoll_create1(0)) == -1 ) {
    CF_FATAL("epoll_create1() fails: %s", strerror(errno));
    goto __end;
  }

  /* manage g_smaster_so to listen */
  if ( !epoll_add(epollfd, g_smaster_so, EPOLLIN) ) {
    CF_FATAL("epoll_(epollfd=%d, smaster_so=%d) fails: %s", epollfd, g_smaster_so, strerror(errno));
    goto __end;
  }

  // fixme: may be ignore errno == EINTR ?
  while ( (n = epoll_wait(epollfd, events, MAX_EPOLL_EVENTS, -1)) >= 0 && !fail ) {

    for ( i = 0; i < n ; ++i ) {

      e = &events[i];

      if ( e->data.fd == g_smaster_so ) {
        if ( e->events & EPOLLIN ) {

          char line[1024] = "";
          ssize_t cb;

          if ( (cb = so_recv_line(g_smaster_so, line, sizeof(line))) < 1 ) {
            CF_FATAL("so_recv_line(g_smaster_so=%d) fails: %s", g_smaster_so, strerror(errno));
            fail = true;
            break;
          }

          if ( strncmp(line, "RRR ", 4)  == 0 ) {

            int64_t rid;
            char ipaddrs[256] = "";
            uint16_t port = 0;
            struct route_request rr;

            if ( sscanf(line + 4, "%"PRIu64" %255[^:]:%hu", &rid, ipaddrs, &port) != 3 ) {
              CF_FATAL("APP BUG: Can not parse RRR responce '%s'", line);
              fail = true;
              break;
            }

            if ( !smaster_queue_pop(rid, &rr) ) {
              CF_FATAL("APP BUG: RRR responce to not existent request '%s'", line);
              fail = true;
              break;
            }

            so_sockaddr_in(ipaddrs, port, &rr.resource_actual);

            CF_DEBUG("Actual resource location is: %s:%u", inet_ntoa(rr.resource_actual.sin_addr),
                ntohs(rr.resource_actual.sin_port));

          }
          else if ( strncmp(line, "NOTIFY ", 7)  == 0 ) {

          }
        }
      }

    }
  }

__end:

  if ( epollfd != -1 ) {
    close(epollfd);
  }

  if ( g_smaster_so != -1 ) {
    close (g_smaster_so);
  }

  return NULL;
}



static bool start_smaster_msgloop()
{
  pthread_t pid;
  int status;
  if ( (status = pthread_create(&pid, NULL, smaster_msgloop_thread, NULL)) ) {
    CF_FATAL("pthread_create(smaster_msgloop_thread): %s", strerror(status));
  }
  return status == 0;
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

#endif

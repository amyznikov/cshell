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
#include "rdtun.h"
//#include "checksum.h"
//#include "ip-pkt.h"
//#include "epoll-ctl.h"
//#include "so-msg.h"
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


static int g_microsrvfd = -1;
struct sockaddr_in g_microsrv_bind_address;


/////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////






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


  CF_DEBUG("REQUESTED ROUTE TO %s:%u", inet_ntoa(addrs->sin_addr), ntohs(addrs->sin_port));

  st = corpc_open_stream(g_smaster_channel, &(corpc_open_stream_opts ) {
        .service = "smaster",
        .method = "get_resource"
      });

  if ( !st ) {
    CF_FATAL("corpc_open_stream(smaster/get_resource) fails");
    goto __end;
  }


  CF_DEBUG("corpc_stream_write_resource_request(st)");

  sprintf(request.resource_id, "%s:%u", inet_ntoa(addrs->sin_addr), ntohs(addrs->sin_port));
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

// called from microsrv_accept()
static void microsrv_thread(void * arg)
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


  if ( !get_actual_resource_location(&item->dst, &ticket, actual_resource_location) ) {
    CF_FATAL("get_actual_resource_location() fails");

    sprintf(buf, "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=ISO-8859-1\r\n"
        "\r\n"
        "<HTML><H1>get_actual_resource_location() fails</H1></HTML>\r\n");
    goto end;
  }


  so_sockaddr_in(actual_resource_location, ntohs(item->dst.sin_port), &addrs);

  if ( !(sslsock2 = co_ssl_socket_connect_new((struct sockaddr*) &addrs, NULL, SOCK_STREAM, IPPROTO_TCP, 10 * 1000)) ) {
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


// called from start_microsrv()
static int microsrv_accept(void * arg, uint32_t events)
{
  (void)(events);

  int so1, so2;

  so1 = (int) (ssize_t) (arg);

  // fixme for cuttle: EPOLLET
  while ( (so2 = accept(so1, NULL, NULL)) != -1 ) {
    if ( !co_schedule(microsrv_thread, (void*) (ssize_t) (so2), 1024 * 1024) ) {
      CF_FATAL("co_schedule(microsrv_client_thread) fails");
      so_close(so2, true);
    }
  }

  return 0;
}

// calls microsrv_accept() for new incoming connection
static bool start_microsrv(const char * listen_addrs, uint16_t listen_port,
    /* out, opt */ struct sockaddr_in * bound_addrs)
{
  if ( (g_microsrvfd = so_tcp_listen(listen_addrs, listen_port, bound_addrs)) == -1 ) {
    CF_FATAL("so_tcp_listen(bindaddrs=%s:%u) fails", listen_addrs, listen_port);
    return false;
  }

  so_set_non_blocking(g_microsrvfd, 1);
  if ( !co_schedule_io(g_microsrvfd, EPOLLIN, microsrv_accept, (void *) (ssize_t) (g_microsrvfd), 1024 * 1024) ) {
    CF_FATAL("co_schedule_io(microsrv_accept) fails: %s", strerror(errno));
    return false;
  }

  return true;
}



/////////////////////////////////////////////////////////////////////////////

// SIDE B

struct authtoken {
  uint64_t ticket;
};

static ccarray_t g_authtokens; // <struct authtoken>

static bool push_auth_tocken(uint64_t ticket)
{
  if ( ccarray_size(&g_authtokens) >= ccarray_capacity(&g_authtokens) ) {
    CF_FATAL("TOO MANY TOKENS");
    return false;
  }

  ccarray_push_back(&g_authtokens, &(struct authtoken ) {
        .ticket = ticket
      });

  return true;
}

static bool pop_auth_tocken(uint64_t ticket, struct authtoken * token)
{
  size_t i, n;
  const struct authtoken * t;
  for ( i = 0, n = ccarray_size(&g_authtokens); i < n; ++i ) {
    if ( (t = ccarray_peek(&g_authtokens, i))->ticket == ticket ) {
      memcpy(token, t, sizeof(*t));
      ccarray_erase(&g_authtokens, i);
      return true;
    }
  }
  return false;
}

static void micro_client_thread(void * arg)
{
  struct sockaddr_in addrs;
  socklen_t addrssize = sizeof(addrs);

  struct authtoken token;
  int so1 = -1, so2 = -1;

//  char buf[1024] = "";

  so1 = (int)(ssize_t)(arg);

  getpeername(so1, (struct sockaddr*) &addrs, &addrssize);

  CF_NOTICE("ACCEPTED FROM %s:%u", inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port));

  so_set_non_blocking(so1, true);
  so_set_recv_timeout(so1, 10);

  if ( co_recv(so1, &token.ticket, sizeof(token.ticket), 0) != sizeof(token.ticket) ) {
    CF_FATAL("Can not read auth ticket, abort connection");
    goto end;
  }

  if ( !pop_auth_tocken(token.ticket, &token) ) {
    CF_FATAL("Inalid ticket received=%llu, abort connection", (unsigned long long )token.ticket);
    goto end;
  }

  CF_DEBUG("AUTH TICKET=%llu", (unsigned long long )token.ticket);

  // make connection to internal (hidden) actual web service
  if ( (so2 = so_tcp_connect2("127.0.0.1", 80)) == -1 ) {
    CF_FATAL("so_tcp_connect() fails, abort connection");
    goto end;
  }

  CF_NOTICE("ESTABLISHED");

  // start data exchange

end:

  if ( so1 != -1 ) {
    so_close(so1, false);
  }

  if ( so2 != -1 ) {
    so_close(so1, false);
  }
}



static int micro_client_accept(void * arg, uint32_t events)
{
  (void)(events);

  int so1, so2;

  so1 = (int) (ssize_t) (arg);

  // fixme for cuttle: EPOLLET
  while ( (so2 = accept(so1, NULL, NULL)) != -1 ) {
    if ( !co_schedule(micro_client_thread, (void*) (ssize_t) (so2), 1024 * 1024) ) {
      CF_FATAL("co_schedule(micro_client_thread) fails");
      so_close(so2, true);
    }
  }

  return 0;
}

static bool start_micro_client_server(const char * listen_address, uint16_t listen_port)
{
  int so;

  if ( (so = so_tcp_listen(listen_address, listen_port, NULL)) == -1 ) {
    CF_FATAL("so_tcp_listen(bindaddrs=%s:%u) fails", listen_address, listen_port);
    return false;
  }

  so_set_non_blocking(so, 1);
  if ( !co_schedule_io(so, EPOLLIN, micro_client_accept, (void *) (ssize_t) (so), 1024 * 1024) ) {
    CF_FATAL("co_schedule_io(micro_client_accept) fails: %s", strerror(errno));
    return false;
  }

  return true;
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

  CF_DEBUG("TICKET=%llu", (unsigned long long )request.ticket);
  CF_DEBUG("RESOURCE_ID='%s'", request.resource_id);

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


int main(int argc, char *argv[])
{

  /* configurable flag for background / foreground mode */
  bool daemon_mode = true;

  int tunfd = -1;


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

  CF_DEBUG("Tunnel name: '%s'", g_tuniface);






  // Schedule internal micro tcp server
  if ( !start_microsrv(g_tunip, 6001, &g_microsrv_bind_address) ) {
    CF_FATAL("start_microsrv(%s:6001) fails", g_tunip);
    return 1;
  }

  // Schedule tunnel ip forwarding
  if ( !start_rdtun_cothread(tunfd, &g_microsrv_bind_address) ) {
    CF_FATAL("start_rdtun_cothread(tunfd=-1) fails: %s", strerror(errno));
    return 1;
  }


  // Schedule services micro stubs
  if ( !start_micro_client_server("0.0.0.0", 80) ) {
    CF_FATAL("start_micro_client_server() fails: %s", strerror(errno));
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

  return 0;
}



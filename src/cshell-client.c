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


#define CO_STACK_SIZE   (64*1024*1024)

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

// micro server stub address:port, must be bound to tunip to work correctly
static int g_g_micro_tcp_server_fd = -1;
static struct sockaddr_in g_micro_tcp_server_bind_address;

// IP addrs pf physical eth device
static char g_phys_addrs[16] = "";
static uint16_t g_phys_port = 80;


/////////////////////////////////////////////////////////////////////////////

/* data exchange between sockets :
 *    recv from src, send to dst
 */
struct so_ddx_thread_arg {
  int src, dst;
  bool finished;
};

static void co_ddx_thread(void * arg)
{
  struct so_ddx_thread_arg * ddxarg = arg;

  char buf[4 * 1024];
  ssize_t cbr, cbs;

  CF_DEBUG("[%d -> %d]", ddxarg->src, ddxarg->dst);

  while ( (cbr = co_recv(ddxarg->src, buf, sizeof(buf), 0)) > 0 ) {
    if ( (cbs = co_send(ddxarg->dst, buf, cbr, 0)) != cbr ) {
      ddxarg->finished = true;
      CF_FATAL("co_send() fails: cbr=%zd cbs=%zd errno=%s", cbr, cbs, strerror(errno));
      break;
    }
  }

  ddxarg->finished = true;
  CF_DEBUG("recv(src=%d, dst=%d): %zd, err=%s", ddxarg->src, ddxarg->dst, cbr, strerror(errno));
  CF_WARNING("[%d -> %d] FINISHED", ddxarg->src, ddxarg->dst);
}

/* data exchange between sockets :
 *    recv from so1, send to so2
 *    recv from so2, send to so1
 */
static bool co_ddx(int so1, int so2)
{
  struct so_ddx_thread_arg arg1 = {
    .src = so1,
    .dst = so2,
    .finished = false
  };

  struct so_ddx_thread_arg arg2 = {
    .src = so2,
    .dst = so1,
    .finished = false
  };


  so_set_recv_timeout(so1, 5);
  so_set_send_timeout(so1, 5);

  so_set_recv_timeout(so2, 5);
  so_set_send_timeout(so2, 5);

  CF_DEBUG("co_schedule(co_ddx_thread(so1=%d -> so2=%d) arg1=%p", so1, so2, &arg1);
  if ( !co_schedule(co_ddx_thread, &arg1, CO_STACK_SIZE) ) {
    CF_FATAL("co_schedule_io(co_ddx_thread2) fails");
    return false;
  }

  CF_DEBUG("co_schedule(co_ddx_thread(so2=%d -> so1=%d) arg2=%p", so2, so1, &arg2);
  if ( !co_schedule(co_ddx_thread, &arg2, CO_STACK_SIZE) ) {
    CF_FATAL("co_schedule_io(co_ddx_thread2) fails");
    return false;
  }

  while ( !arg1.finished || !arg2.finished ) {
    CF_DEBUG("REMOVE ME AFTER DEBUG: co_sleep(1000)");
    co_sleep(1000);
  }


  CF_NOTICE("******** %d <=> %d FINISHED", so1, so2);
  return true;
}


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

  CF_DEBUG("GOT TICKET FROM MASTER = %llu", (unsigned long long ) responce.ticket);

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
static void micro_server_thread(void * arg)
{
  struct sockaddr_in addrs;
  socklen_t addrssize = sizeof(addrs);

  uint64_t ticket = 0;
  char actual_resource_location[SM_MAX_ACTUAL_RESOURCE_ADDRESS] = "";
  const struct tunnel_route_table_item * item;

  char buf[4 * 1024] = "";

  int so1 = -1, so2 = -1;

  so1 = (int)(ssize_t)(arg);

  bool fOk = false;


  getpeername(so1, (struct sockaddr*) &addrs, &addrssize);

  CF_NOTICE("ACCEPTED FROM %s:%u", inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port));

  if ( !(item = rtable_get_rsp(addrs.sin_addr, addrs.sin_port)) ) {
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

  if ( (so2 = co_tcp_connect((struct sockaddr*) &addrs, sizeof(addrs), 10)) == -1 ) {
    CF_FATAL("co_tcp_connect(%s:%u) fails: %s", inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port), strerror(errno));
    sprintf(buf, "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=ISO-8859-1\r\n"
        "\r\n"
        "<HTML><H1>co_tcp_connect(%s:%u) fails</H1></HTML>\r\n",
          inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port));
    goto end;
  }


  // send auth ticket

  CF_DEBUG("Send auth.ticket=%llu so1=%d so2=%d", (unsigned long long ) ticket, so1, so2);

  if ( !co_send(so2, &ticket, sizeof(ticket), 0) ) {
    CF_FATAL("co_send(ticket) fails");
    sprintf(buf, "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=ISO-8859-1\r\n"
        "\r\n"
        "<HTML><H1>co_send(ticket) fails</H1></HTML>\r\n");
    goto end;
  }

  CF_DEBUG("co_send(so1=%d so2=%d) OK", so1, so2);

  fOk = true;

  if ( !co_ddx(so1, so2) ) {
    CF_FATAL("co_ddx() fails");
  }

end:

  if ( !fOk ) {
    if ( so1 != -1 ) {
      co_send(so1, buf, strlen(buf), 0);
    }
  }

  if ( so1 != -1 ) {
    so_close(so1, false);
  }

  if ( so2 != -1 ) {
    so_close(so2, false);
  }
}


// called from start_micro_server()
static int micro_server_accept(void * arg, uint32_t events)
{
  (void)(events);

  int so1, so2;

  so1 = (int) (ssize_t) (arg);

  if ( events & EPOLLERR ) {
    CF_FATAL("FATAL : EPOLLERR");
    so_close(so1, false);
    return 1;
  }

  // fixme for cuttle: EPOLLET
  CF_DEBUG("micro_server_accept: EVENTS=0x%0x", events);

  while ( (so2 = accept(so1, NULL, NULL)) != -1 ) {
    so_set_non_blocking(so2, true);
    if ( !co_schedule(micro_server_thread, (void*) (ssize_t) (so2), CO_STACK_SIZE) ) {
      CF_FATAL("co_schedule(microsrv_client_thread) fails");
      so_close(so2, false);
    }
  }

  CF_DEBUG("micro_server_accept: LEAVE");

  return 0;
}

// calls microsrv_accept() for new incoming connection
static bool start_micro_server(const char * listen_addrs, uint16_t listen_port,
    /* out, opt */ struct sockaddr_in * bound_addrs)
{
  if ( (g_g_micro_tcp_server_fd = so_tcp_listen(listen_addrs, listen_port, bound_addrs)) == -1 ) {
    CF_FATAL("so_tcp_listen(bindaddrs=%s:%u) fails", listen_addrs, listen_port);
    return false;
  }

  so_set_non_blocking(g_g_micro_tcp_server_fd, true);
  if ( !co_schedule_io(g_g_micro_tcp_server_fd, EPOLLIN, micro_server_accept, (void *) (ssize_t) (g_g_micro_tcp_server_fd), CO_STACK_SIZE) ) {
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
  if ( ccarray_capacity(&g_authtokens) < 1 ) {
    if ( !ccarray_init(&g_authtokens, 1000, sizeof(struct authtoken)) ) {
      CF_FATAL("ccarray_init(g_authtokens) fails");
      return false;
    }
  }


  if ( ccarray_size(&g_authtokens) >= ccarray_capacity(&g_authtokens) ) {
    CF_FATAL("TOO MANY TOKENS");
    return false;
  }


  ccarray_push_back(&g_authtokens, &(struct authtoken ) {
        .ticket = ticket
      });

  return true;
}

static bool search_auth_tocken(uint64_t ticket, struct authtoken * token)
{
  size_t i, n;
  const struct authtoken * t;
  for ( i = 0, n = ccarray_size(&g_authtokens); i < n; ++i ) {
    if ( (t = ccarray_peek(&g_authtokens, i))->ticket == ticket ) {
      if ( token ) {
        memcpy(token, t, sizeof(*t));
      }
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

  ssize_t cb;

  so1 = (int)(ssize_t)(arg);

  getpeername(so1, (struct sockaddr*) &addrs, &addrssize);

  CF_NOTICE("ACCEPTED FROM %s:%u", inet_ntoa(addrs.sin_addr), ntohs(addrs.sin_port));

  so_set_recv_timeout(so1, 10);

  if ( (cb = co_recv(so1, &token.ticket, sizeof(token.ticket), 0)) != sizeof(token.ticket) ) {
    CF_FATAL("Can not read auth ticket, abort connection. cb=%zd", cb);
    goto end;
  }

  CF_DEBUG("RECEIVED AUTH TICKET=%llu", (unsigned long long )token.ticket);

  if ( !search_auth_tocken(token.ticket, &token) ) {
    CF_FATAL("Inalid ticket received=%llu, abort connection", (unsigned long long )token.ticket);
    goto end;
  }

  CF_DEBUG("POP-ED AUTH TICKET=%llu", (unsigned long long )token.ticket);


  // fixme: make connection to actual internal (hidden) web service
  so_sockaddr_in(g_tunip, 80, &addrs);
  if ( (so2 = co_tcp_connect((struct sockaddr*) &addrs, sizeof(addrs), 5)) == -1 ) {
    CF_FATAL("co_tcp_connect() fails, abort connection: %s", strerror(errno));
    goto end;
  }

  CF_NOTICE("ESTABLISHED");

  // start data exchange
  if ( !co_ddx(so1,  so2) ) {
    CF_FATAL("co_ddx() fails");
  }


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

  if ( events & EPOLLERR ) {
    CF_FATAL("FATAL : EPOLLERR");
    so_close(so1, false);
    return 1;
  }

  // fixme for cuttle: EPOLLET
  while ( (so2 = accept(so1, NULL, NULL)) != -1 ) {
    so_set_non_blocking(so2, true);
    if ( !co_schedule(micro_client_thread, (void*) (ssize_t) (so2), CO_STACK_SIZE) ) {
      CF_FATAL("co_schedule(micro_client_thread) fails");
      so_close(so2, false);
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
  if ( !co_schedule_io(so, EPOLLIN, micro_client_accept, (void *) (ssize_t) (so), CO_STACK_SIZE) ) {
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

  push_auth_tocken(responce.ticket);

  CF_DEBUG("corpc_stream_send_resource_responce(st)");
  if ( !corpc_stream_send_resource_responce(st, &responce) ) {
    CF_FATAL("corpc_stream_write_resource_request(st2) fails");
    search_auth_tocken(responce.ticket, NULL); // fixme: hack - this actually removes the ticket from list
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

  CF_DEBUG("ENTER");

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
    else if ( strcmp(argv[i], "--phys") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }

      if ( sscanf(argv[i], "%255[^:]:%hu", g_phys_addrs, &g_phys_port) < 1 ) {
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

  if ( !*g_phys_addrs || !g_phys_port ) {
    fprintf(stderr, "--phys not specified or invalid\n");
    return 1;
  }


  cf_set_logfilename("stderr");
  cf_set_loglevel(CF_LOG_DEBUG);



  CF_DEBUG("cf_ssl_initialize()");
  if ( !cf_ssl_initialize() ) {
    CF_FATAL("cf_ssl_initialize() fails: %s", strerror(errno));
    return 1;
  }

  CF_DEBUG("co_scheduler_init(1)");
  if ( !co_scheduler_init(1) ) {
    CF_FATAL("co_scheduler_init() fails: %s", strerror(errno));
    return 1;
  }

  // start smaster authentication, results in opened smaster channel and retrived tunip
  CF_DEBUG("co_schedule(master_authenticate()");
  if ( !co_schedule(master_authenticate, NULL, CO_STACK_SIZE) ) {
    CF_FATAL("co_schedule(master_authenticate) fails: %s", strerror(errno));
    return 1;
  }

  // Wait util authentication finished
  CF_DEBUG("while ( !g_auth_finished )");
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
  CF_DEBUG("start_micro_server()");
  if ( !start_micro_server(g_tunip, 6001, &g_micro_tcp_server_bind_address) ) {
    CF_FATAL("start_microsrv(%s:6001) fails", g_tunip);
    return 1;
  }

  // Schedule tunnel ip forwarding
  CF_DEBUG("start_rdtun_cothread()");
  if ( !start_rdtun(tunfd, &g_micro_tcp_server_bind_address) ) {
    CF_FATAL("start_rdtun_cothread(tunfd=-1) fails: %s", strerror(errno));
    return 1;
  }


  // Schedule services micro stubs
  CF_DEBUG("start_micro_client_server()");
  if ( !start_micro_client_server(g_phys_addrs, g_phys_port) ) {
    CF_FATAL("start_micro_client_server() fails: %s", strerror(errno));
    return 1;
  }






  /* fork() and become daemon */
  CF_DEBUG("if ( daemon_mode )");
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


  CF_DEBUG("co_sleep()");

  while ( 42 ) {
    co_sleep(100000);
  }

  return 0;
}



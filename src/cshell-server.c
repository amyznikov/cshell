/*
 * cshell-server.c
 *
 *  Created on: Feb 4, 2018
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>

#include <cuttle/corpc/server.h>
#include <cuttle/ssl/init-ssl.h>
#include <cuttle/sockopt.h>
#include <cuttle/ccarray.h>
#include <cuttle/debug.h>

#include "smaster.h"


#ifndef CSHELL_VERSION
# define CSHELL_VERSION "0.0.0"
#endif

static const char VERSION[] = CSHELL_VERSION;


#define MAX_CLIENT_ID 64
#define MAX_TUN_IP    16
#define MAX_CLIENTS   256


// Personal client inventory
typedef
struct client_account {
  char  id[MAX_CLIENT_ID];
  char  tunip[MAX_TUN_IP];
} client_account;

// Global list (aka database) of registerd client accounts
static ccarray_t g_client_accounts; // <struct client_account>





// Actual connections from clients
typedef
struct client_context {
  corpc_channel * channel;
  char  id[MAX_CLIENT_ID];
  char  tunip[MAX_TUN_IP];
  char  realip[16];
  uint16_t realp;
} client_context;

#define MAX_CLIENT_CONNECTIONS \
    (ccarray_size(&g_client_accounts))

static ccarray_t g_client_connections; // <struct client_context *>



/*
 * Load client inventory from database, done once at start of this server
 * */
static bool load_client_accounts(const char * filename)
{
  char line[1024];

  FILE * fp = NULL;

  if ( !(fp = fopen(filename, "r")) ) {
    CF_FATAL("fopen(%s) fails: %s", filename, strerror(errno));
    return false;
  }

  ccarray_cleanup(&g_client_accounts);
  ccarray_init(&g_client_accounts, MAX_CLIENTS, sizeof(struct client_account));

  while ( ccarray_size(&g_client_accounts) < ccarray_capacity(&g_client_accounts) && fgets(line, sizeof(line) - 1, fp) ) {
    struct client_account cfg;
    if ( sscanf(line, "%255s %15s", cfg.id, cfg.tunip) == 2 ) {
      ccarray_push_back(&g_client_accounts, &cfg);
    }
  }

  fclose(fp);

  return ccarray_size(&g_client_accounts) > 0;
}

/* search client inventory by client id */
static ssize_t find_client_account(const char * cid)
{
  size_t i, n;
  const struct client_account * acc;

  for ( i = 0, n = ccarray_size(&g_client_accounts); i < n; ++i ) {
    if ( strcmp((acc = ccarray_peek(&g_client_accounts, i))->id, cid) == 0 ) {
      return (ssize_t) (i);
    }
  }

  return (ssize_t) (-1);
}


/* get client inventory pointer by client id */
static struct client_account * get_client_account(const char * cid)
{
  ssize_t pos = find_client_account(cid);
  return pos < 0 ? NULL : ccarray_peek(&g_client_accounts, pos);
}




static client_context * client_context_new(corpc_channel * channel)
{
  struct sockaddr_in addrs;
  socklen_t addrslen = sizeof(addrs);
  client_context * cc;

  if ( (cc = calloc(1, sizeof(struct client_context))) ) {
    cc->channel = channel;
    if ( corpc_channel_get_peername(channel, (struct sockaddr*)&addrs, &addrslen) ) {
      strcpy(cc->realip, inet_ntoa(addrs.sin_addr));
      cc->realp = ntohs(addrs.sin_port);
    }
  }

  return cc;
}



/* search client connection by client id */
static ssize_t find_client_connection(const char * cid)
{
  size_t i, n;
  const struct client_context * cc;

  for ( i = 0, n = ccarray_size(&g_client_connections); i < n; ++i ) {
    if ( strcmp((cc = ccarray_ppeek(&g_client_connections, i))->id, cid) == 0 ) {
      return (ssize_t) (i);
    }
  }

  return (ssize_t) (-1);
}


/* get client inventory pointer by client id */
static struct client_context * get_client_connection(const char * cid)
{
  ssize_t pos = find_client_connection(cid);
  return pos < 0 ? NULL : ccarray_ppeek(&g_client_connections, pos);
}


/* search client connection by tunip */
static ssize_t find_client_connection_tunip(const char * tunip)
{
  size_t i, n;
  const struct client_context * cc;

  for ( i = 0, n = ccarray_size(&g_client_connections); i < n; ++i ) {
    if ( strcmp((cc = ccarray_ppeek(&g_client_connections, i))->tunip, tunip) == 0 ) {
      return (ssize_t) (i);
    }
  }

  return (ssize_t) (-1);
}


/* get client inventory pointer by tunip */
static struct client_context * get_client_connection_tunip(const char * tunip)
{
  ssize_t pos = find_client_connection_tunip(tunip);
  return pos < 0 ? NULL : ccarray_ppeek(&g_client_connections, pos);
}





/* called by corpc when new client connection is accepted */
static void on_client_accepted(corpc_channel * channel)
{
  corpc_channel_set_client_context(channel, client_context_new(channel));
}

/* called by corpc when client is diconnected */
static void on_client_disconnected(corpc_channel * channel)
{
  client_context * cc = corpc_channel_get_client_context(channel);
  if ( cc ) {
    ccarray_erase_item(&g_client_connections, &cc);
    corpc_channel_set_client_context(channel, NULL);
    free(cc);
  }
}

/* called by corpc when client sends auth request */
static void on_smaster_authenticate(corpc_stream * st)
{
  struct client_context * cc = NULL;
  struct client_account * acc = NULL;

  struct auth_request request = {
    .cid = "",
  };

  struct auth_responce responce = {
    .tunip = "",
  };


  CF_DEBUG("ENTER");

  /* proto: client must send his ID in first message line */
  if ( !corpc_stream_recv_auth_request(st, &request) ) {
    CF_CRITICAL("corpc_stream_read_auth_request() fails");
    goto end;
  }


  /* proto: client id must be registered in inventory database */
  CF_DEBUG("ClientID='%s'", request.cid);
  if ( !(acc = get_client_account(request.cid)) ) {
    CF_FATAL("ClientId = '%s' is NOT REGISTERED", request.cid);
    goto end;
  }

  /* proto: client id must NOT be already connected */
  if ( (cc = get_client_connection(request.cid)) ) {
    CF_FATAL("[%s] ALREADY CONNECTED WITH tunip=%s", request.cid, cc->tunip);
    cc = NULL;
    goto end;
  }

  /* mark client online (add to g_client_connections ) */
  if ( ccarray_size(&g_client_connections) >= ccarray_capacity(&g_client_connections) ) {
    CF_FATAL("[%s] BUG: NOT ENOUGH CONNECTION SLOTS. CONNECTION ABORTED.", request.cid);
    goto end;
  }

  /* The actual client context struct is already calloc-ed in on_client_accepted(),
   * but was not initialized */
  if ( !(cc = corpc_stream_get_channel_client_context(st)) ) {
    CF_FATAL("[%s] APP BUG: corpc_stream_get_channel_client_context() return NULL.\n"
        "CONNECTION ABORTED.", request.cid);
    goto end;
  }

  strncpy(cc->id, acc->id, sizeof(cc->id) - 1);
  strncpy(cc->tunip, acc->tunip, sizeof(cc->tunip) - 1);
  ccarray_push_back(&g_client_connections, &cc);

  /* proto: client expect tunip in auth server responce */
  strncpy(responce.tunip, acc->tunip, sizeof(responce.tunip) - 1);
  if ( !corpc_stream_send_auth_responce(st, &responce) ) {
    CF_CRITICAL("[%s] corpc_stream_send_auth_responce() fails", cc->id);
    goto end;
  }

  CF_DEBUG("[%s] AUTHENTICATED. TUNIP=%s", cc->id, cc->tunip);

end:

  CF_DEBUG("LEAVE");
}


/* called by corpc when client sends resource allocation request */
static void on_smaster_get_resource(corpc_stream * st)
{
  struct resource_request request = {
    .ticket = 0,
    .resource_id = "",
  };

  struct resource_responce responce = {
    .ticket = 0,
    .actual_resource_location = ""
  };

  struct client_context * cc = NULL;
  corpc_stream * st2 = NULL;

  char tunip[16] = "";
  uint16_t port = 0;


  CF_DEBUG("///////////////////////////////////////////////////////////////////////////");
  CF_DEBUG("ENTER");

  CF_DEBUG("corpc_stream_read_resource_request()");

  /* proto:  client sends tunip:port as resource ID */
  if ( !corpc_stream_recv_resource_request(st, &request) ) {
    CF_FATAL("corpc_stream_read_resource_request() fails");
    goto end;
  }



  /* search online client with given resource id (actualy tunip) */

  CF_DEBUG("REQUEST.RESOURCE_ID='%s'", request.resource_id);

  if ( sscanf(request.resource_id, "%15[^:]:%hu", tunip, &port) < 1 ) {
    CF_FATAL("invalid resource id requested: '%s'", request.resource_id);
    goto end;
  }

  if ( !(cc = get_client_connection_tunip(tunip)) ) {
    CF_FATAL("requested resource '%s' is not available", tunip);
    goto end;
  }


  /* proto: smaster generates resource auth ticket and sends request to another client */
  request.ticket = ((uint64_t) rand()) | (((uint64_t) rand()) << 32);

  CF_DEBUG("st2 = corpc_open_stream()");
  st2 = corpc_open_stream(cc->channel, &(corpc_open_stream_opts ) {
        .service = "get_resource",
        .method = "get_resource"
      });

  if ( !st2 ) {
    CF_FATAL("corpc_open_stream(get_resource) fails");
    goto end;
  }

  CF_DEBUG("corpc_stream_write_resource_request(st2)");
  if ( !corpc_stream_send_resource_request(st2, &request) ) {
    CF_FATAL("corpc_stream_write_resource_request(st2) fails");
    goto end;
  }


  CF_DEBUG("corpc_stream_recv_resource_request(st2)");
  if ( !corpc_stream_recv_resource_responce(st2, &responce) ) {
    CF_FATAL("corpc_stream_write_resource_request(st2) fails");
    goto end;
  }


  /* proto: smaster send actual ip address of allocate resource (another client) */
  strcpy(responce.actual_resource_location, cc->realip);

  CF_DEBUG("corpc_stream_send_resource_responce(st)");
  if ( !corpc_stream_send_resource_responce(st, &responce) ) {
    CF_FATAL("corpc_stream_write_resource_request(st2) fails");
    goto end;
  }

  CF_DEBUG("FINISHED");

end:;

  corpc_close_stream(&st2);

  CF_DEBUG("LEAVE");
  CF_DEBUG("///////////////////////////////////////////////////////////////////////////");
}


int main(int argc, char *argv[])
{
  // corpc server
  corpc_server * server = NULL;

  char bindaddrs[256] = "0.0.0.0";
  uint16_t bindport = 6010;



  // clients database file name
  char clients_filename[PATH_MAX] = "cshell-clients.cfg";


  /* configurable flag for background / foreground mode */
  bool daemon_mode = true;

  bool fOk = false;

  int i;

  for ( i = 1; i < argc; ++i ) {

    //////////////////////////////////////////////////////////////////////////////////////////////
    if ( strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "--help") == 0 ) {
      printf("cshell-server %s\n\n", VERSION);
      printf("USAGE\n");
      printf("  cshell-server [OPTIONS]\n\n");
      printf("OPTIONS:\n");
      printf(" --bind <arddrs:port>\n");
      printf("      bind server to specified addrs and port\n");
      return 0;
    }

    if ( strcmp(argv[i], "--no-daemon") == 0 || strcmp(argv[i], "-n") == 0 ) {
      daemon_mode = false;
    }
    else if ( strcmp(argv[i], "--bind") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }
      if ( sscanf(argv[i], "%255[^:]:%hu", bindaddrs, &bindport) < 1 ) {
        fprintf(stderr, "Invalid argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }
    }
    else if ( strcmp(argv[i], "--clients") == 0 ) {
      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }
      strncpy(clients_filename, argv[i], sizeof(clients_filename) - 1);
    }


    else {
      fprintf(stderr, "Invalid argument %s\n", argv[i]);
      return 1;
    }
  }


  cf_set_logfilename("stderr");
  cf_set_loglevel(CF_LOG_DEBUG);


  if ( !load_client_accounts(clients_filename) ) {
    CF_FATAL("load_clients(%s) fails: %s", clients_filename, strerror(errno));
    return 1;
  }

  if ( !ccarray_init(&g_client_connections, MAX_CLIENT_CONNECTIONS, sizeof(struct client_context*)) ) {
    CF_FATAL("ccarray_init(client_connections=%zu) fails: %s", MAX_CLIENT_CONNECTIONS, strerror(errno));
    return 1;
  }




  CF_DEBUG("cf_ssl_initialize()");
  if ( !cf_ssl_initialize() ) {
    CF_FATAL("cf_ssl_initialize() fails");
    return 1;
  }

  CF_DEBUG("C co_scheduler_init()");
  if ( !co_scheduler_init(2) ) {
    CF_FATAL("co_scheduler_init() fails");
    return 1;
  }


  CF_DEBUG("C corpc_server_new()");
  server = corpc_server_new(
      &(struct corpc_server_opts ) {
        .ssl_ctx = NULL
      });

  if ( !server ) {
    CF_FATAL("corpc_server_new() fails");
    return 1;
  }


  static const corpc_service smaster_service = {
    .name = "smaster",
    .methods = {
      { .name = "authenicate", .proc = on_smaster_authenticate },
      { .name = "get_resource", .proc = on_smaster_get_resource },
      { .name = NULL },
    }
  };

  static const corpc_service * smaster_services[] = {
    &smaster_service,
    NULL
  };

  CF_DEBUG("corpc_server_add_port()");
  fOk = corpc_server_add_port(server,
      &(struct corpc_listening_port_opts ) {

            .listen_address.in = {
              .sin_family = AF_INET,
              .sin_addr.s_addr = inet_addr(bindaddrs),
              .sin_port = htons(bindport),
              .sin_zero = ""
            },

            .services = smaster_services,

            .onaccepted = on_client_accepted,

            .ondisconnected = on_client_disconnected
          });


  if ( !fOk ) {
    CF_FATAL("corpc_server_add_port() fails");
    return 1;
  }

  CF_DEBUG("corpc_server_start()");
  if ( !corpc_server_start(server) ) {
    CF_FATAL("corpc_server_start() fails");
    return 1;
  }

  CF_DEBUG("Server started");

  /* fork() and become daemon */
  if ( daemon_mode ) {

    pid_t pid;

    switch ( (pid = fork()) ) {

    case -1 :
      CF_FATAL("fork() fails: %s", strerror(errno));
      return 1;

    case 0 :
      // in child, continue initialization
      break;

    default :
      // parrent, fnish
      CF_INFO("switched to background mode: pid=%d", pid);
      return 0;
    }

    cf_set_logfilename("cshell-server.log");
  }

  while ( 42 ) {
    sleep(10);
  }

  return 0;
}

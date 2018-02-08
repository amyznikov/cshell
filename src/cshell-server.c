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

#include "pthread_wait.h"
#include "sockopt.h"
#include "so-msg.h"
#include "ccarray.h"
#include "debug.h"


#ifndef CSHELL_VERSION
# define CSHELL_VERSION "0.0.0"
#endif

static const char VERSION[] = CSHELL_VERSION;


#define MAX_CLIENT_ID 64
#define MAX_TUN_IP    16
#define MAX_CLIENTS   256


// Personal client inventory
struct client_account {
  char  id[MAX_CLIENT_ID];
  char  tunip[MAX_TUN_IP];
};

// Global list (aka database) of registerd client accounts
static ccarray_t g_client_accounts; // <struct client_account>





// Actual connections from clients
struct client_connection {
  char  id[MAX_CLIENT_ID];
  char  tunip[MAX_TUN_IP];
  int   so;
};

#define MAX_CLIENT_CONNECTIONS \
    (ccarray_size(&g_client_accounts))

static ccarray_t g_client_connections;
static pthread_wait_t g_client_connections_lock;





/*
 * Interthread locks management for g_client_connections array
 * */

static void client_connections_lock(void)
{
  pthread_wait_lock(&g_client_connections_lock);
}

static void client_connections_unlock(void)
{
  pthread_wait_unlock(&g_client_connections_lock);
}

static int client_connections_wait(int tmo)
{
  return pthread_wait(&g_client_connections_lock, tmo);
}

static void client_connections_signal(void)
{
  pthread_wait_signal(&g_client_connections_lock);
}



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


/* search client inventory by client id */
static ssize_t find_client_connection(const char * cid)
{
  size_t i, n;
  const struct client_connection * cc;

  for ( i = 0, n = ccarray_size(&g_client_connections); i < n; ++i ) {
    if ( strcmp((cc = ccarray_ppeek(&g_client_connections, i))->id, cid) == 0 ) {
      return (ssize_t) (i);
    }
  }

  return (ssize_t) (-1);
}


/* get client inventory pointer by client id */
static struct client_connection * get_client_connection(const char * cid)
{
  ssize_t pos = find_client_connection(cid);
  return pos < 0 ? NULL : ccarray_ppeek(&g_client_connections, pos);
}

static struct client_connection * authenticate_connection(int so )
{
  // client id
  char cid[MAX_CLIENT_ID] = "";

  struct client_account * acc = NULL;
  struct client_connection * cc = NULL;
  struct client_connection * existing_cc = NULL;

  ssize_t cb;

  bool fOk = false;

  /* proto: client must send his ID in first message line */
  if ( (cb = so_recv_line(so, cid, sizeof(cid))) < 1 ) {
    CF_FATAL("so=%d] so_recv_line() fails", so);
    goto __end;
  }

  CF_DEBUG("[so=%d] client id = '%s'", so, cid);


  /* proto: client id must be registered in inventory database */
  if ( !(acc = get_client_account(cid)) ) {
    CF_FATAL("[so=%d] client id = '%s' is NOT REGISTERED", so, cid);
    goto __end;
  }


  /* proto: client id must NOT be already connected */

  client_connections_lock();

  if ( (existing_cc = get_client_connection(cid)) ) {
    CF_FATAL("[so=%d][%s] ALREADY CONNECTED VIA so=%d with tunip=%s", so, cid,
        existing_cc->so, existing_cc->tunip);
  }
  else if ( ccarray_size(&g_client_connections) >= ccarray_capacity(&g_client_connections) ) {
    CF_FATAL("[so=%d][%s] BUG: NOT ENOUGH CONNECTION SLOTS. CONNECTION ABORTED.", so, cid);
  }
  else if(!(cc = calloc(1, sizeof(struct client_connection)))) {
    CF_FATAL("[so=%d][%s] FATAL: calloc(%zu bytes) fails. CONNECTION ABORTED.", so, cid,
        sizeof(struct client_connection));
  }
  else {
    cc->so = so;
    strncpy(cc->id, acc->id, sizeof(cc->id) - 1);
    strncpy(cc->tunip, acc->tunip, sizeof(cc->tunip) - 1);
    ccarray_push_back(&g_client_connections, &cc);
    fOk = true;
  }

  client_connections_unlock();

  /* proto: client expect tunip in auth server responce */
  if ( (cb = so_sprintf(so, "%s\n", cc->tunip)) <= 0 ) {

    CF_FATAL("[so=%d][%s] FATAL: so_sprintf(tunip) fails. ABORTING CONNECTION.", so, cid);

    client_connections_lock();
    ccarray_erase_item(&g_client_connections, cc);
    client_connections_unlock();

    // cc memory will freed at __end
    fOk = false;
  }

__end:

  if ( !fOk ) {
    free(cc), cc = NULL;
  }

  return cc;
}

static void * cshell_server_client_thread(void * arg)
{
  int so = (int)(ssize_t)(arg);

  struct client_connection * cc = NULL;

  char msg[1024];
  ssize_t cb;

  pthread_detach(pthread_self());


  /* Check if this client id is allowed and is not already connected,
   * add to global connectons list
   * */
  if ( !(cc = authenticate_connection(so)) ) {
    CF_FATAL("[so=%d] authenticate_connection() fails", so);
    goto __end;
  }

  while ( (cb = so_recv_line(so, msg, sizeof(msg))) ) {
    CF_DEBUG("[%d][%s] msg='%s'", so, cc->id, msg);
  }

__end:

  if ( cc ) {

    client_connections_lock();
    ccarray_erase_item(&g_client_connections, cc);
    client_connections_unlock();

    so_close(cc->so, false);
    free(cc);
  }
  else if ( so != -1 ) {
    so_close(so, false);
  }

  return NULL;
}



int main(int argc, char *argv[])
{
  int i;

  char saddrs[256] = "0.0.0.0";
  uint16_t port = 6010;
  struct sockaddr_in bindaddrs;
  struct sockaddr_in fromaddrs;
  socklen_t fromaddrslen = sizeof(fromaddrs);

  int so1, so2;


  char clients_filename[PATH_MAX] = "cshell-clients.cfg";


  /* configurable flag for background / foreground mode */
  bool daemon_mode = true;

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
      if ( sscanf(argv[i], "%255[^:]:%hu", saddrs, &port) < 1 ) {
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

  if ( !ccarray_init(&g_client_connections, MAX_CLIENT_CONNECTIONS, sizeof(struct client_connection*)) ) {
    CF_FATAL("ccarray_init(client_connections=%zu) fails: %s", MAX_CLIENT_CONNECTIONS, strerror(errno));
    return 1;
  }




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



  if ( (so1 = so_tcp_listen(saddrs, port, &bindaddrs)) == -1 ) {
    CF_FATAL("so_tcp_listen() fails: %s", strerror(errno));
    return 1;
  }


  while ( (so2 = accept(so1, (struct sockaddr*) &fromaddrs, &fromaddrslen)) ) {

    pthread_t pid;
    int status;

    CF_DEBUG("ACCEPTED FROM %s:%u so=%d", inet_ntoa(fromaddrs.sin_addr), ntohs(fromaddrs.sin_port), so2);

    if ( (status = pthread_create(&pid, NULL, cshell_server_client_thread, (void*) (ssize_t) (so2))) ) {
      CF_FATAL("pthread_create(cshell_server_client_thread) fauls: %s", strerror(status));
      so_close(so2, true);
    }
  }

  close(so1);

  return 0;
}

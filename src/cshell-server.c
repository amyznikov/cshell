/*
 * cshell-server.c
 *
 *  Created on: Feb 4, 2018
 */

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include "sockopt.h"
#include "checksum.h"
#include "ccarray.h"
#include "debug.h"


#ifndef CSHELL_VERSION
# define CSHELL_VERSION "0.0.0"
#endif

static const char VERSION[] = CSHELL_VERSION;


static void * cshell_server_client_thread(void * arg)
{
  int so = (int)(ssize_t)(arg);
  char buf[4096] = "";



  recv(so, buf, sizeof(buf)-1, 0);
  CF_CRITICAL("%s\n", buf);

  //char msg[1024] = "HTTP/1.1 404 Not Found\r\n\r\n";



  char msg[1024] = "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/html; charset=ISO-8859-1\r\n"
      "\r\n"
      "<HTML><STRONG> Hello FROM MASTER SERVER!<STRONG>\r\n";

  send(so, msg, strlen(msg), 0);

  sleep(rand() % 7);

  char msg2[1024] = ""
      "<H1> End Of Mesdage</H1>"
      "</HTML>\r\n";

  send(so, msg2, strlen(msg2), 0);

  close(so);

  pthread_detach(pthread_self());
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

    if ( strcmp(argv[i], "--bind") == 0 ) {


      if ( ++i >= argc ) {
        fprintf(stderr, "Missing argument after %s command line switch\n", argv[i - 1]);
      }

      if ( sscanf(argv[i], "%255[^:]:%hu", saddrs, &port) < 1 ) {
        fprintf(stderr, "Invalid argument after %s command line switch\n", argv[i - 1]);
        return 1;
      }
    }

  }



  cf_set_logfilename("stderr");
  cf_set_loglevel(CF_LOG_DEBUG);


  if ((so1 = so_tcp_listen(saddrs, port, &bindaddrs)) == -1 ) {
    CF_FATAL("so_tcp_listen() fails: %s", strerror(errno));
    return 1;
  }


  while ( (so2 = accept(so1, (struct sockaddr*) &fromaddrs, &fromaddrslen)) ) {

    pthread_t pid;
    int status;

    CF_DEBUG("ACCEPTED FROM %s:%u", inet_ntoa(fromaddrs.sin_addr), ntohs(fromaddrs.sin_port));

    if ( (status = pthread_create(&pid, NULL, cshell_server_client_thread, (void*)(ssize_t)(so2))) ) {
      CF_FATAL("pthread_create(cshell_server_client_thread) fauls: %s", strerror(status));
      close(so2);
    }

  }

  close(so1);

  return 0;
}

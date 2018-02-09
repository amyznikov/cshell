/*
 * so-msg.c
 *
 *  Created on: Feb 8, 2018
 *      Author: amyznikov
 */

#include "so-msg.h"
#include <cuttle/debug.h>

int so_sprintf(int so, const char * format, ...)
{
  va_list arglist;
  char * msg = NULL;
  ssize_t cb = 0;
  int n;

  /* sprintf() message into temporary memory buffer */
  va_start(arglist, format);
  if ( (n = vasprintf(&msg, format, arglist)) < 0 ) {
    CF_FATAL("[%d] FATAL: vasprintf() fails: %s", so, strerror(errno));
  }
  va_end(arglist);

  if ( n > 0 && (cb = send(so, msg, n, 0)) != n ) {
    CF_FATAL("[%d] FATAL: send() fails: %s", so, strerror(errno));
  }

  /* Free malloc()-ed memory */
  free(msg);

  return (int)cb;
}


/*
 * Receive single line from socket
 *  fixme : performance issues!!!!
 */
ssize_t so_recv_line(int so, char buf[/*maxsize*/], size_t maxsize)
{
  size_t n = 0;
  ssize_t c;

  while ( n < maxsize - 1 && (c = recv(so, &buf[n], 1, 0)) == 1 ) {
    if ( buf[n++] == '\n' ) {
      --n;
      break;
    }
  }

  buf[n] = 0;

  return c < 0 ? -1 : (ssize_t)n;
}

/*
 * tunnel.c
 *
 *  Created on: Feb 8, 2018
 *      Author: amyznikov
 */

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "tunnel.h"
#include "debug.h"


/**************************************************************************
 * allocate or reconnect to a tun device.
 *  node  : "/dev/net/tun"
 *  flags : IFF_TUN | IFF_NO_PI
 **/
int open_tunnel_device(const char * node, char iface[IFNAMSIZ], int flags)
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



/**************************************************************************
 * iface : tun0
 * addrs : 10.10.100.1
 * mask: "255.255.255.0"
 **/
bool set_tunnel_ip(const char * iface, const char * addrs, const char * mask)
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


/**************************************************************************
 * iface : tun0
 * flags: IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP,  etc
 **/
bool set_tunnel_flags(const char * iface, int flags)
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




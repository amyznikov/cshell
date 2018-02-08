/*
 * tunnel.h
 *
 *  Created on: Feb 8, 2018
 *      Author: amyznikov
 *
 *  Based on
 *    http://backreference.org/2010/03/26/tuntap-interface-tutorial
 */

#pragma once

#ifndef __tunnel_h__
#define __tunnel_h__

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <netinet/in.h>


#ifdef __cplusplus
extern "C" {
#endif


/**************************************************************************
 * allocate or reconnect to a tun device.
 *  node  : "/dev/net/tun"
 *  flags : IFF_TUN | IFF_NO_PI
 **/
int open_tunnel_device(const char * node, char iface[IFNAMSIZ], int flags);

/**************************************************************************
 * iface : tun0
 * addrs : 10.10.100.1
 * mask: "255.255.255.0"
 **/
bool set_tunnel_ip(const char * iface, const char * addrs, const char * mask);


/**************************************************************************
 * iface : tun0
 * flags: IFF_UP | IFF_RUNNING | IFF_MULTICAST | IFF_NOARP,  etc
 **/
bool set_tunnel_flags(const char * iface, int flags);



#ifdef __cplusplus
}
#endif

#endif /* __tunnel_h__ */

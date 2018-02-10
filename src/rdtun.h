/*
 * rdtun.h
 *
 *  Created on: Feb 9, 2018
 *      Author: amyznikov
 */

#pragma once

#ifndef ___rdtun_h___
#define ___rdtun_h___

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif


struct rtable_item {
  struct sockaddr_in src, dst, rsp;
};


bool start_rdtun(int tunfd, const struct sockaddr_in * microsrv_bind_address);

struct rtable_item * rtable_get_rsp(struct in_addr addr, in_port_t port);

#ifdef __cplusplus
}
#endif

#endif /* ___rdtun_h___ */

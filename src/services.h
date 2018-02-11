/*
 * service.h
 *
 *  Created on: Feb 10, 2018
 *      Author: vyevtikhiyev
 */

#pragma once

#ifndef __services_h__
#define __services_h__

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <cuttle/ccarray.h>
#include <linux/if.h>


#ifdef __cplusplus
extern "C" {
#endif

#define SVCT_MAX_SERVICES      256
#define SVCT_MAX_SERVICE_NAME  64
#define SVCT_MAX_IFACE_NAME    64
#define SVCT_MAX_CONNECT_ADDRS 64


struct services_table_item {
  int proto;
  int so;
  char bind_iface[SVCT_MAX_IFACE_NAME];
  char connect_addr[SVCT_MAX_CONNECT_ADDRS];
  char name[SVCT_MAX_SERVICE_NAME];
};

/*
 * Load services table from database, done once at start of this server
 * */
bool load_services_table(const char * filename);

size_t services_table_size(void);
struct services_table_item * services_table_item(size_t index);

/*
 * Find services table entry position for specified external address
 * */
struct services_table_item * find_service_by_bind(int proto, const char * bind_addrs);

#ifdef __cplusplus
}
#endif

#endif /* __services_h__ */


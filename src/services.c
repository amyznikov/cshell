/*
 * services.c
 *
 *  Created on: Feb 10, 2018
 *      Author: vyevtikhiyev
 */

#include <stdio.h>
#include <cuttle/debug.h>
#include "services.h"

static ccarray_t g_services; /* <struct services_table_item> */


size_t services_table_size(void)
{
  return ccarray_size(&g_services);
}

struct services_table_item * services_table_item(size_t index)
{
  return index < ccarray_size(&g_services) ? ccarray_peek(&g_services, index) : NULL;
}


static int parse_protocol_name (const char * protocol_name)
{
  if ( strcasecmp(protocol_name, "tcp")  == 0 ) {
    return IPPROTO_TCP;
  }
  if ( strcasecmp(protocol_name, "udp")  == 0 ) {
    return IPPROTO_UDP;
  }
  if ( strcasecmp(protocol_name, "sctp")  == 0 ) {
    return IPPROTO_SCTP;
  }
  return -1;
}


struct services_table_item * find_service_by_bind(int proto, const char *bind_addrs)
{
  size_t i, n;
  for ( i = 0, n = ccarray_size(&g_services); i < n; ++i ) {
    struct services_table_item * item = ccarray_peek(&g_services, i);
    if ( item->proto == proto && strcmp(item->bind_iface,bind_addrs) == 0 ) {
      return item;
    }
  }
  return NULL;
}

//struct services_table_item * find_service_by_int_addr(int proto, const char *int_addr, uint16_t int_port)
//{
//  size_t i, n;
//  for ( i = 0, n = ccarray_size(&g_services); i < n; ++i ) {
//    struct services_table_item * item = ccarray_peek(&g_services, i);
//    if ( item->proto == proto && item->connect_port == int_port && strcmp(item->bind_iface, int_addr) == 0 ) {
//      return item;
//    }
//  }
//  return NULL;
//}



bool load_services_table(const char * filename)
{

  char line[1024];

  FILE * fp = NULL;
  int line_number = 0;

  struct services_table_item * existing_item;


  // try to open the file name provided
  if ( !(fp = fopen(filename, "r")) ) {
    CF_FATAL("fopen(%s) fails: %s", filename, strerror(errno));
    return false;
  }

  CF_DEBUG("Opened");

  ccarray_cleanup(&g_services);
  ccarray_init(&g_services, SVCT_MAX_SERVICES, sizeof(struct services_table_item));

  while ( ccarray_size(&g_services) < ccarray_capacity(&g_services) && fgets(line, sizeof(line) - 1, fp) ) {

    struct services_table_item item;
    char protocol[16] = "";

#if SVCT_MAX_SERVICE_NAME < 64
# error "MAX_SERVICE_NAME is too small for expected format, please update the format string below"
#endif
#if SVCT_MAX_IFACE_NAME < 64
# error "MAX_IFACE_NAME is too small for expected format, please update the format string below"
#endif
#if SVCT_MAX_CONNECT_ADDRS < 64
# error "SVCT_MAX_CONNECT_ADDRS is too small for expected format, please update the format string below"
#endif
    ++line_number;

    memset(&item, 0, sizeof(item));
    item.so = -1;

    if ( sscanf(line, " %15s %63s %63s %64s", protocol, item.bind_iface, item.connect_addr, item.name) != 4 ) {
      CF_WARNING("Parsing error on line %d of '%s', line inored", line_number, filename);
      continue;
    }

    if ( *protocol == '#' || *protocol == '/' ) {
      continue;
    }

    if ( (item.proto = parse_protocol_name(protocol)) < 0 ) {
      CF_WARNING("Can't parse protocol name '%s' at line %d of %s, line ignored",
          protocol, line_number, filename);
      continue;
    }

    if ( !(existing_item = find_service_by_bind(item.proto, item.bind_iface)) ) {
      ccarray_push_back(&g_services, &item);
    }
    else {

      CF_WARNING("Services_table entry update for external address %s/%s at line %d",
          protocol, item.bind_iface, line_number);

      strcpy(existing_item->connect_addr, item.connect_addr);
      strcpy(existing_item->name, item.name);
    }
  }

  if ( fp ) {
    fclose(fp);
  }

  CF_DEBUG("Closed");
  return ccarray_size(&g_services) > 0;
}


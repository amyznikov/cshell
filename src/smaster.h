/*
 * smaster.h
 *
 *  Created on: Feb 9, 2018
 *      Author: amyznikov
 */

#pragma once

#ifndef __smaster_h__
#define __smaster_h__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <cuttle/corpc/channel.h>
#include "corpc-msg.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * smaster messages
 * */



//////////////////////////////////////////////////////////////////////////////////////////
// AUTHENTICATION SERVICE MESSAGES

# define SM_MAX_CLIENT_ID  64
typedef
struct auth_request {
  char cid[SM_MAX_CLIENT_ID];
} auth_request;

#define SM_MAX_TUNIP  16
typedef
struct auth_responce {
  char tunip[SM_MAX_TUNIP];
} auth_responce;


static inline bool corpc_pack_auth_request(const struct auth_request * request, corpc_msg * msg) {
  msg->data = strdup(request->cid);
  msg->size = strlen(msg->data) + 1;
  return true;
}

static inline bool corpc_unpack_auth_request(const corpc_msg * msg, struct auth_request * request) {
  strncpy(request->cid, msg->data, sizeof(request->cid)-1);
  return true;
}

static inline bool corpc_pack_auth_responce(const struct auth_responce * responce, corpc_msg * msg) {
  msg->data = strdup(responce->tunip);
  msg->size = strlen(msg->data) + 1;
  return true;
}

static inline bool corpc_unpack_auth_responce(const corpc_msg * msg, struct auth_responce * responce) {
  strncpy(responce->tunip, msg->data, sizeof(responce->tunip)-1);
  return true;
}

static inline bool corpc_stream_send_auth_request(corpc_stream * st, const struct auth_request * request)
{
  corpc_msg msg;
  bool fok = false;
  corpc_msg_init(&msg);
  if ( corpc_pack_auth_request(request, &msg) ) {
    fok = corpc_stream_write(st, msg.data, msg.size);
  }
  corpc_msg_clean(&msg);
  return fok;
}

static inline bool corpc_stream_recv_auth_request(corpc_stream * st, struct auth_request * request)
{
  corpc_msg msg;
  bool fok = false;
  corpc_msg_init(&msg);
  if ( (msg.size = corpc_stream_read(st, &msg.data)) > 0 ) {
    fok = corpc_unpack_auth_request(&msg, request);
  }
  corpc_msg_clean(&msg);
  return fok;
}

static inline bool corpc_stream_send_auth_responce(corpc_stream * st, const struct auth_responce * responce)
{
  corpc_msg msg;
  bool fok = false;
  corpc_msg_init(&msg);
  if ( corpc_pack_auth_responce(responce, &msg) ) {
    fok = corpc_stream_write(st, msg.data, msg.size);
  }
  corpc_msg_clean(&msg);
  return fok;
}

static inline bool corpc_stream_recv_auth_responce(corpc_stream * st, struct auth_responce * responce)
{
  corpc_msg msg;
  bool fok = false;
  corpc_msg_init(&msg);
  if ( (msg.size = corpc_stream_read(st, &msg.data)) > 0 ) {
    fok = corpc_unpack_auth_responce(&msg, responce);
  }
  corpc_msg_clean(&msg);
  return fok;
}


//////////////////////////////////////////////////////////////////////////////////////////
// RESOURCE ALLOCATION SERVICE MESSAGES

# define SM_MAX_RESOURCE_ID  128
typedef
struct resource_request {
  uint64_t ticket; /* 'mandat' */
  char resource_id[SM_MAX_RESOURCE_ID];
} resource_request;


#define SM_MAX_ACTUAL_RESOURCE_ADDRESS 16
typedef
struct resource_responce {
  uint64_t ticket; /* 'mandat' */
  char actual_resource_location[SM_MAX_ACTUAL_RESOURCE_ADDRESS];
} resource_responce;


static inline bool corpc_pack_resource_request(const struct resource_request * request, corpc_msg * msg) {
  size_t resource_id_length = strlen(request->resource_id);
  msg->size = resource_id_length + 1 + sizeof(request->ticket);
  msg->data = malloc(msg->size);
  strcpy(msg->data, request->resource_id);
  memcpy(((char*)msg->data) + resource_id_length + 1, &request->ticket, sizeof(request->ticket));
  return true;
}

static inline bool corpc_unpack_resource_request(const corpc_msg * msg, struct resource_request * request) {
  size_t resource_id_length = strlen(msg->data);
  strcpy(request->resource_id, msg->data);
  memcpy(&request->ticket, ((char*)msg->data) + resource_id_length + 1, sizeof(request->ticket));
  return true;
}


static inline bool corpc_pack_resource_responce(const struct resource_responce * responce, corpc_msg * msg) {
  size_t resource_id_length = strlen(responce->actual_resource_location);
  msg->size = resource_id_length + 1 + sizeof(responce->ticket);
  msg->data = malloc(msg->size);
  strcpy(msg->data, responce->actual_resource_location);
  memcpy(((char*)msg->data) + resource_id_length + 1, &responce->ticket, sizeof(responce->ticket));
  return true;
}

static inline bool corpc_unpack_resource_responce(const corpc_msg * msg, struct resource_responce * responce) {
  size_t resource_id_length = strlen(msg->data);
  strcpy(responce->actual_resource_location, msg->data);
  memcpy(&responce->ticket, ((char*)msg->data) + resource_id_length + 1, sizeof(responce->ticket));
  return true;
}



static inline bool corpc_stream_send_resource_request(corpc_stream * st, const struct resource_request * request)
{
  corpc_msg msg;
  bool fok = false;
  corpc_msg_init(&msg);
  if ( corpc_pack_resource_request(request, &msg) ) {
    fok = corpc_stream_write(st, msg.data, msg.size);
  }
  corpc_msg_clean(&msg);
  return fok;
}

static inline bool corpc_stream_recv_resource_request(corpc_stream * st, struct resource_request * request)
{
  corpc_msg msg;
  bool fok = false;
  corpc_msg_init(&msg);
  if ( (msg.size = corpc_stream_read(st, &msg.data)) > 0 ) {
    fok = corpc_unpack_resource_request(&msg, request);
  }
  corpc_msg_clean(&msg);
  return fok;
}


static inline bool corpc_stream_send_resource_responce(corpc_stream * st, const struct resource_responce * responce)
{
  corpc_msg msg;
  bool fok = false;
  corpc_msg_init(&msg);
  if ( corpc_pack_resource_responce(responce, &msg) ) {
    fok = corpc_stream_write(st, msg.data, msg.size);
  }
  corpc_msg_clean(&msg);
  return fok;
}

static inline bool corpc_stream_recv_resource_responce(corpc_stream * st, struct resource_responce * responce)
{
  corpc_msg msg;
  bool fok = false;
  corpc_msg_init(&msg);
  if ( (msg.size = corpc_stream_read(st, &msg.data)) > 0 ) {
    fok = corpc_unpack_resource_responce(&msg, responce);
  }
  corpc_msg_clean(&msg);
  return fok;
}



#ifdef __cplusplus
}
#endif

#endif /* __smaster_h__ */

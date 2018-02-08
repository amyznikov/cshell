/*
 * so-msg.h
 *
 *  Created on: Feb 8, 2018
 *      Author: amyznikov
 */

#pragma once

#ifndef ___so_msg_h___
#define ___so_msg_h___

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/socket.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * printf()-like socket send
 * @return      count of bytes sent, -1 on error
 * attributes are not allowed on a function-definition, so, provide prototype here
 */
int so_sprintf(int so, const char * text, ...) \
    __attribute__ ((__format__ (__printf__, 2, 3)));


/*
 * Receive single line from socket
 *  fixme : performance issues!!!!
 */
ssize_t so_recv_line(int so, char buf[/*maxsize*/], size_t maxsize);


#ifdef __cplusplus
}
#endif

#endif /* ___so_msg_h___ */


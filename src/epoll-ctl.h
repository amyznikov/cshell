/*
 * epoll-ctl.h
 *
 *  Created on: Feb 8, 2018
 *      Author: amyznikov
 */

#pragma once

#ifndef ___epoll_ctl_h___
#define ___epoll_ctl_h___

#include <sys/epoll.h>


#ifdef __cplusplus
extern "C" {
#endif


static inline bool epoll_add(int epollfd, int so, uint32_t events)
{
  int status = epoll_ctl(epollfd, EPOLL_CTL_ADD, so,
      &(struct epoll_event ) {
            .data.fd = so,
            .events = events
          });

  return status == 0;
}




static inline bool epoll_remove(int epollfd, int so)
{
  return epoll_ctl(epollfd, EPOLL_CTL_DEL, so, NULL) == 0;
}



#ifdef __cplusplus
}
#endif

#endif /* ___epoll_ctl_h___ */

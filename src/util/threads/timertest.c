/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/
/**
 * @file util/threads/timertest.c
 * @brief testcase for util/threads/timer.c; also measures how
 *  precise the timers are.  Expect values between 10 and 20 ms on
 *  modern machines.
 */

#include "gnunet_util.h"
#include "platform.h"

#define VERBOSE NO

static int check() {
  cron_t now;
  cron_t last;
  TIME_T tnow;
  TIME_T tlast;
  int i;
  unsigned long long cumDelta;

  /* test that time/cronTime are monotonically
     increasing;
     measure precision of sleep and report;
     test that sleep is interrupted by signals; */
  last = now = get_time();
  while (now == last)
    now = get_time();
  if (now < last)
    return 1;
  tnow = tlast = TIME(NULL);
  while (tnow == tlast)
    tnow = TIME(NULL);
  if (tnow < tlast)
    return 2;
  cumDelta = 0;
#define INCR 47
#define MAXV 1500
  for (i=0;i<MAXV;i+=INCR) {
    last = get_time();
    PTHREAD_SLEEP(cronMILLIS * i);
    now = get_time();
#if VERBOSE
    fprintf(stderr,
	    "%4llu ms requested, got: %4llu ms\n",
	    i * cronMILLIS,
	    (now - last));
#endif
    if (last + cronMILLIS * i < now)
      cumDelta += (now - (last+cronMILLIS*i));
    else
      cumDelta += ((last+cronMILLIS*i) - now);
  }
  FPRINTF(stdout,
	  "Sleep precision: %llu ms. ",
	  cumDelta / cronMILLIS / (MAXV/INCR));
  if (cumDelta <= 10 * cronMILLIS * MAXV / INCR)
    fprintf(stdout,
	    "Timer precision is excellent.\n");
  else if (cumDelta <= 50 * cronMILLIS * MAXV / INCR) /* 50 ms average deviation */
    fprintf(stdout,
	    "Timer precision is good.\n");
  else if (cumDelta > 250 * cronMILLIS * MAXV / INCR)
    fprintf(stdout,
	    "Timer precision is awful.\n");
  else
    fprintf(stdout,
	    "Timer precision is acceptable.\n");
  return 0;
}

int main(int argc,
	 char * argv[]){
  int ret;

  ret = check();

  return ret;
}

/* end of timertest.c */

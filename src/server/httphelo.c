/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004 Christian Grothoff (and other contributing authors)

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
 * @file server/httphelo.c
 * @brief HOSTLISTURL support
 *
 * @author Christian Grothoff
 */

#include "gnunet_core.h"

#include "httphelo.h"
#include "keyservice.h"
#include "knownhosts.h"

#define TCP_HTTP_PORT 80
#define HTTP_URL "http://"
#define GET_COMMAND "GET http://%s%s HTTP/1.0\r\n\r\n"

#define HELO_HELPER_TABLE_START_SIZE 128

#define DEBUG_HELOEXCHANGE NO

#if VERBOSE_STATS
static int stat_helo_received_via_http;
#endif

/* is the HELO processing still ongoing from previous downloadHostlist()? */
static Semaphore * hostlistDownload; 

/**
 * The HTTP proxy (optional)
 */
static struct sockaddr_in theProxy;


void initHttpHelo() {
  char *proxy, *proxyPort;
  struct hostent *ip;

#if VERBOSE_STATS
  stat_helo_received_via_http 
    = statHandle(_("# HELO messages received from http server"));
#endif
  proxy = getConfigurationString("GNUNETD", 
				 "HTTP-PROXY");
  if (proxy != NULL) {
    ip = GETHOSTBYNAME(proxy);
    if (ip == NULL) {
      LOG(LOG_ERROR, 
	  _("Could not resolve name of HTTP proxy '%s'. Trying without a proxy.\n"),
	  proxy);
      theProxy.sin_addr.s_addr = 0;
    } else {
      theProxy.sin_addr.s_addr 
	= ((struct in_addr *)ip->h_addr)->s_addr;
      proxyPort = getConfigurationString("GNUNETD",
					 "HTTP-PROXY-PORT");
      if (proxyPort == NULL) {
	theProxy.sin_port = htons(8080);
      } else {
	theProxy.sin_port = htons(atoi(proxyPort));
	FREE(proxyPort);
      }
    }
    FREE(proxy);
  } else {
    theProxy.sin_addr.s_addr = 0;
  }
  hostlistDownload = SEMAPHORE_NEW(1);
}

void doneHttpHelo() {
  /* FIXME: to be ultimately clean, we would here have to go through
     the cron jobs, find the one matching receiveHeloDeferred (if
     exists) and free the hcq->helos array.  Anyway, this would
     require extending the cron API first...  For now, we have the
     following possible one-shot memory leak (possible valgrind
     output):

     808 bytes in 1 blocks are possibly lost in loss record 5 of 6
     at 0x3C02140D: malloc (vg_replace_malloc.c:105)
     by 0x3C03FA32: xmalloc_unchecked_ (xmalloc.c:86)
     by 0x3C03F9EC: xmalloc_ (xmalloc.c:72)
     by 0x3C03FC7E: xgrow_ (xmalloc.c:250)
     by 0x8059CC6: receiveHeloDeferred (httphelo.c:122)
     by 0x3C02F2FF: runJob (cron.c:550)
     by 0x3C02F3FD: cron (cron.c:585)
     by 0x3C0C2110: thread_wrapper (vg_libpthread.c:837)
     by 0xB800FACC: do__quit (vg_scheduler.c:1792)    
  */
  SEMAPHORE_FREE(hostlistDownload);
}



typedef struct {
  /* HELOs received from the http server */
  p2p_HEADER ** helos;
  
  /* number of items in helos */
  int helosCount;
} HELOHelperContext;

/* prototype, either in heloexchange.c or 
   gnunet-transport-check.c */
int receivedHELO(p2p_HEADER * message);

static void receiveHeloDeferred(HELOHelperContext * hcq) {
  int rndidx;
  p2p_HEADER * msg;

  if ( (NULL == hcq) || 
       (hcq->helosCount==0) ) {
    BREAK();
    return;
  }
  /* select HELO by random */
  rndidx = randomi(hcq->helosCount);
#if DEBUG_HELOEXCHANGE
  LOG(LOG_DEBUG,
      "%s chose HELO %d of %d\n",
      __FUNCTION__,
      rndidx, hcq->helosCount);
#endif
  msg = hcq->helos[rndidx];
  hcq->helos[rndidx]
    = hcq->helos[hcq->helosCount-1];
  GROW(hcq->helos,
       hcq->helosCount,
       hcq->helosCount-1);
  
  receivedHELO(msg);
  FREE(msg);
    
  if (hcq->helosCount > 0) { /* schedule next helo */ 
    int load;
    int nload;
    load = getCPULoad();
    nload = getNetworkLoadUp();
    if (nload > load)
      load = nload;
    nload = getNetworkLoadDown();
    if (nload > load)
      load = nload;
    addCronJob((CronJob)&receiveHeloDeferred,		 
	       50 + randomi((load+1)*(load+1)), 
	       0,
	       hcq);
  } else { /* all HELOs processed, its ok to go again */
#if DEBUG_HELOEXCHANGE
    LOG(LOG_DEBUG, 
        "%s processed all HELOs\n",
	__FUNCTION__);
#endif
    FREE(hcq);
    SEMAPHORE_UP(hostlistDownload);
  }
}

typedef struct {
  p2p_HEADER ** helos;
  int helosCount;
  int helosLen;
} HeloListClosure;

static void downloadHostlistCallback(HELO_Message * helo,
				     HeloListClosure * cls) {
  if (cls->helosCount >= cls->helosLen) 
    GROW(cls->helos,
	 cls->helosLen,
	 cls->helosLen + HELO_HELPER_TABLE_START_SIZE);
  cls->helos[cls->helosCount++] = MALLOC(ntohs(helo->header.size));
  memcpy(cls->helos[cls->helosCount-1],
	 helo,
	 ntohs(helo->header.size));
}

static void postProcessHelos(HeloListClosure * cls) {
  if (cls->helosCount > 0) {
    HELOHelperContext * hcq;
    
    hcq = MALLOC(sizeof(HELOHelperContext));
    
    /* truncate table */
    GROW(cls->helos,
         cls->helosLen,
	 cls->helosCount);
    hcq->helos = cls->helos;
    hcq->helosCount = cls->helosCount;
   
    addCronJob((CronJob)&receiveHeloDeferred,
	       2 * cronSECONDS,
	       0,
	       hcq);
  } else {
#if DEBUG_HELOEXCHANGE
    LOG(LOG_DEBUG, 
        "%s has no HELOs to process\n",
	__FUNCTION__);
#endif
    SEMAPHORE_UP(hostlistDownload);
  }
  cls->helosCount = 0;
  cls->helosLen = 0;
  cls->helos = NULL;
}

/**
 * Download hostlist from the web and call method
 * on each HELO.
 */
void downloadHostlistHelper(char * url,
			    HELO_Callback callback,
			    void * arg) {
  unsigned short port;
  char * hostname;
  char * filename;
  unsigned int curpos;
  struct hostent *ip_info;
  struct sockaddr_in soaddr;
  int sock;
  int ret;
  char * command;
  cron_t start;
  char c;
  char * buffer;
  size_t n;

  port = TCP_HTTP_PORT;

#if DEBUG_HELOEXCHANGE
  LOG(LOG_INFO,
      _("Trying to download a hostlist from '%s'.\n"),
      url);
#endif
    
 
  if (0 != strncmp(HTTP_URL, url, strlen(HTTP_URL)) ) {
    LOG(LOG_WARNING, 
	_("Invalid URL '%s' (must begin with '%s')\n"), 
	url, 
	HTTP_URL);
    return;
  }
  curpos = strlen(HTTP_URL);
  hostname = &url[curpos];
  while ( (curpos < strlen(url)) &&
	  (url[curpos] != '/') )
    curpos++;
  if (curpos == strlen(url))
    filename = STRDUP("/");
  else 
    filename = STRDUP(&url[curpos]);
  url[curpos] = '\0'; /* terminator for hostname */  

  sock = SOCKET(PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    LOG(LOG_ERROR,
	_("'%s' failed at %s:%d with error: '%s'.\n"),
	"socket",
	__FILE__, __LINE__,
	STRERROR(errno));
    FREE(filename);
    return;
  }

  /* Do we need to connect through a proxy? */
  if (theProxy.sin_addr.s_addr == 0) {
    ip_info = GETHOSTBYNAME(hostname);
    if (ip_info == NULL) {
      LOG(LOG_WARNING,
	  _("Could not download list of peer contacts, host '%s' unknown.\n"),
	  hostname);
      FREE(filename);
      return;
    }
    
    soaddr.sin_addr.s_addr 
      = ((struct in_addr*)(ip_info->h_addr))->s_addr;
    soaddr.sin_port 
      = htons(TCP_HTTP_PORT);
  } else {
    soaddr.sin_addr.s_addr 
      = theProxy.sin_addr.s_addr;
    soaddr.sin_port 
      = theProxy.sin_port;
  }
  soaddr.sin_family = AF_INET;

  if (CONNECT(sock, 
	      (struct sockaddr*)&soaddr, 
	      sizeof(soaddr)) < 0) {
    LOG(LOG_WARNING,
	_("'%s' to '%s' failed at %s:%d with error: %s\n"),
	"connect",
	hostname,
	__FILE__, __LINE__,
	STRERROR(errno));
    FREE(filename);
    CLOSE(sock);
    return;
  }
  
  n = strlen(filename) + strlen(GET_COMMAND) + strlen(hostname) + 1;
  command = MALLOC(n);
  SNPRINTF(command, 
	   n,
	   GET_COMMAND,
	   hostname,
	   filename);
  FREE(filename);
  curpos = strlen(command)+1;
  curpos = SEND_BLOCKING_ALL(sock,
			     command,
			     curpos);
  if (SYSERR == (int)curpos) {
    LOG(LOG_WARNING,
	_("'%s' to '%s' failed at %s:%d with error: %s\n"),
	"send",
	hostname,
	__FILE__, __LINE__,
	STRERROR(errno));
    FREE(command);
    CLOSE(sock);
    return;
  }
  FREE(command);
  cronTime(&start);

  /* we first have to read out the http_response*/
  /* it ends with four line delimiters: "\r\n\r\n" */
  curpos = 0;
  while (curpos < 4) {
    int success;
    
    if (start + 300 * cronSECONDS < cronTime(NULL))
      break; /* exit after 5m */
    success = RECV_NONBLOCKING(sock,
			       &c,
			       sizeof(c),
			       &ret);
    if ( success == NO ) {
      gnunet_util_sleep(100 * cronMILLIS);
      continue;    
    }
    if (ret <= 0)
      break; /* end of transmission or error */
    if ((c=='\r') || (c=='\n')) 
      curpos += ret;
    else 
      curpos=0;    
  }

  if (curpos < 4) { /* we have not found it */
    LOG(LOG_WARNING, 
	_("Parsing HTTP response for URL '%s' failed.\n"),
	url);
    CLOSE(sock);
    return;
  }

  buffer = MALLOC(MAX_BUFFER_SIZE);
  while (1) {
    HELO_Message * helo;
    
    helo = (HELO_Message*) &buffer[0];
    helo->header.requestType = htons(p2p_PROTO_HELO);

    if (start + 300 * cronSECONDS < cronTime(NULL))
      break; /* exit after 300s */
    curpos = 0;
    helo->senderAddressSize = 0;
    while (curpos < HELO_Message_size(helo)) {
      int success;
      
      if (start + 300 * cronSECONDS < cronTime(NULL))
	break; /* exit after 300s */
      success = RECV_NONBLOCKING(sock,
			         &((char*)helo)[curpos],
			         HELO_Message_size(helo)-curpos,
			         &ret);      
      if ( success == NO ) {
        gnunet_util_sleep(20);
	continue;
      }
      if (ret <= 0)
	break; /* end of file or error*/
      if (HELO_Message_size(helo) >= MAX_BUFFER_SIZE) 
	break; /* INVALID! Avoid overflow! */      
      curpos += ret;
    }
    if (curpos != HELO_Message_size(helo)) {
      if (curpos != 0)
	LOG(LOG_WARNING,
	    _("Parsing HELO from '%s' failed.\n"),
	    url);
      break;
    }
    helo->header.size = htons(HELO_Message_size(helo));
#if DEBUG_HELOEXCHANGE
    LOG(LOG_CRON,
	".");
#endif
#if VERBOSE_STATS
    statChange(stat_helo_received_via_http, 1);
#endif
    callback(helo,
	     arg);
  }
    
  FREE(buffer);
  CLOSE(sock);  
#if DEBUG_HELOEXCHANGE
  LOG(LOG_INFO,
      _("Completed '%s' (%ds before timeout).\n"),
      __FUNCTION__,
      (int)(start + 300 * cronSECONDS - cronTime(NULL))/cronSECONDS);
#endif
}

void downloadHostlist() {
  HeloListClosure arg;
  char * url;
  int i;
  int cnt;
 
  url = getConfigurationString("GNUNETD",
			       "HOSTLISTURL");
  if (url == NULL) {
#if DEBUG_HELOEXCHANGE
    LOG(LOG_CRON,
	"Exiting '%s': no URL specified in configuration file.\n",
	__FUNCTION__);
#endif
    return;
  }
  arg.helosCount = 0;
  arg.helosLen = 0;
  arg.helos = NULL;
  if (SYSERR == SEMAPHORE_DOWN_NONBLOCKING(hostlistDownload)) {
    LOG(LOG_INFO,
	_("Will not download hostlist until HELOs downloaded previously are all processed.\n"));
    return;
  }
  cnt = 1;
  i = strlen(url);
  while (i > 0) {
    i--;
    if (url[i] == ' ') 
      cnt++;
  }
  cnt = randomi(cnt); /* pick random hostlist of the pack */
  i = strlen(url);
  while (i > 0) {
    i--;
    if (url[i] == ' ') {
      if (cnt > 0) {
	url[i] = '\0';
	cnt--;
	continue;
      }
      downloadHostlistHelper(&url[i+1],
			     (HELO_Callback)&downloadHostlistCallback,
			     &arg);
      postProcessHelos(&arg);
      return;
    }
  } 
  downloadHostlistHelper(&url[0],
			 (HELO_Callback)&downloadHostlistCallback,
			 &arg);
  postProcessHelos(&arg);
  FREE(url);
}

/* end of httphelo.c */

/**
 * @file upnp.c UPnP Implementation
 * @ingroup core
 *
 * gaim
 *
 * Gaim is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "platform.h"
#include "xmlnode.h"
#include "util.h"
#include "upnp.h"
#include "error.h"
#include "ip.h"

#include <curl/curl.h>

#define TRUE YES
#define FALSE NO
#define g_return_if_fail(a) if(!(a)) return;
#define g_return_val_if_fail(a, val) if(!(a)) return (val);

#define HTTP_OK "200 OK"
#define NUM_UDP_ATTEMPTS 2
#define HTTPMU_HOST_ADDRESS "239.255.255.250"
#define HTTPMU_HOST_PORT 1900
#define SEARCH_REQUEST_DEVICE "urn:schemas-upnp-org:service:%s"
#define SEARCH_REQUEST_STRING \
	"M-SEARCH * HTTP/1.1\r\n" \
	"MX: 2\r\n" \
	"HOST: 239.255.255.250:1900\r\n" \
	"MAN: \"ssdp:discover\"\r\n" \
	"ST: urn:schemas-upnp-org:service:%s\r\n" \
	"\r\n"
#define WAN_IP_CONN_SERVICE "WANIPConnection:1"
#define WAN_PPP_CONN_SERVICE "WANPPPConnection:1"
#define HTTP_POST_SOAP_HEADER \
        "SOAPACTION: \"urn:schemas-upnp-org:service:%s#%s\""
#define HTTP_POST_SIZE_HEADER "CONTENT-LENGTH: %u"
#define SOAP_ACTION \
	"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" \
	"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " \
		"s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n" \
	  "<s:Body>\r\n" \
	    "<u:%s xmlns:u=\"urn:schemas-upnp-org:service:%s\">\r\n" \
	      "%s" \
	    "</u:%s>\r\n" \
	  "</s:Body>\r\n" \
	"</s:Envelope>"
#define PORT_MAPPING_LEASE_TIME "0"
#define PORT_MAPPING_DESCRIPTION "GNUNET_UPNP_PORT_FORWARD"
#define ADD_PORT_MAPPING_PARAMS \
	"<NewRemoteHost></NewRemoteHost>\r\n" \
	"<NewExternalPort>%i</NewExternalPort>\r\n" \
	"<NewProtocol>%s</NewProtocol>\r\n" \
	"<NewInternalPort>%i</NewInternalPort>\r\n" \
	"<NewInternalClient>%s</NewInternalClient>\r\n" \
	"<NewEnabled>1</NewEnabled>\r\n" \
	"<NewPortMappingDescription>" \
	PORT_MAPPING_DESCRIPTION \
	"</NewPortMappingDescription>\r\n" \
	"<NewLeaseDuration>" \
	PORT_MAPPING_LEASE_TIME \
	"</NewLeaseDuration>\r\n"
#define DELETE_PORT_MAPPING_PARAMS \
	"<NewRemoteHost></NewRemoteHost>\r\n" \
	"<NewExternalPort>%i</NewExternalPort>\r\n" \
	"<NewProtocol>%s</NewProtocol>\r\n"

typedef enum {
  GAIM_UPNP_STATUS_UNDISCOVERED = -1,
  GAIM_UPNP_STATUS_UNABLE_TO_DISCOVER,
  GAIM_UPNP_STATUS_DISCOVERING,
  GAIM_UPNP_STATUS_DISCOVERED
} GaimUPnPStatus;

typedef struct {
  GaimUPnPStatus status;
  char* control_url;
  const char * service_type;
  char publicip[16];
} GaimUPnPControlInfo;

typedef struct {
  const char * service_type;
  char * full_url;
  char * buf;
  unsigned int buf_len;
  int sock;
} UPnPDiscoveryData;

static GaimUPnPControlInfo control_info = {
  GAIM_UPNP_STATUS_UNDISCOVERED, 
  NULL,
  NULL,
  "",
};

/**
 * This is the signature used for functions that act as a callback
 * to CURL.
 */
typedef size_t (*GaimUtilFetchUrlCallback)(void *url_data,
					   size_t size,
					   size_t nmemb,
					   void * user_data);



static char * g_strstr_len (const char *haystack,
			    int haystack_len,
			    const char *needle) {
  int i;

  g_return_val_if_fail (haystack != NULL, NULL);
  g_return_val_if_fail (needle != NULL, NULL);

  if (haystack_len < 0)
    return strstr (haystack, needle);
  else
    {
      const char *p = haystack;
      int needle_len = strlen (needle);
      const char *end = haystack + haystack_len - needle_len;

      if (needle_len == 0)
       return (char *)haystack;

      while (*p && p <= end)
       {
         for (i = 0; i < needle_len; i++)
           if (p[i] != needle[i])
             goto next;

         return (char *)p;

       next:
         p++;
       }
    }

  return NULL;
}

static int
gaim_upnp_compare_device(const xmlnode* device, 
			 const char* deviceType) {
  xmlnode * deviceTypeNode = xmlnode_get_child(device, "deviceType");
  char * tmp;
  int ret;
  
  if (deviceTypeNode == NULL) 
    return FALSE;	
  tmp = xmlnode_get_data(deviceTypeNode);
  ret = !strcasecmp(tmp, deviceType);
  FREE(tmp);  
  return ret;
}

static int
gaim_upnp_compare_service(const xmlnode* service, 
			  const char* serviceType) {
  xmlnode * serviceTypeNode;
  char *tmp;
  int ret;
  
  if (service == NULL) 
    return FALSE;	
  serviceTypeNode = xmlnode_get_child(service, "serviceType");
  if(serviceTypeNode == NULL) 
    return FALSE;
  tmp = xmlnode_get_data(serviceTypeNode);
  ret = !strcasecmp(tmp, serviceType);
  FREE(tmp); 
  return ret;
}

static char*
gaim_upnp_parse_description_response(const char* httpResponse, 
				     size_t len,
				     const char* httpURL,
				     const char* serviceType) {
  char *xmlRoot, *baseURL, *controlURL, *service;
  xmlnode *xmlRootNode, *serviceTypeNode, *controlURLNode, *baseURLNode;
  char *tmp;
  
  /* find the root of the xml document */
  xmlRoot = g_strstr_len(httpResponse, len, "<root");
  if (xmlRoot == NULL)
    return NULL;  
  if (g_strstr_len(httpResponse, len, "</root") == NULL) 
    return NULL;  

  /* create the xml root node */
  xmlRootNode = xmlnode_from_str(xmlRoot,
				 len - (xmlRoot - httpResponse));
  if (xmlRootNode == NULL) 
    return NULL;  
  
  /* get the baseURL of the device */
  baseURLNode = xmlnode_get_child(xmlRootNode, "URLBase");
  if (baseURLNode != NULL) {
    baseURL = xmlnode_get_data(baseURLNode);
  } else {
    baseURL = STRDUP(httpURL);
  }
 
  /* get the serviceType child that has the service type as its data */  
  /* get urn:schemas-upnp-org:device:InternetGatewayDevice:1 and its devicelist */
  serviceTypeNode = xmlnode_get_child(xmlRootNode, "device");
  while(!gaim_upnp_compare_device(serviceTypeNode,
				  "urn:schemas-upnp-org:device:InternetGatewayDevice:1") &&
	serviceTypeNode != NULL) {
    serviceTypeNode = xmlnode_get_next_twin(serviceTypeNode);
  }
  if(serviceTypeNode == NULL) {
    FREE(baseURL);
    xmlnode_free(xmlRootNode);
    return NULL;
  }
  serviceTypeNode = xmlnode_get_child(serviceTypeNode, "deviceList");
  if(serviceTypeNode == NULL) {
    FREE(baseURL);
    xmlnode_free(xmlRootNode);
    return NULL;
  }
  
  /* get urn:schemas-upnp-org:device:WANDevice:1 and its devicelist */
  serviceTypeNode = xmlnode_get_child(serviceTypeNode, "device");
  while(!gaim_upnp_compare_device(serviceTypeNode,
				  "urn:schemas-upnp-org:device:WANDevice:1") &&
	serviceTypeNode != NULL) {
    serviceTypeNode = xmlnode_get_next_twin(serviceTypeNode);
  }
  if(serviceTypeNode == NULL) {
    FREE(baseURL);
    xmlnode_free(xmlRootNode);
    return NULL;
  }
  serviceTypeNode = xmlnode_get_child(serviceTypeNode, "deviceList");
  if(serviceTypeNode == NULL) {
    FREE(baseURL);
    xmlnode_free(xmlRootNode);
    return NULL;
  }
  
  /* get urn:schemas-upnp-org:device:WANConnectionDevice:1 and its servicelist */
  serviceTypeNode = xmlnode_get_child(serviceTypeNode, "device");
  while(serviceTypeNode && !gaim_upnp_compare_device(serviceTypeNode,
						     "urn:schemas-upnp-org:device:WANConnectionDevice:1")) {
    serviceTypeNode = xmlnode_get_next_twin(serviceTypeNode);
  }
  if(serviceTypeNode == NULL) {
    FREE(baseURL);
    xmlnode_free(xmlRootNode);
    return NULL;
  }
  serviceTypeNode = xmlnode_get_child(serviceTypeNode, "serviceList");
  if(serviceTypeNode == NULL) {
    FREE(baseURL);
    xmlnode_free(xmlRootNode);
    return NULL;
  }
  
  /* get the serviceType variable passed to this function */
  service = g_strdup_printf(SEARCH_REQUEST_DEVICE, serviceType);
  serviceTypeNode = xmlnode_get_child(serviceTypeNode, "service");
  while(!gaim_upnp_compare_service(serviceTypeNode, service) &&
	serviceTypeNode != NULL) {
    serviceTypeNode = xmlnode_get_next_twin(serviceTypeNode);
  }
  
  FREE(service);
  if (serviceTypeNode == NULL) {
    FREE(baseURL);
    xmlnode_free(xmlRootNode);
    return NULL;
  }
  
  /* get the controlURL of the service */
  if((controlURLNode = xmlnode_get_child(serviceTypeNode,
					 "controlURL")) == NULL) {
    FREE(baseURL);
    xmlnode_free(xmlRootNode);
    return NULL;
  }
  
  tmp = xmlnode_get_data(controlURLNode);
  if(baseURL && !gaim_str_has_prefix(tmp, "http://") &&
     !gaim_str_has_prefix(tmp, "HTTP://")) {
    if (tmp[0] == '/') {
      size_t len;
      const char * end;
      /* absolute path */
      end = strstr(&baseURL[strlen("http://")],
		   "/");
      if (end == NULL)
	len = strlen(&baseURL[strlen("http://")]);
      else
	len = end - &baseURL[strlen("http://")];
      controlURL = g_strdup_printf("http://%.*s%s",
				   len,
				   &baseURL[strlen("http://")],
				   tmp);
    } else {
      controlURL = g_strdup_printf("%s%s", baseURL, tmp);
    }
    FREE(tmp);
  } else{
    controlURL = tmp;
  }
  FREE(baseURL);
  xmlnode_free(xmlRootNode);
  
  return controlURL;
}

#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GE_LOG(NULL, GE_WARNING | GE_USER | GE_BULK, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0);

/**
 * Do the generic curl setup.
 */
static int setup_curl(const char * proxy,
		      CURL * curl) {
  int ret;

  CURL_EASY_SETOPT(curl,
		   CURLOPT_FAILONERROR,
		   1);
  if (strlen(proxy) > 0)
    CURL_EASY_SETOPT(curl,
		     CURLOPT_PROXY,
		     proxy);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_BUFFERSIZE,
		   1024); /* a bit more than one HELLO */
  CURL_EASY_SETOPT(curl,
		   CURLOPT_CONNECTTIMEOUT,
		   150L);
  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  CURL_EASY_SETOPT(curl,
		   CURLOPT_NOSIGNAL,
		   1);
  return OK;
}

static int
gaim_upnp_generate_action_message_and_send(const char * proxy,
					   const char* actionName,
					   const char* actionParams, 
					   GaimUtilFetchUrlCallback cb,
					   void * cb_data) {
  CURL * curl;	
  int ret;
  char * soapHeader;
  char * sizeHeader;
  char * soapMessage;
  struct curl_slist * headers = NULL;

  GE_ASSERT(NULL, cb != NULL);
  if (0 != curl_global_init(CURL_GLOBAL_WIN32)) 
    return SYSERR;
  /* set the soap message */  
  soapMessage = g_strdup_printf(SOAP_ACTION, 
				actionName,
				control_info.service_type, 
				actionParams, 
				actionName);
  soapHeader = g_strdup_printf(HTTP_POST_SOAP_HEADER,
			       control_info.service_type, 
			       actionName);
  sizeHeader = g_strdup_printf(HTTP_POST_SIZE_HEADER,
			       strlen(soapMessage));
  curl = curl_easy_init();
  setup_curl(proxy, curl);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_URL,
		   control_info.control_url);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_WRITEFUNCTION,
		   cb);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_WRITEDATA,
		   cb_data); 
  CURL_EASY_SETOPT(curl,
		   CURLOPT_POST,
		   1);
  headers = curl_slist_append(headers, 
			      "CONTENT-TYPE: text/xml ; charset=\"utf-8\"");
  headers = curl_slist_append(headers, 
			      soapHeader);
  headers = curl_slist_append(headers, 
			      sizeHeader);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_HTTPHEADER,
		   headers);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_POSTFIELDS,
		   soapMessage);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_POSTFIELDSIZE,
		   strlen(soapMessage));
  if (ret == CURLE_OK)
    ret = curl_easy_perform(curl);
#if 0
  if (ret != CURLE_OK)
    GE_LOG(NULL,
	   GE_ERROR | GE_ADMIN | GE_DEVELOPER | GE_BULK,
	   _("%s failed for url `%s' and post-data `%s' at %s:%d: `%s'\n"),
	   "curl_easy_perform",
	   control_info.control_url,
	   soapMessage,
	   __FILE__,
	   __LINE__,
	   curl_easy_strerror(ret));
#endif
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  FREE(sizeHeader);
  FREE(soapMessage);
  FREE(soapHeader);
  if (ret != CURLE_OK)
    return SYSERR;
  return OK;
}


static size_t
looked_up_public_ip_cb(void *url_data, 
		       size_t size,
		       size_t nmemb,		      
		       void * user_data) {
  UPnPDiscoveryData * dd = user_data;
  size_t len = size * nmemb;
  const char * temp;
  const char * temp2;

  if (len + dd->buf_len > 1024 * 1024 * 4)
    return 0; /* refuse to process - too big! */
  GROW(dd->buf,
       dd->buf_len,
       dd->buf_len + len);
  memcpy(&dd->buf[dd->buf_len - len],
	 url_data,
	 len);
  if (dd->buf_len == 0)
    return len;
  /* extract the ip, or see if there is an error */
  if ((temp = g_strstr_len(dd->buf,
			   dd->buf_len,
			   "<NewExternalIPAddress")) == NULL) 
    return len;  
  if (!(temp = g_strstr_len(temp, 
			    dd->buf_len - (temp - dd->buf), ">"))) 
    return len;
  if (!(temp2 = g_strstr_len(temp, 
			     dd->buf_len - (temp - dd->buf), "<"))) 
    return len;
  memset(control_info.publicip, 
	 0,
	 sizeof(control_info.publicip));
  if (temp2 - temp >= sizeof(control_info.publicip))
    temp2 = temp + sizeof(control_info.publicip) - 1;
  memcpy(control_info.publicip, 
	 temp + 1,
	 temp2 - (temp + 1));
  GE_LOG(NULL,
	 GE_INFO | GE_USER | GE_BULK,
	 _("upnp: NAT Returned IP: %s\n"),
	 control_info.publicip);
  return len;
}


static size_t
ignore_response(void *url_data, 
		size_t size,
		size_t nmemb,		      
		void * user_data) {
  return size * nmemb;
}

/**
 * Process downloaded bits of service description.
 */
static size_t
upnp_parse_description_cb(void * httpResponse,
			  size_t size,
			  size_t nmemb,
			  void * user_data) {
  UPnPDiscoveryData * dd = user_data;
  size_t len = size * nmemb;
  char * control_url = NULL;
  
  if (len + dd->buf_len > 1024 * 1024 * 4)
    return len; /* refuse to process - too big! */
  GROW(dd->buf,
       dd->buf_len,
       dd->buf_len + len);
  memcpy(&dd->buf[dd->buf_len - len],
	 httpResponse,
	 len);
  if (dd->buf_len > 0)
    control_url = gaim_upnp_parse_description_response(dd->buf,
						       dd->buf_len,
						       dd->full_url,
						       dd->service_type);
  control_info.status = control_url ? GAIM_UPNP_STATUS_DISCOVERED
    : GAIM_UPNP_STATUS_UNABLE_TO_DISCOVER;
  FREENONNULL(control_info.control_url);
  control_info.control_url = control_url;
  control_info.service_type = dd->service_type;
  return len;
}

static int
gaim_upnp_parse_description(char * proxy,
			    UPnPDiscoveryData * dd) {
  CURL * curl;	
  int ret;
  
  if (0 != curl_global_init(CURL_GLOBAL_WIN32)) 
    return SYSERR;
  curl = curl_easy_init();
  setup_curl(proxy, curl);
  ret = CURLE_OK;
  CURL_EASY_SETOPT(curl,
		   CURLOPT_URL,
		   dd->full_url);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_WRITEFUNCTION,
		   &upnp_parse_description_cb);
  CURL_EASY_SETOPT(curl,
		   CURLOPT_WRITEDATA,
		   dd);
  ret = curl_easy_perform(curl);
  if (ret != CURLE_OK)
    GE_LOG(NULL,
	   GE_ERROR | GE_ADMIN | GE_DEVELOPER | GE_BULK,
	   _("%s failed at %s:%d: `%s'\n"),
	   "curl_easy_perform",
	   __FILE__,
	   __LINE__,
	   curl_easy_strerror(ret));
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  if (control_info.control_url == NULL)
    return SYSERR;
  return OK;
}

int
gaim_upnp_discover(struct GE_Context * ectx,
		   struct GC_Configuration * cfg,
		   int sock) {
  char * proxy;
  struct hostent* hp;
  struct sockaddr_in server;
  int retry_count;
  char * sendMessage;
  size_t totalSize;
  int sentSuccess;
  char buf[65536];
  int buf_len;
  const char * startDescURL;
  const char * endDescURL;
  int ret;
  UPnPDiscoveryData dd;

  memset(&dd,
	 0, 
	 sizeof(UPnPDiscoveryData));
  if (control_info.status == GAIM_UPNP_STATUS_DISCOVERING) 
    return NO;
  dd.sock = sock;
  hp = gethostbyname(HTTPMU_HOST_ADDRESS);
  if (hp == NULL) {
    CLOSE(dd.sock);
    return SYSERR; 
  } 
  memset(&server,
	 0, 
	 sizeof(struct sockaddr));
  server.sin_family = AF_INET;
  memcpy(&server.sin_addr,
	 hp->h_addr_list[0],
	 hp->h_length);
  server.sin_port = htons(HTTPMU_HOST_PORT);  
  control_info.status = GAIM_UPNP_STATUS_DISCOVERING;
  
  /* because we are sending over UDP, if there is a failure
     we should retry the send NUM_UDP_ATTEMPTS times. Also,
     try different requests for WANIPConnection and WANPPPConnection*/
  for (retry_count=0;retry_count<NUM_UDP_ATTEMPTS;retry_count++) {
    sentSuccess = FALSE;    
    if((retry_count % 2) == 0) 
      dd.service_type = WAN_IP_CONN_SERVICE;
    else 
      dd.service_type = WAN_PPP_CONN_SERVICE;    
    sendMessage = g_strdup_printf(SEARCH_REQUEST_STRING, 
				  dd.service_type);
    totalSize = strlen(sendMessage);
    do {
      if (SENDTO(dd.sock,
		 sendMessage, 
		 totalSize, 
		 0,
		 (struct sockaddr*) &server,
		 sizeof(struct sockaddr_in)) == totalSize) {
	sentSuccess = TRUE;
	break;
      }
    } while ( ((errno == EINTR) || (errno == EAGAIN)) &&
	      (GNUNET_SHUTDOWN_TEST() == NO));
    FREE(sendMessage);    
    if (sentSuccess) 
      break;
  }
  if (sentSuccess == FALSE) 
    return SYSERR;  

  /* try to read response */
  do {
    buf_len = recv(dd.sock,
		   buf,
		   sizeof(buf) - 1, 
		   0);   
    if (buf_len > 0) {
      buf[buf_len] = '\0';
      break;
    } else if (errno != EINTR) {
      continue;
    }
  } while ( (errno == EINTR) &&
	    (GNUNET_SHUTDOWN_TEST() == NO) );

  /* parse the response, and see if it was a success */
  if (g_strstr_len(buf, buf_len, HTTP_OK) == NULL) 
    return SYSERR; 
  if ( (startDescURL = g_strstr_len(buf, buf_len, "http://")) == NULL) 
    return SYSERR;  
  
  endDescURL = g_strstr_len(startDescURL,
			    buf_len - (startDescURL - buf),
			    "\r");
  if (endDescURL == NULL) 
    endDescURL = g_strstr_len(startDescURL,
			      buf_len - (startDescURL - buf), "\n");
  if(endDescURL == NULL) 
    return SYSERR;  
  if (endDescURL == startDescURL) 
    return SYSERR;    
  dd.full_url = STRNDUP(startDescURL,
			  endDescURL - startDescURL); 
  proxy = NULL; 
  GC_get_configuration_value_string(cfg,
				    "GNUNETD",
				    "HTTP-PROXY",
				    "",
				    &proxy);
  ret = gaim_upnp_parse_description(proxy,
				    &dd);  
  FREE(dd.full_url);
  GROW(dd.buf,
       dd.buf_len,
       0);
  if (ret == OK) {
    ret = gaim_upnp_generate_action_message_and_send(proxy,
						     "GetExternalIPAddress", 
						     "",
						     looked_up_public_ip_cb, 
						     &dd);
    GROW(dd.buf,
	 dd.buf_len,
	 0);
  }
  FREE(proxy);
  return ret;
}

const char *
gaim_upnp_get_public_ip() {
  if (control_info.status == GAIM_UPNP_STATUS_DISCOVERED
      && control_info.publicip
      && strlen(control_info.publicip) > 0)
    return control_info.publicip;
  return NULL;
}

int
gaim_upnp_change_port_mapping(struct GE_Context * ectx,
			      struct GC_Configuration * cfg,
			      int do_add,
			      unsigned short portmap, 
			      const char* protocol) {
  const char * action_name;
  char * action_params;
  char * internal_ip;
  char * proxy;
  int ret;
    
  if (control_info.status != GAIM_UPNP_STATUS_DISCOVERED) 
    return NO;	
  if (do_add) {
    internal_ip = gaim_upnp_get_internal_ip(cfg,
					    ectx);
    if (internal_ip == NULL) {
      gaim_debug_error("upnp",
		       "gaim_upnp_set_port_mapping(): couldn't get local ip\n");
      return NO;
    }
    action_name = "AddPortMapping";
    action_params = g_strdup_printf(ADD_PORT_MAPPING_PARAMS,
				    portmap, 
				    protocol,
				    portmap,
				    internal_ip);
    FREE(internal_ip);
  } else {
    action_name = "DeletePortMapping";
    action_params = g_strdup_printf(DELETE_PORT_MAPPING_PARAMS,
				    portmap, 
				    protocol);
  }  
  proxy = NULL; 
  GC_get_configuration_value_string(cfg,
				    "GNUNETD",
				    "HTTP-PROXY",
				    "",
				    &proxy);
  ret = gaim_upnp_generate_action_message_and_send(proxy,
						   action_name,
						   action_params,
						   &ignore_response,
						   NULL);
  
  FREE(action_params);
  FREE(proxy);
  return ret; 
}

/* end of upnp.c */

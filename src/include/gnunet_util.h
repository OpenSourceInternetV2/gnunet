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
 * @file include/gnunet_util.h
 * @brief public interface to libgnunet_util
 *
 * @author Christian Grothoff
 * @author Krista Bennett
 * @author Gerd Knorr <kraxel@bytesex.org> 
 * @author Ioana Patrascu
 * @author Tzvetan Horozov
 */

#ifndef GNUNET_UTIL_H
#define GNUNET_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/* we need size_t, and since it can be both unsigned int
   or unsigned long long, this IS platform dependent;
   but "stdlib.h" should be portable 'enough' to be
   unconditionally available... */
#include <stdlib.h>


/* do not turn this on unless you know what you
   are doing, you'll get a ton of output... */
#define DEBUG_LOCKING 0

/**
 * Just the version number of GNUnet-util implementation.
 * Encoded as 
 * 0.6.1-4 => 0x00060104
 * 4.5.2   => 0x04050200
 *
 * Note that this version number is changed whenever
 * something changes GNUnet-util.  It does not have
 * to match exactly with the GNUnet version number;
 * especially the least significant bits may change
 * frequently, even between different CVS versions.
 */

#define GNUNET_UTIL_VERSION 0x00060200

typedef struct {
  void * internal;
} Hostkey__;

typedef Hostkey__ * Hostkey;

/**
 * We use an unsigned short in the protocol header, thus: 
 */
#define MAX_BUFFER_SIZE 65536

/* ********* transport protocol numbers ************* */

/**
 * These are the protocol numbers for the underlying GNUnet
 * protocols. They are typically taken to hint at a well-known
 * protocol, but they are not used in the same way. They just indicate
 * _internally_ to GNUnet which protocol from the TCP/IP suite to use
 * to run GNUnet over.
 */
   
/**
 * protocol number for "unspecified"
 */
#define ANY_PROTOCOL_NUMBER 0

/**
 * protocol number for 'NAT'.  Used as the advertisements for peers behind
 * a NAT box.
 */
#define NAT_PROTOCOL_NUMBER 1

/**
 * protocol number of TCP. Do NEVER change, also used in other context! 
 */
#define TCP_PROTOCOL_NUMBER 6

/**
 * protocol number for HTTP (80 is too big, so 8 will have to do)
 */
#define HTTP_PROTOCOL_NUMBER 8

/**
 * Protocol number for TCP on IPv6 (TCP+6)
 */
#define TCP6_PROTOCOL_NUMBER 12

/**
 * protocol number of UDP. Do NEVER change, also used in other context! 
 */
#define UDP_PROTOCOL_NUMBER 17

/**
 * Protocol number for UDP on IPv6 (UDP+6)
 */
#define UDP6_PROTOCOL_NUMBER 23

/**
 * protocol number for SMTP 
 */
#define SMTP_PROTOCOL_NUMBER 25



/* ********* client-server protocol (over TCP) ********** */
/* ********* CS infrastructure messages ********** */

/**
 * return value for remote calls 
 */
#define CS_PROTO_RETURN_VALUE 0

/**
 * client to gnunetd: to how many nodes are we connected? 
 * reply is a CS_RETURN_VALUE message. 
 */
#define CS_PROTO_CLIENT_COUNT 1

/**
 * Client to gnunetd: how much traffic do we have at the moment?
 */
#define CS_PROTO_TRAFFIC_QUERY 2

/**
 * gnunetd to client: traffic statistics 
 */
#define CS_PROTO_TRAFFIC_INFO 3

/* *********** messages for statistics ************* */

/**
 * client to gnunetd: request statistics 
 */
#define STATS_CS_PROTO_GET_STATISTICS 4

/**
 * gnunetd to client: statistics 
 */
#define STATS_CS_PROTO_STATISTICS 5

/**
 * client to gnunetd: is client server message supported
 */
#define STATS_CS_PROTO_GET_CS_MESSAGE_SUPPORTED 6

/**
 * client to gnunetd: is p2p message supported
 */
#define STATS_CS_PROTO_GET_P2P_MESSAGE_SUPPORTED 7

/* ********** CS AFS application messages ********** */

/**
 * client to gnunetd: send queries
 * */
#define AFS_CS_PROTO_QUERY 8

/**
 * gnunetd to client: here is your answer (3-hash-content) 
 */
#define AFS_CS_PROTO_RESULT_3HASH 9

/**
 * gnunetd to client: here is your answer (CHK-content) 
 */
#define AFS_CS_PROTO_RESULT_CHK 10

/**
 * client to gnunetd: insert CHK content (no index) 
 */
#define AFS_CS_PROTO_INSERT_CHK 11

/**
 * client to gnunetd: insert 3HASH content (no index) 
 */
#define AFS_CS_PROTO_INSERT_3HASH 12

/**
 * client to gnunetd: index content 
 */
#define AFS_CS_PROTO_INDEX_BLOCK 13

/**
 * client to gnunetd: get an index for a file
 */
#define AFS_CS_PROTO_INDEX_FILE 14

/**
 * client to gnunetd: index super-block
 */
#define AFS_CS_PROTO_INDEX_SUPER 15

/**
 * client to gnunetd: delete CHK content (no index) 
 */
#define AFS_CS_PROTO_DELETE_CHK 16

/**
 * client to gnunetd: delete 3HASH content (no index) 
 * Not used so far!
 */
#define AFS_CS_PROTO_DELETE_3HASH 17

/**
 * client to gnunetd: unindex content (remove)
 */
#define AFS_CS_PROTO_UNINDEX_BLOCK 18

/**
 * client to gnunetd: remove an file from the indexed list
 */
#define AFS_CS_PROTO_UNINDEX_FILE 19

/**
 * client to gnunetd: unindex super-block
 */
#define AFS_CS_PROTO_UNINDEX_SUPER 20

/**
 * client to gnunetd: issue namespace query
 */
#define AFS_CS_PROTO_NSQUERY 21

/**
 * client to gnunetd: store SBlock
 */
#define AFS_CS_PROTO_INSERT_SBLOCK 22

/**
 * gnuentd to client: SBlock found
 */
#define AFS_CS_PROTO_RESULT_SBLOCK 23

/**
 * client to gnunetd: bits of file to upload (indexing)
 */
#define AFS_CS_PROTO_UPLOAD_FILE 24

/**
 * Client to gnunetd: try using a link for the file
 */
#define AFS_CS_PROTO_LINK_FILE 25

/**
 * Client to gnunetd: what is the average priority of entries
 * in the routing table?
 */
#define AFS_CS_PROTO_GET_AVG_PRIORITY 26

/* ********** CS CHAT application messages ********** */

#define CHAT_CS_PROTO_MSG 32

/* ********** CS TRACEKIT application messages ********* */

#define TRACEKIT_CS_PROTO_PROBE 36

#define TRACEKIT_CS_PROTO_REPLY 37

/* ********** CS TBENCH application messages ********** */

#define TBENCH_CS_PROTO_REQUEST	40
#define TBENCH_CS_PROTO_REPLY	41

/* ********** CS TESTBED application messages ********** */

#define TESTBED_CS_PROTO_REQUEST 50
#define TESTBED_CS_PROTO_REPLY   51

/* ************ additional common CS messages *************** */

/** 
 * client to gnunetd: shutdown
 */
#define CS_PROTO_SHUTDOWN_REQUEST 64

/** 
 * client to gnunetd: get configuration option
 */
#define CS_PROTO_GET_OPTION_REQUEST 65

/**
 * gnunetd to client: option value
 */
#define CS_PROTO_GET_OPTION_REPLY 66

/* ********** CS DHT application messages ********** */
                                        
/**
 * client to CS: join table        
*/
#define DHT_CS_PROTO_REQUEST_JOIN     72

/**
 * client to CS: leave table       
 */
#define DHT_CS_PROTO_REQUEST_LEAVE    73

/**
 * Client to CS or CS to client: get from table   
 */
#define DHT_CS_PROTO_REQUEST_GET      74

/**
 * Client to CS or CS to client: put into table    
 */
#define DHT_CS_PROTO_REQUEST_PUT      75 

/**
 * Client to CS or CS to client: remove from table
 */
#define DHT_CS_PROTO_REQUEST_REMOVE   76 

/**
 * Client to CS or CS to client: results from get
 */
#define DHT_CS_PROTO_REPLY_GET        77

/**
 * Client to CS or CS to client: confirmed
 */
#define DHT_CS_PROTO_REPLY_ACK        78



/* **************** common structs ******************* */

/**
 * Header for all Client-Server communications.
 */
typedef struct {
  /**
   * The length of the struct (in bytes, including the length field itself) 
   */
  unsigned short size;

  /**
   * The type of the message (XX_CS_PROTO_XXXX) 
   */
  unsigned short tcpType;

} CS_HEADER;

/**
 * Generic version of CS_HEADER with field for accessing end of struct (use the
 * other version for allocation).
 */
typedef struct {
  /**
   * actual header
   */
  CS_HEADER cs_header;

  /**
   * This is followed by a requestType specific data block, consisting
   * of size bytes.
   */
  char data[1];

} CS_HEADER_GENERIC;

/**
 * CS communication: simple return value
 */
typedef struct {
  /**
   * The CS header (values: sizeof(CS_RETURN_VALUE), CS_PROTO_RETURN_VALUE)
   */ 
  CS_HEADER header;

  /**
   * The return value (network byte order) 
   */
  int return_value;
} CS_RETURN_VALUE;


/* ******** node-to-node (p2p) messages (over anything) ********* */

/* ********* p2p infrastructure messages *********** */

/**
 * announcement of public key 
 */
#define p2p_PROTO_HELO 0

/**
 * session key exchange, session key is encrypted with hostkey 
 */
#define p2p_PROTO_SKEY 1

/**
 * PING 
 */
#define p2p_PROTO_PING 2

/**
 * PONG (response to PING) 
 */
#define p2p_PROTO_PONG 3

/**
 * timestamp (until when is the packet valid) 
 */
#define p2p_PROTO_TIMESTAMP 4

/**
 * sequence number (discard packet if sequence number
 * is not higher than previously received number) 
 */
#define p2p_PROTO_SEQUENCE 5

/**
 * noise, used to fill packets to sizes >1k.
 */
#define p2p_PROTO_NOISE 6

/**
 * termination of connection (other host is nice
 * and tells us, there is NO requirement to do so!) 
 */
#define p2p_PROTO_HANGUP 7

/**
 * Advertise capability (or limitation).
 */
#define p2p_PROTO_CAPABILITY 8

/* ************* p2p AFS application messages *********** */

/**
 * Query for content. 
 */
#define AFS_p2p_PROTO_QUERY 16

/**
 * receive content 
 */
#define AFS_p2p_PROTO_3HASH_RESULT 17

/**
 * receive CHK content 
 */
#define AFS_p2p_PROTO_CHK_RESULT 18

/**
 * Request namespace entry
 */
#define AFS_p2p_PROTO_NSQUERY 19

/**
 * Received namespace entry
 */
#define AFS_p2p_PROTO_SBLOCK_RESULT 20


/* ************** p2p CHAT application messages *********** */

/**
 * chat message 
 */
#define CHAT_p2p_PROTO_MSG 32

/* *************** p2p TRACEKIT application messages ******** */

#define TRACEKIT_p2p_PROTO_PROBE 36

#define TRACEKIT_p2p_PROTO_REPLY 37

/* ********** p2p TBENCH application messages ********** */

/**
 * benchmark message: send back reply asap 
 */
#define TBENCH_p2p_PROTO_REQUEST 40
#define TBENCH_p2p_PROTO_REPLY 	 41

/************** p2p RPC/DHT application messages ************/
                                                                                
#define RPC_p2p_PROTO_REQ 42
#define RPC_p2p_PROTO_RES 43
#define RPC_p2p_PROTO_ACK 44

#define MAX_p2p_PROTO_USED 45

/* ************** common structs ********************* */

/**
 * p2p message part header
 */
typedef struct {
  /**
   * size of this MESSAGE_PART (network byte order) 
   */
  unsigned short size;

  /**
   * type of the request, XX_p2p_PROTO_XXX (network byte order) 
   */
  unsigned short requestType; 
} p2p_HEADER;


/**
 * Generic version of p2p_HEADER with field for accessing end of struct (use 
 * the other version for allocation).
 */
typedef struct {
  p2p_HEADER p2p_header;

  /**
   * this is followed by a requestType specific data block,
   * consisting of size bytes. 
   */
  char data[1];
} p2p_HEADER_GENERIC;

/**
 * Named constants for return values.
 */


#define OK 1
#define SYSERR -1

#define YES 1
#define NO 0


/**
 * Compute the CRC32 checksum for the first len
 * bytes of the buffer.
 *
 * @param buf the data over which we're taking the CRC
 * @param len the length of the buffer in bytes
 * @return the resulting CRC32 checksum 
 */
int crc32N(const void * buf, int len);

/**
 * Produce a random value.
 *
 * @param i the upper limit (exclusive) for the random number
 * @return a random value in the interval [0,i[. 
 */
int randomi(int i);

/**
 * Random on unsigned 64-bit values.  We break them down into signed
 * 32-bit values and reassemble the 64-bit random value bit-wise.
 */
unsigned long long randomi64(unsigned long long u);

/**
 * Get an array with a random permutation of the
 * numbers 0...n-1.
 * @param n the size of the array
 * @return the permutation array (allocated from heap)
 */
int * permute(int n);

/**
 * Convert a long-long to host-byte-order.
 * @param n the value in network byte order
 * @return the same value in host byte order
 */
unsigned long long ntohll(unsigned long long n);

/**
 * Convert a long long to network-byte-order.
 * @param n the value in host byte order
 * @return the same value in network byte order
 */
unsigned long long htonll(unsigned long long n);


/**
 * GNU gettext support macro.
 */
#define _(String) gettext (String)

/**
 * Macro for assertions in GNUnet.  Use liberally and instead
 * of specific but cryptic error messages that merely refer
 * to the location of the problem but that would be evident
 * by looking at the code instead.  Do NOT use this macro if
 * an error message with context information (strerror,
 * filenames, etc.) would be useful.
 *
 * Note that a failed assertion always aborts, so do not use
 * this for errors that can be managed.
 */
#define GNUNET_ASSERT(cond)  do { if (! (cond)) errexit(_("Assertion failed at %s:%d.\n"), __FILE__, __LINE__); } while(0);

#define GNUNET_ASSERT_FL(cond, f, l)  do { if (! (cond)) errexit(_("Assertion failed at %s:%d.\n"), f, l); } while(0);

/**
 * Configuration management.
 */

/* ****************** config values **************** */

/**
 * Default names of the configuration files.
 */
#define DEFAULT_CLIENT_CONFIG_FILE "~/.gnunet/gnunet.conf"
#define DEFAULT_DAEMON_CONFIG_FILE "/etc/gnunet.conf"

/* *******************API *********************** */

typedef void (*NotifyConfigurationUpdateCallback)();

void registerConfigurationUpdateCallback
(NotifyConfigurationUpdateCallback cb);
  
void unregisterConfigurationUpdateCallback
(NotifyConfigurationUpdateCallback cb);

/**
 * Call all registered configuration update callbacks,
 * the configuration has changed.
 */
void triggerGlobalConfigurationRefresh();

/**
 * Read the specified configuration file. The previous
 * configuration will be discarded if this method is 
 * invoked twice. The configuration file that is read
 * can be set using setConfigurationString on 
 * section "FILES" and option "gnunet.conf".
 * 
 * This method should be invoked after the options have
 * been parsed (and eventually the configuration filename
 * default has been overriden) and if gnunetd receives
 * a SIGHUP.
 */
void readConfiguration();


/**
 * Obtain a filename from the given section and option.  If the
 * filename is not specified, die with the given error message (do not
 * die if errMsg == NULL). 
 *
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 *
 * @param errMsg the errormessage, should contain two %s tokens for
 * the section and the option.
 *
 * @return the specified filename (caller must free), or NULL if no
 * filename was specified and errMsg == NULL
 */
char * getFileName(const char * section,
		   const char * option,
		   const char * errMsg);

/**
 * Check if a string in the configuration matches a given value.  This
 * method should be preferred over getConfigurationString since this
 * method can avoid making a copy of the configuration string that
 * then must be freed by the caller.
 *
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @param value the value to compare against
 * @return YES or NO
 */
int testConfigurationString(const char * section,
			    const char * option,
			    const char * value);

/**
 * Obtain a string from the configuration.
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @return a freshly allocated string, caller must free!
 *   Note that the result can be NULL if the option is not set.
 */
char * getConfigurationString(const char * section,
			      const char * option);

/**
 * Obtain an int from the configuration.
 * @param section from which section
 * @param option which option
 * @return 0 if no option is specified
 */
unsigned int getConfigurationInt(const char * section,
				 const char * option);

/**
 * Set an option.
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @param value the value to use, may be NULL
 * @return the previous value (or NULL if none),
 *     caller must free!
 */
char * setConfigurationString(const char * section,
			      const char * option,
			      const char * value);

/**
 * Set an option.
 * @param section from which section, may not be NULL
 * @param option which option, may not be NULL
 * @param value the value to use
 * @return the previous value (or 0 if none)
 */
unsigned int setConfigurationInt(const char * section,
				 const char * option,
				 const unsigned int value);

/**
 * Get the command line strings (the ones
 * remaining after getopt-style parsing).
 * @param value the values
 + @return the number of values
 */
int getConfigurationStringList(char *** value);

/**
 * Set the list of command line options (remainder after getopt style
 * parsing).
 *
 * @param value the values 
 + @param count the number of values
 */
void setConfigurationStringList(char ** value,
				int count);

/**
 * @brief Module to run background jobs.
 */

/* use these constants to specify timeings */
#define cronMILLIS 1
#define cronSECONDS (1000 * cronMILLIS)
#define cronMINUTES (60 * cronSECONDS)
#define cronHOURS (60 * cronMINUTES)
#define cronDAYS (24 * cronHOURS)
#define cronWEEKS (7 * cronDAYS)
#define cronMONTHS (30 * cronDAYS)
#define cronYEARS (365 * cronDAYS)

/**
 * Time for absolute times used by cron.
 */
typedef unsigned long long cron_t;  

/**
 * Type of a cron-job method.
 */
typedef void (*CronJob)(void *);

/**
 * Initialize controlThread.
 */
void initCron();

/**
 * Make sure to call stopCron before calling this method!
 */
void doneCron();

/**
 * Start the cron jobs.
 */
void startCron();

/**
 * Stop the cron service.
 */
void stopCron();

/**
 * Stop running cron-jobs for a short time.  This method may only be
 * called by a thread that is not holding any locks.  It will cause
 * a deadlock if this method is called from within a cron-job.
 * Use with caution.
 */
void suspendCron();

/**
 * Resume running cron-jobs.
 */
void resumeCron();

/**
 * Get the current time (works just as "time", just
 * that we use the unit of time that the cron-jobs use).
 * @param setme will set the current time if non-null
 * @return the current time 
 */
cron_t cronTime(cron_t * setme);

/**
 * Add a cron-job to the delta list.
 * @param method which method should we run
 * @param delta how many milliseconds until we run the method
 * @param deltaRepeat if this is a periodic, the time between
 *        the runs, otherwise 0.
 * @param data argument to pass to the method
 */
void addCronJob(CronJob method,
		unsigned int delta,
		unsigned int deltaRepeat,
		void * data);


/**
 * If the specified cron-job exists in th delta-list, move it to the
 * head of the list.  If it is running, do nothing.  If it is does not
 * exist and is not running, add it to the list to run it next.
 *
 * @param method which method should we run
 * @param deltaRepeat if this is a periodic, the time between
 *        the runs, otherwise 0.
 * @param data extra argument to calls to method, freed if
 *        non-null and cron is shutdown before the job is
 *        run and/or delCronJob is called
 */
void advanceCronJob(CronJob method,
		   unsigned int deltaRepeat,
		   void * data);
/**
 * Remove all matching cron-jobs from the list. This method should
 * only be called while cron is suspended or stopped, or from a cron
 * job that deletes another cron job.  If cron is not suspended or
 * stopped, it may be running the method that is to be deleted, which
 * could be bad (in this case, the deletion will not affect the
 * running job and may return before the running job has terminated).
 *
 * @param method which method is listed?
 * @param repeat which repeat factor was chosen? 
 * @param data what was the data given to the method
 * @return the number of jobs removed
 */
int delCronJob(CronJob method,
	       unsigned int repeat,
	       void * data);

/**
 * Sleep for the specified time interval.
 * A signal interrupts the sleep.  Caller
 * is responsible to check that the sleep was
 * long enough.
 *
 * @return 0 if there was no interrupt, 1 if there was, -1 on error.
 */
int gnunet_util_sleep(cron_t delay);

/**
 * Support for loading dynamic libraries.
 */

void * loadDynamicLibrary(const char * libprefix,
			  const char * dsoname);

void * bindDynamicMethod(void * libhandle,
			 const char * methodprefix,
			 const char * dsoname);

void unloadDynamicLibrary(void * libhandle);

/* For communication from `getopt' to the caller.
   When `getopt' finds an option that takes an argument,
   the argument value is returned here.
   Also, when `ordering' is RETURN_IN_ORDER,
   each non-option ARGV-element is returned here.  */

extern char *GNoptarg;

/* Index in ARGV of the next element to be scanned.
   This is used for communication to and from the caller
   and for communication between successive calls to `getopt'.

   On entry to `getopt', zero means this is the first call; initialize.

   When `getopt' returns -1, this is the index of the first of the
   non-option elements that the caller should itself scan.

   Otherwise, `GNoptind' communicates from one call to the next
   how much of ARGV has been scanned so far.  */

extern int GNoptind;

/* Callers store zero here to inhibit the error message `getopt' prints
   for unrecognized options.  */

extern int GNopterr;

/* Set to an option character which was unrecognized.  */

extern int GNoptopt;

/* Describe the long-named options requested by the application.
   The LONG_OPTIONS argument to getopt_long or getopt_long_only is a vector
   of `struct GNoption' terminated by an element containing a name which is
   zero.

   The field `has_arg' is:
   no_argument		(or 0) if the option does not take an argument,
   required_argument	(or 1) if the option requires an argument,
   optional_argument 	(or 2) if the option takes an optional argument.

   If the field `flag' is not NULL, it points to a variable that is set
   to the value given in the field `val' when the option is found, but
   left unchanged if the option is not found.

   To have a long-named option do something other than set an `int' to
   a compiled-in constant, such as set a value from `GNoptarg', set the
   option's `flag' field to zero and its `val' field to a nonzero
   value (the equivalent single-letter option character, if there is
   one).  For long options that have a zero `flag' field, `getopt'
   returns the contents of the `val' field.  */

struct GNoption {
  const char *name;
  /* has_arg can't be an enum because some compilers complain about
     type mismatches in all the code that assumes it is an int.  */
  int has_arg;
  int *flag;
  int val;
};

/* Names for the values of the `has_arg' field of `struct GNoption'.  */

#define	no_argument		0
#define required_argument	1
#define optional_argument	2

int GNgetopt_long (int argc, 
		   char *const *argv, 
		   const char *shortopts,
		   const struct GNoption *longopts,
		   int *longind);

/**
 * @brief check IP addresses against a blacklist
 */

/**
 * @brief an IPv4 address
 */ 
typedef struct {
  unsigned int addr; /* struct in_addr */
} IPaddr;

/**
 * @brief IPV4 network in CIDR notation.
 */
typedef struct {
  IPaddr network;
  IPaddr netmask;
} CIDRNetwork;

/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
CIDRNetwork * parseRoutes(const char * routeList);


/**
 * Check if the given IP address is in the list of 
 * IP addresses.
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return NO if the IP is not in the list, YES if it it is
 */
int checkIPListed(const CIDRNetwork * list,
		  IPaddr ip);

/**
 * @brief an IPV6 address.
 */
typedef struct {
  unsigned int addr[4]; /* struct in6_addr addr; */
} IP6addr;

/**
 * @brief network in CIDR notation for IPV6.
 */
typedef struct {
  IP6addr network;
  IP6addr netmask;
} CIDR6Network;


/**
 * Check if the given IP address is in the list of 
 * IP addresses.
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return NO if the IP is not in the list, YES if it it is
 */
int checkIP6Listed(const CIDR6Network * list,
		   const IP6addr * ip);

/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
CIDR6Network * parseRoutes6(const char * routeList);



/**
 * This type is for messages that we send.
 */
#define TC_SENT      0x8000

/**
 * This type is for messages that we receive.
 */
#define TC_RECEIVED  0x4000

#define TC_TYPE_MASK (TC_RECEIVED|TC_SENT)

/**
 * From/To how many different peers did we receive/send
 * messages of this type? (bitmask)
 */
#define TC_DIVERSITY_MASK 0xFFF

/**
 * Counter for traffic.
 */
typedef struct {

  /**
   * Flags. See TC_XXXX definitions.
   */
  unsigned short flags;

  /**
   * What was the number of messages of this type that the peer
   * processed in the last n time units?
   */
  unsigned short count;

  /**
   * What is the message type that this counter is concerned with?
   */
  unsigned short type;

  /**
   * What is the average size of the last "count" messages that
   * the peer processed?
   */
  unsigned short avrg_size;

  /**
   * In which of the last 32 time units did the peer receive or send a
   * message of this type? The lowest bit (1) corresponds to -31
   * seconds ago, the highest bit (2^31) corresponds to the current
   * second.
   */
  unsigned int time_slots;
} TRAFFIC_COUNTER;

/**
 * Format of the reply-message to a CS_TRAFFIC_QUERY.
 * A message of this format is send back to the client
 * if it sends a CS_TRAFFIC_QUERY to gnunetd.
 */
typedef struct {
  CS_HEADER header;

  /**
   * The number of different message types we have seen
   * in the last time.
   */
  unsigned int count;

} CS_TRAFFIC_INFO;

/**
 * Generic version of CS_TRAFFIC_INFO with field for accessing end of struct 
 * (use the other version for allocation).
 */
typedef struct {
  CS_TRAFFIC_INFO cs_traffic_info;

  /**
   * The number of different message types we have seen
   * in the last time.
   */
  unsigned int count;

  /**
   * "count" traffic counters.
   */
  TRAFFIC_COUNTER counters[1];

} CS_TRAFFIC_INFO_GENERIC;

/**
 * Request for CS_TRAFFIC_INFO.
 */
typedef struct {
  CS_HEADER header;

  /**
   * How many time units back should the statistics returned contain? 
   * (in network byte order) Must be smaller or equal to HISTORY_SIZE.
   */
  unsigned int timePeriod;

} CS_TRAFFIC_REQUEST;

/**
 * What is the unit of time (in cron_t) for the traffic module? This
 * constant essentially specifies the resolution of the distribution
 * function that is applied for sampling traffic. Default is 1s.
 */ 
#define TRAFFIC_TIME_UNIT cronSECONDS

#define CS_GET_OPTION_REQUEST_OPT_LEN 32

/**
 * Request for option value.
 */
typedef struct {
  CS_HEADER header;
  char section[CS_GET_OPTION_REQUEST_OPT_LEN];
  char option[CS_GET_OPTION_REQUEST_OPT_LEN];
} CS_GET_OPTION_REQUEST;


/**
 * Reply with option value.
 */
typedef struct {
  CS_HEADER header;
  char value[1];
} CS_GET_OPTION_REPLY;




/* ************** log levels *********** */

#define LOG_NOTHING    0
#define LOG_FATAL      1
#define LOG_ERROR      2
#define LOG_FAILURE    3
#define LOG_WARNING    4
#define LOG_MESSAGE    5
#define LOG_INFO       6
#define LOG_DEBUG      7
#define LOG_CRON       8
#define LOG_EVERYTHING 9

/* use IFLOG(LOG_XXX, statement(s)) for statements
   that should only be executed if we are at the
   right loglevel */
#define IFLOG(a,b) {if (getLogLevel() >= a) {b;} }

#define PRIP(ip) (int)((ip)>>24), (int)((ip)>>16 & 255), (int)((ip)>>8 & 255), (int)((ip) & 255)

typedef void (*TLogProc)(const char *txt);

/**
 * Get the current loglevel.
 */
int getLogLevel();

/**
 * Return the logfile
 */
void *getLogfile();

/**
 * errexit - log an error message and exit.
 *
 * @param format the string describing the error message
 */
void errexit(const char *format, ...);

/**
 * Register an additional logging function which gets
 * called whenever GNUnet LOG()s something
 *
 * @param proc the function to register
 */
void setCustomLogProc(TLogProc proc);

/**
 * Log a message.
 * @param minLogLevel the minimum loglevel that we must be at
 * @param format the format string describing the message
 */
void LOG(int minLogLevel,
	 const char * format,
	 ...);

#define BREAK() do { breakpoint_(__FILE__,__LINE__); } while(0);

#define BREAK_FL(f, n) do { breakpoint_(f,n); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define LOG_STRERROR(level, cmd) do { LOG(level, _("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); } while(0);

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' with the message given
 * by strerror(errno).
 */
#define DIE_STRERROR(cmd) do { errexit(_("'%s' failed at %s:%d with error: %s\n"), cmd, __FILE__, __LINE__, STRERROR(errno)); } while(0);

#define DIE_STRERROR_FL(cmd, f, l) do { errexit(_("'%s' failed at %s:%d with error: %s\n"), cmd, f, l, STRERROR(errno)); } while(0);

/**
 * Log an error message at log-level 'level' that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define LOG_FILE_STRERROR(level, cmd, filename) do { LOG(level, _("'%s' failed on file '%s' at %s:%d with error: %s\n"), cmd, filename, __FILE__, __LINE__, STRERROR(errno)); } while(0);

#define LOG_FILE_STRERROR_FL(level, cmd, filename, f, l) do { LOG(level, _("'%s' failed on file '%s' at %s:%d with error: %s\n"), cmd, filename, f, l, STRERROR(errno)); } while(0);

/**
 * Die with an error message that indicates
 * a failure of the command 'cmd' on file 'filename'
 * with the message given by strerror(errno).
 */
#define DIE_FILE_STRERROR(cmd, filename) do { errexit(_("'%s' failed on file '%s' at %s:%d with error: %s\n"), cmd, filename, __FILE__, __LINE__, STRERROR(errno)); } while(0);

/**
 * gdb breakpoint
 */
void breakpoint_(const char * filename,
                 const int linenumber);


/**
 * Allocate memory. Checks the return value, aborts if no more
 * memory is available.  Don't use xmalloc_ directly. Use the
 * MALLOC macro.
 */
void * xmalloc_(size_t size, 
		const char * filename,
		const int linenumber);

/**
 * Allocate memory.  This function does not check if the
 * allocation request is within reasonable bounds, allowing
 * allocations larger than 40 MB.  If you don't expect the
 * possibility of very large allocations, use MALLOC instead.
 */
void * xmalloc_unchecked_(size_t size, 
			  const char * filename,
			  const int linenumber);

/**
 * Wrapper around malloc. Allocates size bytes of memory.
 * @param size the number of bytes to allocate
 * @return pointer to size bytes of memory
 */
#define MALLOC(size) xmalloc_(size, __FILE__,__LINE__)

/**
 * Free memory. Merely a wrapper for the case that we
 * want to keep track of allocations.  Don't use xfree_
 * directly. Use the FREE macro.
 */
void xfree_(void * ptr, 
	    const char * filename,
	    const int linenumber);

/**
 * Wrapper around free. Frees the memory referred to by ptr.
 * Note that is is generally better to free memory that was
 * allocated with GROW using GROW(mem, size, 0) instead of FREE.
 *
 * @param ptr location where to free the memory. ptr must have
 *     been returned by STRDUP, MALLOC or GROW earlier. 
 */
#define FREE(ptr) xfree_(ptr, __FILE__, __LINE__)

/**
 * Free the memory pointed to by ptr if ptr is not NULL.
 * Equivalent to if (ptr!=null)FREE(ptr).
 * @param ptr the location in memory to free
 */
#define FREENONNULL(ptr) do { void * __x__ = ptr; if (__x__ != NULL) { FREE(__x__); } } while(0)

/**
 * Dup a string. Don't call xstrdup_ directly. Use the STRDUP macro.
 */
char * xstrdup_(const char * str,
		const char * filename,
		const int linenumber);

/**
 * Wrapper around STRDUP.  Makes a copy of the zero-terminated string
 * pointed to by a. 
 * @param a pointer to a zero-terminated string
 * @return a copy of the string including zero-termination
 */
#define STRDUP(a) xstrdup_(a,__FILE__,__LINE__)

/**
 * Dup a string. Don't call xstrdup_ directly. Use the STRDUP macro.
 *
 * @param str the string to dup
 * @param n the maximum number of characters to copy (+1 for 0-termination)
 * @param filename where in the code was the call to GROW
 * @param linenumber where in the code was the call to GROW
 * @return strdup(str)
 */
char * xstrndup_(const char * str,
		 const size_t n,
		 const char * filename,
		 const int linenumber);

/**
 * Wrapper around STRNDUP.  Makes a copy of the zero-terminated string
 * pointed to by a. 
 * @param a pointer to a zero-terminated string
 * @param n the maximum number of characters to copy (+1 for 0-termination)
 * @return a copy of the string including zero-termination
 */
#define STRNDUP(a,n) xstrndup_(a,n,__FILE__,__LINE__)

/**
 * Grow an array, the new elements are zeroed out.
 * Grows old by (*oldCount-newCount)*elementSize
 * bytes and sets *oldCount to newCount.
 *
 * Don't call xgrow_ directly. Use the GROW macro.
 *
 * @param old address of the pointer to the array
 *        *old may be NULL
 * @param elementSize the size of the elements of the array
 * @param oldCount address of the number of elements in the *old array
 * @param newCount number of elements in the new array, may be 0 (then *old will be NULL afterwards)
 */
void xgrow_(void ** old,
	    size_t elementSize,
	    unsigned int * oldCount,
	    unsigned int newCount,
	    const char * filename,
	    const int linenumber);

/**
 * Grow a well-typed (!) array.  This is a convenience
 * method to grow a vector <tt>arr</tt> of size <tt>size</tt>
 * to the new (target) size <tt>tsize</tt>. 
 * <p>
 *
 * Example (simple, well-typed stack):
 *
 * <pre>
 * static struct foo * myVector = NULL;
 * static int myVecLen = 0;
 * 
 * static void push(struct foo * elem) {
 *   GROW(myVector, myVecLen, myVecLen+1);
 *   memcpy(&myVector[myVecLen-1], elem, sizeof(struct foo));
 * }
 *
 * static void pop(struct foo * elem) {
 *   if (myVecLen == 0) die();
 *   memcpy(elem, myVector[myVecLen-1], sizeof(struct foo));
 *   GROW(myVector, myVecLen, myVecLen-1);
 * }
 * </pre>
 *
 * @param arr base-pointer of the vector, may be NULL if size is 0;
 *        will be updated to reflect the new address. The TYPE of
 *        arr is important since size is the number of elements and
 *        not the size in bytes
 * @param size the number of elements in the existing vector (number
 *        of elements to copy over)
 * @param tsize the target size for the resulting vector, use 0 to 
 *        free the vector (then, arr will be NULL afterwards).
 */
#define GROW(arr,size,tsize) xgrow_((void**)&arr, sizeof(arr[0]), &size, tsize, __FILE__, __LINE__)

/**
 * @brief wrapper around time calls
 */

/**
 * 32-bit timer value.
 */
typedef unsigned int TIME_T;

/**
 * TIME prototype. "man time".
 */
TIME_T TIME(TIME_T * t);

/**
 * "man ctime".
 */
char * GN_CTIME(const TIME_T * t);

/**
 * @brief sym encrypt/decrypt operations
 */

/** length of the sessionkey in bytes
   (128 BIT sessionkey) */
#define SESSIONKEY_LEN (128/8)

/** size of blowfish key in bytes */
#define BF_KEYSIZE 16

/** this unsigned short is 64 bit, blowfish */
#define BLOWFISH_BLOCK_LENGTH 8 

/** value for the IV in the streamcipher for the
    link-to-link encryption */
#define INITVALUE "GNUnet!!"

/** 
 * type for session keys 
 */
typedef struct {
  unsigned char key[SESSIONKEY_LEN];
} SESSIONKEY;

/**
 * Create a new Session key.
 */
void makeSessionkey(SESSIONKEY * key);

/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 * @param block the block to encrypt
 * @param len the size of the block
 * @param sessionkey the key used to encrypt
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @returns the size of the encrypted block, -1 for errors
 */
int encryptBlock(const void * block, 
		 unsigned short len,
		 const SESSIONKEY * sessionkey,
		 const unsigned char * iv,
		 void * result);

/**
 * Decrypt a given block with the sessionkey.
 * @param sessionkey the key used to decrypt
 * @param block the data to decrypt, encoded as returned by encrypt
 * @param size how big is the block?
 * @param iv the initialization vector to use, use INITVALUE
 *        for streams.
 * @param result address to store the result at
 * @return -1 on failure, size of decrypted block on success
 */
int decryptBlock(const SESSIONKEY * sessionkey, 
		 const void * block,
		 unsigned short size,
		 const unsigned char * iv,
		 void * result);


/**
 * @brief Structure for MUTual EXclusion (Mutex).  
 *
 * Essentially a wrapper around pthread_mutex_t.
 */ 
typedef struct Mutex {
  void * internal;
} Mutex;

/**
 * @brief Semaphore abstraction implemented with pthreads
 */
typedef struct Semaphore {
  int v;
  Mutex mutex;
  /**
   * Wrapper for pthread condition variable.
   */
  void * cond;
} Semaphore;

/* ************** Semaphore operations ************* */

#define SEMAPHORE_NEW(value) semaphore_new_(value, __FILE__, __LINE__)
#define SEMAPHORE_FREE(s) semaphore_free_(s, __FILE__, __LINE__)
#define SEMAPHORE_DOWN(s) semaphore_down_(s, __FILE__, __LINE__)
#define SEMAPHORE_DOWN_NONBLOCKING(s) semaphore_down_nonblocking_(s, __FILE__, __LINE__)
#define SEMAPHORE_UP(s) semaphore_up_(s, __FILE__, __LINE__)

/* ************** MUTEX OPERATIONS ***************** */

#if DEBUG_LOCKING
#define MUTEX_CREATE(a) do { \
  fprintf(stderr, \
          "Creating mutex %x at line %d in file %s\n", \
          (int) a, __LINE__, __FILE__); \
  create_mutex_(a); \
}\
while(0)
#define MUTEX_CREATE_RECURSIVE(a) do { \
  fprintf(stderr, \
          "Creating recursive mutex %x at line %d in file %s\n", \
          (int) a, __LINE__, __FILE__); \
  create_recursive_mutex_(a); \
}\
while(0)
#define MUTEX_DESTROY(a) do { \
  fprintf(stderr, \
          "Destroying mutex %x at line %d in file %s\n", \
          (int) a, __LINE__, __FILE__); \
  destroy_mutex_(a); \
}\
while(0)
#define MUTEX_LOCK(a) do { \
  fprintf(stderr, \
          "Aquireing lock %x at %s:%d\n", \
          (int)a, __FILE__, __LINE__); \
  mutex_lock_(a, __FILE__, __LINE__); \
}\
while (0)
#define MUTEX_UNLOCK(a) do { \
  fprintf(stderr, \
         "Releasing lock %x at %s:%d\n", \
	(int)a, __FILE__, __LINE__); \
  mutex_unlock_(a, __FILE__, __LINE__); \
}\
while (0)
#else
#define MUTEX_LOCK(a) mutex_lock_(a, __FILE__, __LINE__)
#define MUTEX_UNLOCK(a) mutex_unlock_(a, __FILE__, __LINE__)
#define MUTEX_CREATE(a) create_mutex_(a)
#define MUTEX_CREATE_RECURSIVE(a) create_recursive_mutex_(a)
#define MUTEX_DESTROY(a) destroy_mutex_(a)
#endif


/* *************** thread handling ************* */

typedef void * (*PThreadMain)(void*);

typedef struct {
  void * internal;
} PTHREAD_T;

int PTHREAD_CREATE(PTHREAD_T * handle,
		   PThreadMain main,
		   void * arg,
		   size_t stackSize);

void PTHREAD_JOIN(PTHREAD_T * handle,
		  void ** ret);

void PTHREAD_KILL(PTHREAD_T * handle,
		  int signal);

void PTHREAD_DETACH(PTHREAD_T * handle);



/* ********************** IPC ********************* */

#define IPC_SEMAPHORE_NEW(name,value) ipc_semaphore_new_(name, value, __FILE__, __LINE__)
#define IPC_SEMAPHORE_FREE(s) ipc_semaphore_free_(s, __FILE__, __LINE__)
#define IPC_SEMAPHORE_DOWN(s) ipc_semaphore_down_(s, __FILE__, __LINE__)
#define IPC_SEMAPHORE_UP(s) ipc_semaphore_up_(s, __FILE__, __LINE__)

typedef struct {
  void * platform;
} IPC_Semaphore;

IPC_Semaphore * ipc_semaphore_new_(const char * basename,
				   const unsigned int initialValue,
				   const char * filename,
				   const int linenumber);

void ipc_semaphore_up_(IPC_Semaphore * sem,
		       const char * filename,
		       const int linenumber);

void ipc_semaphore_down_(IPC_Semaphore * sem,
			 const char * filename,
			 const int linenumber);


void ipc_semaphore_free_(IPC_Semaphore * sem,
			 const char * filename,
			 const int linenumber);



/* ***************** internal methods ************* */

/**
 * While we must define these globally to make the
 * compiler happy, always use the macros in the sources
 * instead! 
 */
void create_mutex_(Mutex * mutex);
void create_recursive_mutex_(Mutex * mutex);
void create_fast_mutex_(Mutex * mutex);
void destroy_mutex_(Mutex * mutex);
void mutex_lock_(Mutex * mutex, 
		 const char * filename,
		 const int linenumber);
void mutex_unlock_(Mutex * mutex, 
		   const char * filename,
		   const int linenumber);
Semaphore * semaphore_new_(int value, 
			   const char * filename,
			   const int linenumber);
void semaphore_free_(Semaphore * s,
		     const char * filename,
		     const int linenumber);
int semaphore_down_(Semaphore * s,
		    const char * filename,
		    const int linenumber);
int semaphore_down_nonblocking_(Semaphore * s,
				const char * filename,
				const int linenumber);
int semaphore_up_(Semaphore * s,
		  const char * filename,
		  const int linenumber);		    

/**
 * @brief Hashing and hash conversion methods.
 */

/**
 * A 160-bit hashcode
 */
typedef struct {
  int a;
  int b;
  int c;
  int d;
  int e;
} HashCode160;

/**
 * The identity of the host (basically the RIPE160 hashcode of
 * it's public key).
 */
typedef struct {
  HashCode160 hashPubKey;
} HostIdentity;


/**
 * Hash2Hex: filename, consisting of 32 bytes [0-9A-Z] plus
 * null-termination.
 */
typedef struct {
  unsigned char data[sizeof(HashCode160)*2+1];
} HexName;

/**
 * ASCII encoding of a HashCode160.
 */
typedef struct {
  unsigned char encoding[33];
} EncName;

/**
 * Convert hash to ASCII encoding.
 * @param block the hash code
 * @param result where to store the encoding (EncName can be
 *  safely cast to char*, a '\0' termination is set).
 */
void hash2enc(const HashCode160 * block,
	      EncName * result);

/**
 * Convert ASCII encoding back to hash
 * @param enc the encoding
 * @param result where to store the hash code 
 * @return OK on success, SYSERR if result has the wrong encoding
 */
int enc2hash(const char * enc,
	     HashCode160 * result);

/**
 * Compute the distance between 2 hashcodes.
 * The computation must be fast, not involve
 * a.a or a.e (they're used elsewhere), and
 * be somewhat consistent. And of course, the
 * result should be a positive number.
 */
int distanceHashCode160(const HashCode160 * a, 
			const HashCode160 * b);
 
/**
 * compare two hashcodes.
 */
int equalsHashCode160(const HashCode160 * a, 
		      const HashCode160 * b);
 
/**
 * Convert (hash) block to hex (= filename)
 * @param block the sequence to convert
 * @param result where to store thestring (\0-terminated), hex-encoding
 */
void hash2hex(const HashCode160 * block,
	      HexName * result);

/**
 * Convert hex (filename) to the hostIdentity
 * @param hex the filename
 * @param hash is set to the correspoinding host identity
 */
void hex2hash(const HexName * hex,
	      HashCode160 * hash);

  /**
 * Convert ch to a hex sequence.  If ch is a HexName, the hex is
 * converted back to a HashCode.  If ch is NULL or an empty string, a
 * random Id is generated.  Otherwise, the hash of the string "ch" is
 * used.
 */
void tryhex2hashOrHashString(const char * ch,
			     HashCode160 * hc);

/**
 * Try converting a hex to a hash.
 * @param ch the hex sequence
 * @param hash the resulting hash code
 * @return OK on success, SYSERR on error
 */
int tryhex2hash(const char * ch,
		HashCode160 * hash);

/**
 * Hash block of given size.
 * @param block the data to hash, length is given as a second argument
 * @param ret pointer to where to write the hashcode
 */
void hash(const void * block,
	  int size,
	  HashCode160 * ret);


/**
 * Compute the hash of an entire file.
 * @return OK on success, SYSERR on error
 */
int getFileHash(const char * filename,
     	        HashCode160 * ret);

/**
 * Check if 2 hosts are the same (returns 1 if yes)
 * @param first the first host
 * @param second the second host
 * @returns 1 if the hosts are the same, 0 otherwise
 */
int hostIdentityEquals(const HostIdentity * first, 
		       const HostIdentity * second);
 
void makeRandomId(HashCode160 * result);

/* compute result(delta) = b - a */
void deltaId(const HashCode160 * a,
	     const HashCode160 * b,
	     HashCode160 * result);

/* compute result(b) = a + delta */
void addHashCodes(const HashCode160 * a,
		  const HashCode160 * delta,
		  HashCode160 * result);

/* compute result = a ^ b */
void xorHashCodes(const HashCode160 * a,
		  const HashCode160 * b,
		  HashCode160 * result);

/**
 * Convert a hashcode into a key.
 */
void hashToKey(const HashCode160 * hc,
	       SESSIONKEY * skey,
	       unsigned char * iv);

/**
 * Obtain a bit from a hashcode.
 * @param code the hash to index bit-wise
 * @param bit index into the hashcode, [0...159]
 * @return Bit \a bit from hashcode \a code, -1 for invalid index
 */
int getHashCodeBit(const HashCode160 * code, 
		   unsigned int bit);

/**
 * Compare function for HashCodes, producing a total ordering
 * of all hashcodes.
 * @return 1 if h1 > h2, -1 if h1 < h2 and 0 if h1 == h2.
 */
int hashCodeCompare(const HashCode160 * h1,
		    const HashCode160 * h2);

/**
 * Find out which of the two hash codes is closer to target
 * in the XOR metric (Kademlia).
 * @return -1 if h1 is closer, 1 if h2 is closer and 0 if h1==h2.
 */
int hashCodeCompareDistance(const HashCode160 * h1,
			    const HashCode160 * h2,
			    const HashCode160 * target);
  

/**
 * @brief Hostkey - management of the node's main identity.
 */

/**
 * We currently do not handle encryption of data
 * that can not be done in a single call to the
 * RSA methods (read: large chunks of data).
 * We should never need that, as we can use
 * the hash for larger pieces of data for signing,
 * and for encryption, we only need to encode sessionkeys!
 */

/**
 * Length of RSA encrypted data (2048 bit)
 */
#define RSA_ENC_LEN 256

/**
 * Length of an RSA KEY (d,e,len), 2048 bit (=256 octests) key d, 2 byte e
 */
#define RSA_KEY_LEN 258

typedef struct {
  unsigned short len; /*  in big-endian! */
  unsigned short sizen;/*  in big-endian! */
  unsigned short sizee;/*  in big-endian! */
  unsigned short sized;/*  in big-endian! */
  unsigned short sizep;/*  in big-endian! */
  unsigned short sizeq;/*  in big-endian! */
  unsigned short sizedmp1;/*  in big-endian! */
  unsigned short sizedmq1;/*  in big-endian! */
} HostKeyEncoded;

/**
 * Generic version of HostKeyEncoded with field for accessing the end of
 * the data structure (use the other version for allocation)
 */
typedef struct {
  HostKeyEncoded host_key_encoded;

  /**
   * Address of this field used for finding the end of the structure
   */
  unsigned char key[1];
} HostKeyEncoded_GENERIC;

typedef struct {
  unsigned char sig[RSA_ENC_LEN]; 
} Signature;

typedef struct {
  unsigned short len; /*  in big-endian, must be RSA_KEY_LEN+2 */
  unsigned short sizen;  /*  in big-endian! */ 
  unsigned char key[RSA_KEY_LEN];
  unsigned short padding; /* padding (must be 0) */
} PublicKey;

typedef struct {
  unsigned char encoding[RSA_ENC_LEN];
} RSAEncryptedData;



/**
 * create a new hostkey. Callee must free return value.
 */
Hostkey makeHostkey(); 

/**
 * Deterministically (!) create a hostkey using only the
 * given HashCode as input to the PRNG.
 */
Hostkey makeKblockKey(const HashCode160 * input);

/**
 * Free memory occupied by hostkey
 * @param hostkey pointer to the memory to free
 */
void freeHostkey(Hostkey hostkey); 

/**
 * Extract the public key of the host.
 * @param result where to write the result.
 */
void getPublicKey(const Hostkey hostkey,
		  PublicKey * result);

/**
 * Encode the private key in a format suitable for
 * storing it into a file.
 * @param hostkey the hostkey to use
 * @returns encoding of the private key.
 */
HostKeyEncoded * encodeHostkey(const Hostkey hostkey);

/**
 * Decode the private key from the file-format back
 * to the "normal", internal, RSA format.
 * @param encoded the encoded hostkey
 * @returns the decoded hostkey
 */
Hostkey decodeHostkey(const HostKeyEncoded * encoding);

/**
 * Encrypt a block with the public key of another
 * host that uses the same cyper.
 * @param block the block to encrypt
 * @param size the size of block
 * @param publicKey the encoded public key used to encrypt
 * @param target where to store the encrypted block
 * @returns SYSERR on error, OK if ok
 */
int encryptHostkey(const void * block, 
		   unsigned short size,
		   const PublicKey * publicKey,
		   RSAEncryptedData * target);

/**
 * Decrypt a given block with the hostkey. 
 * @param hostkey the hostkey to use
 * @param block the data to decrypt, encoded as returned by encrypt, not consumed
 * @param result pointer to a location where the result can be stored
 * @param max the maximum number of bits to store for the result, if
 *        the decrypted block is bigger, an error is returned
 * @returns the size of the decrypted block, -1 on error
 */
int decryptHostkey(const Hostkey hostkey, 
		   const RSAEncryptedData * block,
		   void * result,
		   unsigned int max);

/**
 * Sign a given block.
 * @param block the data to sign, first unsigned short_SIZE bytes give length
 * @param size how many bytes to sign
 * @param result where to write the signature
 * @return SYSERR on error, OK on success
 */
int sign(const Hostkey hostkey, 
	 unsigned short size,
	 const void * block,
	 Signature * result);

/**
 * Verify signature.
 * @param block the signed data
 * @param len the length of the block 
 * @param sig signature
 * @param publicKey public key of the signer
 * @returns OK if ok, SYSERR if invalid
 */
int verifySig(const void * block,
	      unsigned short len,
	      const Signature * sig,	      
	      const PublicKey * publicKey);


/**
 * Methods for initializing things in util in
 * the right order.
 */

/**
 * Method to parse the command line. The results
 * are to be stored in the configuration module.
 * @param argc the number of arguments
 * @param argv the command line arguments
 * @return OK on success, SYSERR if we should abort the
 *   initialization sequence and exit the program
 */
typedef int (*CommandLineParser)(int argc, char * argv[]);

/**
 * Initialize the util module. 
 * @param argc the number of arguments
 * @param argv the command line arguments
 * @param parser parser to call at the right moment
 * @return OK on success, SYSERR if we should abort
 */
int initUtil(int argc,
	     char * argv[],
	     CommandLineParser parser);


/**
 * The configuration was re-loaded. All
 * util modules should check if it has
 * changed for them.
 */
void resetUtil();

/**
 * Shutdown the util services in proper order.
 */
void doneUtil();

/**
 * Common methods for GNUnet clients.
 */

/**
 * Configuration: get the GNUnet port for the client to
 * connect to (via TCP).
 */
unsigned short getGNUnetPort();

/**
 * Configuration: get the GNUnetd host where the client
 * should connect to (via TCP)
 */
char * getGNUnetdHost();

/**
 * Struct to refer to a GNUnet TCP connection. 
 * This is more than just a socket because if the server
 * drops the connection, the client automatically tries
 * to reconnect (and for that needs connection information).
 */
typedef struct {

  /**
   * the socket handle, -1 if invalid / not life 
   */
  int socket;

  /**
   * the following is the IP for the remote host for client-sockets,
   * as returned by gethostbyname("hostname"); server sockets should
   * use 0.
   */
  IPaddr ip;
  
  /**
   * the port number, in host byte order 
   */
  unsigned short port;

  /**
   * Write buffer length for non-blocking writes.
   */ 
  unsigned int outBufLen;

  /**
   * Write buffer for non-blocking writes.
   */ 
  void * outBufPending;

  Mutex readlock; 
  Mutex writelock;

} GNUNET_TCP_SOCKET;

/**
 * Get a GNUnet TCP socket that is connected to gnunetd.
 */
GNUNET_TCP_SOCKET * getClientSocket();

/**
 * Free a Client socket.
 */
void releaseClientSocket(GNUNET_TCP_SOCKET * sock);

/**
 * Directory based implementation of a tiny, stateful database
 * to keep track of GNUnet _internal_ configuration parameters
 * that users are not supposed to see (e.g. *previous* quota,
 * previous database type for AFS, etc.)
 */


/**
 * Read the contents of a bucket to a buffer.
 *
 * @param fn the hashcode representing the entry
 * @param result the buffer to write the result to 
 *        (*result should be NULL, sufficient space is allocated)
 * @return the number of bytes read on success, -1 on failure
 */ 
int stateReadContent(const char * name,
		     void ** result);

/**
 * Append content to file.
 *
 * @param fn the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int stateAppendContent(const char * name,
		       int len,
		       const void * block);

/**
 * Write content to a file. 
 *
 * @param fn the key for the entry
 * @param len the number of bytes in block
 * @param block the data to store
 * @return SYSERR on error, OK if ok.
 */
int stateWriteContent(const char * name,
		      int len,
		      const void * block);

/**
 * Free space in the database by removing one file
 * @param name the hashcode representing the name of the file 
 *        (without directory)
 */
int stateUnlinkFromDB(const char * name);

/**
 * Generic TCP code. This module is used to receive or send records
 * (!) from a TCP stream. The code automatically attempts to
 * re-connect if the other side closes the connection.<br>
 *
 * The code can be used on the server- or the client side, just in
 * case of the server the reconnect can of course not be used. The TCP
 * stream is broken into records of maximum length MAX_BUFFER_SIZE,
 * each preceeded by an unsigned short giving the length of the
 * following record.<p>
 */

/**
 * Initialize a GNUnet client socket.
 * @param port the portnumber in host byte order
 * @param hostname the name of the host to connect to
 * @param result the SOCKET (filled in)
 * @return OK if successful, SYSERR on failure
 */
int initGNUnetClientSocket(unsigned short port,
			   const char * hostname,
			   GNUNET_TCP_SOCKET * result);

/**
 * Initialize a GNUnet client socket.
 * @param port the portnumber in host byte order
 * @param ip IP of the host to connect to
 * @param result the SOCKET (filled in)
 * @return OK if successful, SYSERR on failure
 */
int initGNUnetClientSocketIP(unsigned short port,
			     IPaddr ip,
			     GNUNET_TCP_SOCKET * result);

/**
 * Initialize a GNUnet server socket.
 * @param sock the open socket
 * @param result the SOCKET (filled in)
 * @return OK (always successful)
 */
int initGNUnetServerSocket(int socket,
			   GNUNET_TCP_SOCKET * result);

/**
 * Check if a socket is open. Will ALWAYS return 'true'
 * for a valid client socket (even if the connection is
 * closed), but will return false for a closed server socket.
 * @return 1 if open, 0 if closed
 */
int isOpenConnection(GNUNET_TCP_SOCKET * sock);

/**
 * Check a socket, open and connect if it is closed and it is a
 * client-socket.
 */
int checkSocket(GNUNET_TCP_SOCKET * sock);

/**
 * Read from a GNUnet TCP socket.
 * @param sock the socket
 * @param buffer the buffer to write data to;
 *        if NULL == *buffer, *buffer is allocated (caller frees)
 * @return OK if the read was successful, SYSERR if the socket
 *         was closed by the other side (if the socket is a
 *         client socket and is used again, tcpio will attempt
 *         to re-establish the connection [temporary error]).
 */
int readFromSocket(GNUNET_TCP_SOCKET * sock,
		   CS_HEADER ** buffer);

/**
 * Write to a GNUnet TCP socket.
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return OK if the write was sucessful, otherwise SYSERR.
 */
int writeToSocket(GNUNET_TCP_SOCKET * sock,
		  const CS_HEADER * buffer);

/**
 * Write to a GNUnet TCP socket non-blocking.
 * @param sock the socket to write to
 * @param buffer the buffer to write
 * @return OK if the write was sucessful, NO if it would have blocked and was not performed,
 *         otherwise SYSERR.
 */
int writeToSocketNonBlocking(GNUNET_TCP_SOCKET * sock,
			     const CS_HEADER * buffer);

/**
 * Close a GNUnet TCP socket for now (use to temporarily close
 * a TCP connection that will probably not be used for a long
 * time; the socket will still be auto-reopened by the
 * readFromSocket/writeToSocket methods if it is a client-socket).
 */
void closeSocketTemporarily(GNUNET_TCP_SOCKET * sock);

/**
 * Destroy a socket for good. If you use this socket afterwards,
 * you must first invoke initializeSocket, otherwise the operation
 * will fail.
 */
void destroySocket(GNUNET_TCP_SOCKET * sock);


/**
 * Obtain a return value from a remote call from
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value from TCP
 * @return SYSERR on error, OK if the return value was
 *         read successfully
 */
int readTCPResult(GNUNET_TCP_SOCKET * sock,
		  int * ret);

/**
 * Send a return value to the caller of a remote call via
 * TCP.
 * @param sock the TCP socket
 * @param ret the return value to send via TCP
 * @return SYSERR on error, OK if the return value was
 *         send successfully
 */
int sendTCPResult(GNUNET_TCP_SOCKET * sock,
		  int ret);


/**
 * Obtain option from a peer.
 * @return NULL on error
 */   
char * getConfigurationOptionValue(GNUNET_TCP_SOCKET * sock,
				   const char * section,
				   const char * option);

/**
 * @brief Determine the (external) IP of the local machine.
 *
 * We have many ways to get that IP:
 * a) from the interface (ifconfig)
 * b) via DNS from our HOSTNAME (environment)
 * c) from the configuration (HOSTNAME specification or static IP)
 *
 * Which way applies depends on the OS, the configuration
 * (dynDNS? static IP? NAT?) and at the end what the user 
 * needs.
 */



/**
 * Get the IP address for the local machine.
 * @return SYSERR on error, OK on success
 */
int getPublicIPAddress(IPaddr  * address);

/**
 * Get the IP address for the local machine.
 * @return SYSERR on error, OK on success
 */
int getPublicIP6Address(IP6addr  * address);


/**
 * GNUnet statistics module.
 */


/**
 * Get a handle to a statistical entity.
 * @param name a description of the entity
 * @return a handle for updating the associated value
 */
int statHandle(const char * name);

/**
 * Manipulate statistics.
 * Sets the core-statistics associated with
 * the handle to value.
 * @param handle the handle for the value to change
 * @param value to what the value should be set
 */
void statSet(const int handle,
	     const unsigned long long value);

/**
 * Manipulate statistics.
 * Changes the core-statistics associated with
 * the value by delta.
 * @param handle the handle for the value to change
 * @param delta by how much should the value be changed
 */
void statChange(const int handle,
		const int delta);

/**
 * Opaque handle for client connections passed by
 * the core to the CSHandlers.
 */
typedef struct ClientH * ClientHandle;

/**
 * Send a message to the client identified by the handle.  Note that
 * the core will typically buffer these messages as much as possible
 * and only return SYSERR if it runs out of buffers.  Returning OK
 * on the other hand does NOT confirm delivery since the actual
 * transfer happens asynchronously.
 */
typedef int (*SendToClientCallback)(ClientHandle handle,
				    const CS_HEADER * message);

/**
 * Send statistics to a TCP socket.
 */
int sendStatistics(ClientHandle sock,
		   const CS_HEADER * message,
		   SendToClientCallback callback);


/* ********************* types ************** */

/**
 * Statistics message. Contains the timestamp and an aribtrary
 * (bounded by the maximum CS message size!) number of statistical
 * numbers. If needed, several messages are used.
 */
typedef struct {
  CS_HEADER header;
  /**
   * For 64-bit alignment...
   */
  int reserved;
  /* timestamp  (network byte order)*/
  cron_t startTime;
  /* total number of statistical counters */
  int totalCounters;
  /* number of statistical counters in this message */
  int statCounters;

} STATS_CS_MESSAGE;

/**
 * Generic version of STATS_CS_MESSAGE with field for finding the end
 * of the struct. Use the other version for allocation.
 */
typedef struct {
  STATS_CS_MESSAGE stats_cs_message;

  /* values[statCounters] */
  unsigned long long values[1];

  /* description for each of the values,
     separated by '\0'-terminators; the
     last description is also terminated 
     by a '\0'; again statCounters entries */
  /* char descriptions[0]; */
} STATS_CS_MESSAGE_GENERIC;

/**
 * Query protocol supported message.  Contains the type of
 * the message we are requesting the status of.
 */
typedef struct {
  CS_HEADER header;

  /**
   * For 64-bit alignment...
   */
  int reserved;

  /**
   * The type of the message (XX_CS_PROTO_XXXX) 
   * we want to know the status of.
   */
  unsigned short tcpType;

} STATS_CS_GET_MESSAGE_SUPPORTED;


/** 
 * Status calls implementation.  Usage is how much we are using
 * (relative to what is available). Load is what we are using relative
 * to what we are allowed to use.
 */

/**
 * The following routine returns the percentage of available used
 * bandwidth.  A number from 0-100 is returned.  Example: If 81 is
 * returned this means that 81% of the network bandwidth of the host
 * is consumed.
 */
int networkUsageUp();

/**
 * The following routine returns the percentage of available used
 * bandwidth. A number from 0-100 is returned.  Example: If 81 is
 * returned this means that 81% of the network bandwidth of the host
 * is consumed.
 */
int networkUsageDown();

/**
 * The following routine returns a positive number which indicates
 * the percentage CPU usage. 100 corresponds to one runnable process
 * on average.
 */
int cpuUsage();

/**
 * Get the load of the CPU relative to what is allowed.
 * 
 * @return the CPU load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getCPULoad();

/**
 * Get the load of the network relative to what is allowed.
 * The only difference to networkUsageUp is that
 * this function averages the values over time.
 *
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getNetworkLoadUp();

/**
 * Get the load of the network relative to what is allowed.
 * The only difference to networkUsageDown is that
 * this function averages the values over time.
 *
 * @return the network load as a percentage of allowed
 *        (100 is equivalent to full load)
 */
int getNetworkLoadDown();

/**
 * Tell statuscalls to increment the number of bytes sent
 */
void incrementBytesSent(unsigned long long delta);

/**
 * Tell statuscalls to increment the number of bytes received
 */
void incrementBytesReceived(unsigned long long delta);

/**
 * Storage - management of the node's files.
 */

/**
 * Get the size of the file (or directory)
 * of the given file (in bytes).
 */
unsigned long long getFileSize(const char * filename);

/**
 * Get the size of the file (or directory) without
 * counting symlinks.
 */
unsigned long long getFileSizeWithoutSymlinks(const char * filename);

/**
 * Get the number of blocks that are left on the partition that
 * contains the given file (for normal users).
 *
 * @param part a file on the partition to check
 * @return -1 on errors, otherwise the number of free blocks
 */
long getBlocksLeftOnDrive(const char * part);

/**
 * Assert that fil corresponds to a filename
 * (of a file that exists and that is not a directory).
 * @returns 1 if yes, 0 if not (will print an error
 * message in that case, too).
 */
int assertIsFile(const char * fil);

/**
 * Complete filename (a la shell) from abbrevition.
 * @param fil the name of the file, may contain ~/ or 
 *        be relative to the current directory
 * @returns the full file name, 
 *          NULL is returned on error
 */
char * expandFileName(const char * fil);

/**
 * Implementation of "mkdir -p"
 * @param dir the directory to create
 * @returns SYSERR on failure, OK otherwise
 */
int mkdirp(const char * dir);

/**
 * Read the contents of a binary file into a buffer.
 * @param fileName the name of the file, not freed,
 *        must already be expanded!
 * @param len the maximum number of bytes to read
 * @param result the buffer to write the result to
 * @return the number of bytes read on success, -1 on failure
 */ 
int readFile(const char * fileName,
	     int len,
	     void * result);

/**
 * Write a buffer to a file.
 * @param fileName the name of the file, NOT freed!
 * @param buffer the data to write
 * @param n number of bytes to write
 * @param mode the mode for file permissions
 */ 
void writeFile(const char * fileName, 
	       const void * buffer,
	       int n,
	       const char * mode);

/**
 * Build a filename from directory and filename, completing like the shell does
 * @param dir the name of the directory, may contain ~/ or other shell stuff. Will 
 *        NOT be freed!
 * @param fil the name of the file, will NOT be deallocated anymore!
 * @param result where to store the full file name (must be large enough!)
 */
void buildFileName(const char * dir,
		   const EncName * fil,
		   char * result);

typedef void (*DirectoryEntryCallback)(const char * filename,
				       const char * dirName,
				       void * data);

/**
 * Scan a directory for files. The name of the directory
 * must be expanded first (!).
 * @param dirName the name of the directory
 * @param callback the method to call for each file
 * @param data argument to pass to callback
 * @return the number of files found, -1 on error
 */
int scanDirectory(const char * dirName,
		  DirectoryEntryCallback callback,
		  void * data);

/**
 * Test if fil is a directory.
 * @returns YES if yes, NO if not
 */
int isDirectory(const char * fil);

/**
 * Remove all files in a directory (rm -rf). Call with
 * caution.
 *
 *
 * @param fileName the file to remove
 * @return OK on success, SYSERR on error
 */
int rm_minus_rf(const char * fileName);

/* use the CLOSE macro... */
void close_(int fd, const char * filename, int linenumber);

#define CLOSE(fd) close_(fd, __FILE__, __LINE__)




/**
 * Stop the application.
 * @param signum is ignored
 */
void run_shutdown(int signum);

/**
 * Test if the shutdown has been initiated.
 * @return YES if we are shutting down, NO otherwise
 */
int testShutdown();

/**
 * Initialize the signal handlers, etc.
 */
void initializeShutdownHandlers();

/**
 * Wait until the shutdown has been initiated.
 */
void wait_for_shutdown();


void doneShutdownHandlers();


typedef struct {
  char shortArg;
  char * longArg;
  char * mandatoryArg;
  char * description;
} Help;

#define HELP_HELP \
  { 'h', "help", NULL,				\
    gettext_noop("print this help") }
#define HELP_LOGLEVEL \
  { 'L', "loglevel", "LEVEL",			\
    gettext_noop("set verbosity to LEVEL") }
#define HELP_CONFIG \
  { 'c', "config", "FILENAME",			\
    gettext_noop("use configuration file FILENAME") }
#define HELP_HOSTNAME \
  { 'H', "host", "HOSTNAME",			\
    gettext_noop("specify host on which gnunetd is running") }
#define HELP_VERSION \
  { 'v', "version", NULL,			\
    gettext_noop("print the version number") }
#define HELP_VERBOSE \
  { 'V', "verbose", NULL,			\
    gettext_noop("be verbose") }
#define HELP_END \
    { 0, NULL, NULL, NULL, }

/**
 * Print output of --help in GNU format.
 */
void formatHelp(const char * general,
		const char * description,
		const Help * opt);

/**
 * Parse the default set of options and set
 * options in the configuration accordingly.
 * This does not include --help or --version.
 * @return YES if the option was a default option
 *  that was successfully processed
 */
int parseDefaultOptions(char c,
			char * optarg);

/**
 * Default "long" version of the options, use
 * "vhdc:L:H:" in the short option argument 
 * to getopt_long for now.
 */
#define LONG_DEFAULT_OPTIONS \
      { "config",        1, 0, 'c' }, \
      { "version",       0, 0, 'v' }, \
      { "help",          0, 0, 'h' }, \
      { "debug",         0, 0, 'd' }, \
      { "loglevel",      1, 0, 'L' }, \
      { "host",          1, 0, 'H' }





typedef struct {
  /** The bit counter file on disk */
  int fd;
  /** How many bits we set for each stored element */  
  unsigned int addressesPerElement;
  /** The actual bloomfilter bit array */
  char * bitArray;
  /** Size of bitArray in bytes */
  unsigned int bitArraySize;
  /** Concurrency control */
  Mutex lock;
  /** Statistics handle for filter hits */
  int statHandle_hits;
  /** Statistics handle for filter misses */
  int statHandle_misses;
  /** Statistics handle for adds to filter */
  int statHandle_adds;
  /** Statistics handle for dels from filter */
  int statHandle_dels;

} Bloomfilter;

/**
 * Load a bloom-filter from a file.
 * @param filename the name of the file (or the prefix)
 * @param size the size of the bloom-filter (number of
 *        bytes of storage space to use)
 * @param k the number of hash-functions to apply per
 *        element (number of bits set per element in the set)
 * @return the bloomfilter
 */
Bloomfilter * loadBloomfilter(const char * filename,
			      unsigned int size,
			      unsigned int k);

/**
 * Test if an element is in the filter.
 * @param e the element
 * @param bf the filter
 * @return YES if the element is in the filter, NO if not
 */
int testBloomfilter(Bloomfilter * bf,
		    const HashCode160 * e);

/**
 * Add an element to the filter
 * @param bf the filter
 * @param e the element
 */
void addToBloomfilter(Bloomfilter * bf,
		      const HashCode160 * e);

/**
 * Remove an element from the filter.
 * @param bf the filter
 * @param e the element to remove
 */
void delFromBloomfilter(Bloomfilter * bf,
			const HashCode160 * e);

/**
 * Free the space associcated with a filter
 * in memory, flush to drive if needed (do not
 * free the space on the drive)
 * @param bf the filter
 */
void freeBloomfilter(Bloomfilter * bf);

/**
 * Reset a bloom filter to empty.
 * @param bf the filter
 */
void resetBloomfilter(Bloomfilter * bf);

typedef HashCode160 * (*ElementIterator)(void * arg);

/**
 * Resize a bloom filter.  Note that this operation
 * is pretty costly.  Essentially, the bloom filter
 * needs to be completely re-build.
 *
 * @param bf the filter
 * @param iterator an iterator over all elements stored in the BF
 * @param iterator_arg argument to the iterator function
 * @param size the new size for the filter
 * @param k the new number of hash-function to apply per element
 */
void resizeBloomfilter(Bloomfilter * bf,
		       ElementIterator iterator,
		       void * iterator_arg,
		       unsigned int size,
		       unsigned int k);


/**
 * Depending on doBlock, enable or disable the nonblocking mode
 * of socket s.
 *
 * @return Upon successful completion, it returns zero.
 * @return Otherwise -1 is returned.
 */
int setBlocking(int s, int doBlock);


/**
 * Check whether the socket is blocking
 * @param s the socket
 * @return YES if blocking, NO non-blocking
 */
int isSocketBlocking(int s);


/**
 * Do a NONBLOCKING read on the given socket.  Note that in order to
 * avoid blocking, the caller MUST have done a select call before
 * calling this function.
 *
 * Reads at most max bytes to buf.  On error, return SYSERR (errors
 * are blocking or invalid socket but NOT a partial read).  Interrupts
 * are IGNORED.
 *
 * @return the number of bytes read or SYSERR. 
 *         0 is returned if no more bytes can be read
 */ 
int RECV_NONBLOCKING(int s,
		     void * buf,
		     size_t max);


/**
 * Do a BLOCKING read on the given socket.  Read len bytes (if needed
 * try multiple reads).  Interrupts are ignored.
 *
 * @return SYSERR if len bytes could not be read,
 *   otherwise the number of bytes read (must be len)
 */
int RECV_BLOCKING_ALL(int s,
		      void * buf,
		      size_t len);


/**
 * Do a NONBLOCKING write on the given socket.
 * Write at most max bytes from buf.  On error,
 * return SYSERR (errors are blocking or invalid
 * socket but NOT an interrupt or partial write).
 * Interrupts are ignored (cause a re-try).
 *
 * @return the number of bytes written or SYSERR. 
 */ 
int SEND_NONBLOCKING(int s,
		     const void * buf,
		     size_t max);


/**
 * Do a BLOCKING write on the given socket.  Write len bytes (if
 * needed do multiple write).  Interrupts are ignored (cause a
 * re-try).
 *
 * @return SYSERR if len bytes could not be send,
 *   otherwise the number of bytes transmitted (must be len)
 */
int SEND_BLOCKING_ALL(int s,
		      const void * buf,
		      size_t len);

/**
 * Check if socket is valid
 * @return 1 if valid, 0 otherwise
 */
int isSocketValid(int s);

/**
 * Like snprintf, just aborts if the buffer is of insufficient size.
 */
int SNPRINTF(char * buf,
	     size_t size,
	     const char * format,
	     ...);


typedef struct vector_t {
  unsigned int VECTOR_SEGMENT_SIZE;
  struct vector_segment_t * segmentsHead;
  struct vector_segment_t * segmentsTail;
  struct vector_segment_t * iteratorSegment;
  unsigned int iteratorIndex;
  size_t size;
} Vector;


/**
 * A debug function that dumps the vector to stderr.
 */
void vectorDump(Vector *v);

/**
 * @param vss Size of the VectorSegment data area. The "correct" value for this
 * is a bit of a gamble, as it depends on both the operations you
 * perform on the vectors and how much data is stored in them. In
 * general, the more data you store the bigger the segments should be,
 * or otherwise the increased length of the linked list will become a
 * bottleneck for operations that are performed on arbitrary indexes.
 */
Vector * vectorNew(unsigned int vss);

/**
 * Free vector structure including its data segments, but _not_ including the
 * stored void pointers. It is the user's responsibility to empty the vector
 * when necessary to avoid memory leakage.
 */
void vectorFree(Vector * v);

size_t vectorSize(const Vector * v);

/**
 * Insert a new element in the vector at given index. 
 * @return OK on success, SYSERR if the index is out of bounds.
 */
int vectorInsertAt(Vector * v, 
		   void * object,
		   unsigned int index);

/**
 * Insert a new element at the end of the vector.
 */
void vectorInsertLast(Vector * v, void * object);

/**
 * Return the element at given index in the vector or NULL if the index is out
 * of bounds. The iterator is set to point to the returned element.
 */
void * vectorGetAt(Vector * v, 
		   unsigned int index);

/** 
 * Return the first element in the vector, whose index is 0, or NULL if the
 * vector is empty. The iterator of the vector is set to point to the first
 * element.
 */
void * vectorGetFirst(Vector * v);

/**
 * Return the last element in the vector or NULL if the vector is empty. The
 * iterator of the vector is set to point to the last element.
 */
void * vectorGetLast(Vector * v);

/**
 * Return the next element in the vector, as called after vector_get_at() or
 * vector_get_first(). The return value is NULL if there are no more elements
 * in the vector or if the iterator has not been set. 
 */
void * vectorGetNext(Vector * v);

/**
 * Return the previous element in the vector, as called after vector_get_at()
 * or vector_get_last(). The return value is NULL if there are no more
 * elements in the vector or if the iterator has not been set.
 */
void * vectorGetPrevious(Vector * v);

/**
 * Delete and return the element at given index. NULL is returned if index is 
 * out of bounds. 
 */
void * vectorRemoveAt(Vector * v, 
		      unsigned int index);

/**
 * Delete and return the last element in the vector, or NULL if the vector
 * is empty.
 */
void * vectorRemoveLast(Vector * v);

/**
 * Delete and return given object from the vector, or return NULL if the object
 * is not found.
 */
void * vectorRemoveObject(Vector * v, void * object);

/**
 * Set the given index in the vector. The old value of the index is 
 * returned, or NULL if the index is out of bounds.
 */
void * vectorSetAt(Vector * v,
		   void * object, 
		   unsigned int index);

/**
 * Set the index occupied by the given object to point to the new object.
 * The old object is returned, or NULL if it's not found.
 */
void * vectorSetObject(Vector * v, 
		       void * object,
		       void * old_object);

/** 
 * Swaps the contents of index1 and index2. Return value is OK
 * on success, SYSERR if either index is out of bounds.
 */
int vectorSwap(Vector * v, 
	       unsigned int index1, 
	       unsigned int index2);

/**
 * Return the index of given element or -1 if the element is not found.
 */
unsigned int vectorIndexOf(Vector * v, 
			   void * object);

/**
 * Return the data stored in the vector as a single dynamically
 * allocated array of (void *), which must be FREEed by the caller.
 * Use the functions get_{at,first,last,next,previous} instead, unless
 * you really need to access everything in the vector as fast as
 * possible.
 */
void ** vectorElements(Vector * v);



#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_UTIL_H */
#endif
/* end of gnunet_util.h */

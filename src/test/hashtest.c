/** 
 * @file test/hashtest.c
 * @brief testcase for util/hashing.c
 **/

#include "gnunet_util.h"
#include "platform.h"

int main(int argc, char * argv[]){
  HashCode160 hc;
  HexName hex;

  hash("TEST", 4, &hc);
  if ( (hc.a != ntohl(830102737)) ||
       (hc.b != ntohl(-2066785626)) ||
       (hc.c != ntohl(-326698784)) ||
       (hc.d != ntohl(-183450437)) ||
       (hc.e != ntohl(1019905624)) ) {
    printf("Hash of TEST wrong (%d, %d, %d, %d, %d).\n",
	   hc.a, hc.b, hc.c, hc.d, hc.e);
    return -1;
  }
  hash2hex(&hc,
	   &hex);
  if (0 != strcmp((char*)&hex,
		  "13A7C51D48FCA56ACE688F0E5F014CBBC3AC6885")) {
    printf("hash2hex of TEST wrong: %s\n",
	   (char*)&hex);
    return -1;
  }    
  hash(NULL, 0, &hc);
  if ( (hc.a != ntohl(-1676573275)) ||
       (hc.b != ntohl(-974521260)) ||
       (hc.c != ntohl(1630013591)) ||
       (hc.d != ntohl(2129196360)) ||
       (hc.e != ntohl(-1306161871)) ) {
    printf("Hash of nothing (0-size) wrong  (%d, %d, %d, %d, %d).\n",
	   hc.a, hc.b, hc.c, hc.d, hc.e);
    return -1;
  }
  return 0;
}

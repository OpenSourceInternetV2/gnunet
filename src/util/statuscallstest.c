/** 
 * @file util/statuscallstest.c
 * @brief testcase for util/statuscalls.c
 */

#include "gnunet_util.h"
#include "platform.h"

/**
 * Perform option parsing from the command line. 
 */
static int parseCommandLine(int argc, 
			    char * argv[]) {
  char c;

  FREENONNULL(setConfigurationString("GNUNETD",
				     "_MAGIC_",
				     "YES"));
  FREENONNULL(setConfigurationString("",
				     "GNUNETD_HOME",
				     "/tmp/gnunet_test/"));
  FREENONNULL(setConfigurationString("FILES",
				     "gnunet.conf",
				     "/tmp/gnunet_test/gnunet.conf"));
  while (1) {
    int option_index = 0;
    static struct GNoption long_options[] = {
      { "config",  1, 0, 'c' },
      { 0,0,0,0 }
    };
    
    c = GNgetopt_long(argc,
		      argv, 
		      "c:", 
		      long_options, 
		      &option_index);
    
    if (c == -1) 
      break;  /* No more flags to process*/
    
    switch(c) {
    case 'c': 
      FREENONNULL(setConfigurationString("FILES",
					 "gnunet.conf",
					 GNoptarg));
      break;
    } /* end of parsing commandline */
  }
  return OK;
}

int main(int argc, char * argv[]){
  int i;
  int ret;
  cron_t start;

  if (OK != initUtil(argc, argv, &parseCommandLine))
    errexit("Error during initialization!\n");

  for (i=0;i<3;i++) {
    if (cpuUsage() == -1) {
      printf("cpuUsage == -1\n");
      return -1;
    }
    if (networkUsageUp() == -1) {
      printf("networkUsageUp == -1\n");    
      return -1;
    }
    if (networkUsageDown() == -1) {
      printf("networkUsageDown == -1\n");    
      return -1;
    }
    sleep(1);
  }
  /* need to run each phase for more than 10s since
     statuscalls only refreshes that often... */
  cronTime(&start);
  while (start + 12 * cronSECONDS > cronTime(NULL))
    sleep(1);
  cronTime(&start);
  ret = cpuUsage();
  while (start + 12 * cronSECONDS > cronTime(NULL))
    sqrt(245.2523); /* do some processing to drive load up */
  if (ret > cpuUsage()) 
    printf("busy loop decreased CPU load: %d < %d.\n",
	   ret,
	   cpuUsage());
  
  /* make sure we don't leak open files... */
  for (i=0;i<10000;i++) {
    if (cpuUsage() == -1)
      return -1;
    if (networkUsageUp() == -1)
      return -1;
    if (networkUsageDown() == -1)
      return -1;
  }
  doneUtil();

  return 0;
}

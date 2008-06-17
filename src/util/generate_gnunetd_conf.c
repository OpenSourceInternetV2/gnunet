#include <stdio.h>
void  generate_gnunetd_conf (FILE * f) {
 fprintf(f, "%s\n","# This is the configuration for the GNUnet daemon, gnunetd.");
 fprintf(f, "%s\n","# Copy this file to \"/etc/gnunet.conf\" if you are root. ");
 fprintf(f, "%s\n","# For any other location, you must explicitly tell gnunetd");
 fprintf(f, "%s\n","# where this file is (option -c FILENAME).");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# After any change in this file, you may want to manually restart");
 fprintf(f, "%s\n","# gnunetd since some changes are only recognized after a re-start.");
 fprintf(f, "%s\n","# Sending a SIGHUP to gnunetd will trigger re-reading the following");
 fprintf(f, "%s\n","# options:");
 fprintf(f, "%s\n","# NETWORK: HELOEXCHANGE");
 fprintf(f, "%s\n","# GNUNETD: LOGLEVEL");
 fprintf(f, "%s\n","# LOAD: INTERFACES");
 fprintf(f, "%s\n","# LOAD: BASICLIMITING");
 fprintf(f, "%s\n","# LOAD: MAXNETDOWNBPSTOTAL");
 fprintf(f, "%s\n","# LOAD: MAXNETUPBPSTOTAL");
 fprintf(f, "%s\n","# LOAD: MAXCPULOAD");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# This file is structured as follows.");
 fprintf(f, "%s\n","# 1) GNUNETD_HOME - base directory for all GNUnet files");
 fprintf(f, "%s\n","# 2) gnunetd options (which transport and application services, logging)");
 fprintf(f, "%s\n","# 3) network configuration ");
 fprintf(f, "%s\n","# 4) load management (resource limitations)");
 fprintf(f, "%s\n","# 5) UDP, TCP and SMTP transport configuration");
 fprintf(f, "%s\n","# 6) configuration for anonymous file sharing (AFS)");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","#################################################");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# This line gives the root-directory of the GNUnet installation. Make");
 fprintf(f, "%s\n","# sure there is some space left in that directory. :-)  Users inserting");
 fprintf(f, "%s\n","# or indexing files will be able to store data in this directory");
 fprintf(f, "%s\n","# up to the (global) quota specified below.  Having a few gigabytes");
 fprintf(f, "%s\n","# of free space is recommended.");
 fprintf(f, "%s\n","# Default: GNUNETD_HOME     = /var/lib/GNUnet");
 fprintf(f, "%s\n","GNUNETD_HOME     = /var/lib/GNUnet");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","#########################################");
 fprintf(f, "%s\n","# Options for the GNUnet server, gnunetd");
 fprintf(f, "%s\n","#########################################");
 fprintf(f, "%s\n","[GNUNETD]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# How many minutes is the current IP valid?  (GNUnet will sign HELO");
 fprintf(f, "%s\n","# messages with this expiration timeline. If you are on dialup, 60");
 fprintf(f, "%s\n","# (for 1 hour) is suggested. If you are having a static IP address,");
 fprintf(f, "%s\n","# you may want to set this to a large value (say 14400).  The default");
 fprintf(f, "%s\n","# is 1440 (1 day). If your IP changes periodically, you will want to");
 fprintf(f, "%s\n","# choose the expiration to be smaller than the frequency with which");
 fprintf(f, "%s\n","# your IP changes.");
 fprintf(f, "%s\n","# The largest legal value is 14400 (10 days).");
 fprintf(f, "%s\n","# Default: HELOEXPIRES     = 1440");
 fprintf(f, "%s\n","HELOEXPIRES     = 1440");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Loglevel, how much should be logged? You can use NOTHING, FATAL,");
 fprintf(f, "%s\n","# ERROR, FAILURE, WARNING, MESSAGE, INFO, DEBUG, CRON or EVERYTHING");
 fprintf(f, "%s\n","# (which log more and more messages in this order). Default is");
 fprintf(f, "%s\n","# WARNING.");
 fprintf(f, "%s\n","LOGLEVEL        = WARNING");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# In which file should gnunetd write the logs?  If you specify");
 fprintf(f, "%s\n","# nothing, logs are written to stderr (and note that if gnunetd runs");
 fprintf(f, "%s\n","# in the background, stderr is closed and all logs are discarded).");
 fprintf(f, "%s\n","# Default: LOGFILE         = $GNUNETD_HOME/logs");
 fprintf(f, "%s\n","LOGFILE         = $GNUNETD_HOME/logs");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# In which file should gnunetd write the process-id of the server?  If");
 fprintf(f, "%s\n","# you run gnunetd as root, you may want to choose");
 fprintf(f, "%s\n","# /var/run/gnunetd.pid. It's not the default since gnunetd may not");
 fprintf(f, "%s\n","# have write rights at that location.");
 fprintf(f, "%s\n","# Default: PIDFILE         = $GNUNETD_HOME/gnunetd.pid");
 fprintf(f, "%s\n","PIDFILE         = $GNUNETD_HOME/gnunetd.pid");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# This directory should be made available periodically --- it contains");
 fprintf(f, "%s\n","# information how to join GNUnet that is in no way private to the");
 fprintf(f, "%s\n","# local node.  This directory can be shared between nodes AND should");
 fprintf(f, "%s\n","# be put on a public web-server (if possible).  You should find a list");
 fprintf(f, "%s\n","# of known hosts under http://www.ovmj.org/GNUnet/hosts/, you can copy");
 fprintf(f, "%s\n","# those files into this directory.");
 fprintf(f, "%s\n","# ");
 fprintf(f, "%s\n","# If you specify a HOSTLISTURL, the directory will be automatically");
 fprintf(f, "%s\n","# populated by gnunetd with an initial set of nodes.");
 fprintf(f, "%s\n","# Default: HOSTS   	= $GNUNETD_HOME/data/hosts/");
 fprintf(f, "%s\n","HOSTS   	= $GNUNETD_HOME/data/hosts/");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# GNUnet can automatically update the hostlist from the web. While");
 fprintf(f, "%s\n","# GNUnet internally communicates which hosts are online, it is");
 fprintf(f, "%s\n","# typically a good idea to get a fresh hostlist whenever gnunetd");
 fprintf(f, "%s\n","# starts from the WEB. By setting this option, you can specify from");
 fprintf(f, "%s\n","# which server gnunetd should try to download the hostlist. The");
 fprintf(f, "%s\n","# default should be fine for now.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The general format is a list of space-separated URLs.  Each URL must");
 fprintf(f, "%s\n","# have the format http://HOSTNAME/FILENAME");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# If you want to setup an alternate hostlist server, you must run a");
 fprintf(f, "%s\n","# permanent node and \"cat data/hosts/* > hostlist\" every few minutes");
 fprintf(f, "%s\n","# to keep the list up-to-date.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# If you do not specify a HOSTLISTURL, you must copy valid hostkeys to");
 fprintf(f, "%s\n","# data/hosts manually.");
 fprintf(f, "%s\n","# Default: HOSTLISTURL = \"http://www.ovmj.org/GNUnet/download/hostlist http://www.woodtick.co.uk/hostlist\"");
 fprintf(f, "%s\n","HOSTLISTURL = \"http://www.ovmj.org/GNUnet/download/hostlist http://www.woodtick.co.uk/hostlist\"");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# If you have to use a proxy for outbound HTTP connections,");
 fprintf(f, "%s\n","# specify the proxy configuration here.  Default is no proxy.");
 fprintf(f, "%s\n","# HTTP-PROXY = localhost");
 fprintf(f, "%s\n","# HTTP-PROXY-PORT = 1080");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Which applications should gnunetd support? Specify the name of the");
 fprintf(f, "%s\n","# dynamic shared object (DSO) that implements the service in the");
 fprintf(f, "%s\n","# gnunetd core here. Separate multiple modules with spaces.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Currently, the available applications are:");
 fprintf(f, "%s\n","# afs: anonymous file sharing");
 fprintf(f, "%s\n","# chat: broadcast chat (demo-application)");
 fprintf(f, "%s\n","# tbench: benchmark tool for transport performance");
 fprintf(f, "%s\n","# tracekit: GNUnet topology visualization toolkit");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# All protocols but \"afs\" are potential security risks");
 fprintf(f, "%s\n","# and have been engineered for testing GNUnet or demonstrating how");
 fprintf(f, "%s\n","# GNUnet works. They should be used with caution.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Typical choices are: \"afs chat tbench tracekit\"");
 fprintf(f, "%s\n","# Default: APPLICATIONS = \"afs tbench tracekit\"");
 fprintf(f, "%s\n","APPLICATIONS = \"afs tbench tracekit\"");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Which transport mechanisms are available? Use space-separated list");
 fprintf(f, "%s\n","# of the modules, e.g.  \"udp smtp tcp\". The order is irrelevant, each");
 fprintf(f, "%s\n","# protocol has a build-in cost-factor and this factor determines which");
 fprintf(f, "%s\n","# protocols are preferred.  ");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The available transports at this point are udp, tcp, http, smtp,");
 fprintf(f, "%s\n","# tcp6, udp6 and the special 'nat' service.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Loading the 'nat' and 'tcp' modules is required for peers behind NAT");
 fprintf(f, "%s\n","# boxes that cannot directly be reached from the outside.  Peers that");
 fprintf(f, "%s\n","# are NOT behind a NAT box and that want to *allow* peers that ARE");
 fprintf(f, "%s\n","# behind a NAT box to connect must ALSO load the 'nat' module.  Note");
 fprintf(f, "%s\n","# that the actual transfer will always be via tcp initiated by the peer");
 fprintf(f, "%s\n","# behind the NAT box.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Usually, the default is just fine for most people.");
 fprintf(f, "%s\n","# Choices are: \"udp tcp udp6 tcp6 nat http smtp\"");
 fprintf(f, "%s\n","# Default: TRANSPORTS = \"udp tcp nat\"");
 fprintf(f, "%s\n","TRANSPORTS = \"udp tcp nat\"");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","############################################");
 fprintf(f, "%s\n","# Network configuration");
 fprintf(f, "%s\n","############################################");
 fprintf(f, "%s\n","[NETWORK]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Which is the client-server port that is used between gnunetd and the");
 fprintf(f, "%s\n","# clients (TCP only).  You may firewall this port for non-local");
 fprintf(f, "%s\n","# machines.");
 fprintf(f, "%s\n","# Default: PORT = 2087");
 fprintf(f, "%s\n","PORT = 2087");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Set if GNUnet fails to determine your IP.  GNUnet first tries to");
 fprintf(f, "%s\n","# determine your IP by looking at the IP that matches the interface");
 fprintf(f, "%s\n","# that is given with the option INTERFACE.");
 fprintf(f, "%s\n","# Under Windows, specify the index number reported by");
 fprintf(f, "%s\n","#  \"gnunet-win-tool -n\"");
 fprintf(f, "%s\n","# Default: INTERFACE = eth0");
 fprintf(f, "%s\n","INTERFACE = eth0");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# If this fails, GNUnet will try to do a DNS lookup on your HOSTNAME,");
 fprintf(f, "%s\n","# which may also fail, in particular if you are on dialup.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# If both options are not viable for you, you can specify an IP in");
 fprintf(f, "%s\n","# this configuration file.  This may be required if you have multiple");
 fprintf(f, "%s\n","# interfaces (currently GNUnet can only work on one of them) or if you");
 fprintf(f, "%s\n","# are behind a router/gateway that performs network address");
 fprintf(f, "%s\n","# translation (NAT). In the latter case, set this IP to the *external*");
 fprintf(f, "%s\n","# IP of the router (!) and make sure that the router forwards incoming");
 fprintf(f, "%s\n","# UDP packets on the GNUnet port (default: 2086) to the dedicated");
 fprintf(f, "%s\n","# GNUnet server in the local network.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The given example value (127.0.0.1) will NOT work!  If you do not know");
 fprintf(f, "%s\n","# what all this means, try without!");
 fprintf(f, "%s\n","# Default is no IP specified.");
 fprintf(f, "%s\n","# IP  	= 127.0.0.1");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# If this host is connected to two networks, a private which is not");
 fprintf(f, "%s\n","# reachable from the Internet and that contains GNUnet clients and to");
 fprintf(f, "%s\n","# a public network, typically the Internet (and is this host is thus");
 fprintf(f, "%s\n","# in the position of a router, typically doing NAT), then this option");
 fprintf(f, "%s\n","# should be set to 'NO'. It prevents the node from forwarding HELOs");
 fprintf(f, "%s\n","# other than its own. If you do not know what the above is about, just");
 fprintf(f, "%s\n","# keep it set to YES (which is also the default when the option is not");
 fprintf(f, "%s\n","# given).");
 fprintf(f, "%s\n","# Default is yes: HELOEXCHANGE = YES");
 fprintf(f, "%s\n","HELOEXCHANGE = YES");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# With this option, you can specify which networks are trusted enough");
 fprintf(f, "%s\n","# to connect as clients to the TCP port.  This is useful if you run");
 fprintf(f, "%s\n","# gnunetd on one host of your network and want to allow all other");
 fprintf(f, "%s\n","# hosts to use this node as their server. By default, this is set to");
 fprintf(f, "%s\n","# 'loopback only'. The format is the same as for the BLACKLIST.");
 fprintf(f, "%s\n","# Default is: TRUSTED = 127.0.0.0/8;");
 fprintf(f, "%s\n","TRUSTED = 127.0.0.0/8;");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","######################################");
 fprintf(f, "%s\n","# Options for load management ");
 fprintf(f, "%s\n","######################################");
 fprintf(f, "%s\n","[LOAD]");
 fprintf(f, "%s\n","# In this section you specify how many resources GNUnet is allowed to");
 fprintf(f, "%s\n","# use. GNUnet may exceed the limits by a small margin (network & CPU");
 fprintf(f, "%s\n","# are hard to control directly), but should do a reasonable job to");
 fprintf(f, "%s\n","# keep the average around these values");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# For which interfaces should we do accounting?  GNUnet will evaluate");
 fprintf(f, "%s\n","# the total traffic (not only the GNUnet related traffic) and adjust");
 fprintf(f, "%s\n","# its bandwidth usage accordingly. You can currently only specify a");
 fprintf(f, "%s\n","# single interface. GNUnet will also use this interface to determine");
 fprintf(f, "%s\n","# the IP to use. Typical values are eth0, ppp0, eth1, wlan0, etc.");
 fprintf(f, "%s\n","# 'ifconfig' will tell you what you have.  Never use 'lo', that just");
 fprintf(f, "%s\n","# won't work.");
 fprintf(f, "%s\n","# Under Windows, specify the index number reported by");
 fprintf(f, "%s\n","#  \"gnunet-win-tool -n\".");
 fprintf(f, "%s\n","# Default is: INTERFACES      = eth0");
 fprintf(f, "%s\n","INTERFACES      = eth0");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Use basic bandwidth limitation? YES or NO.  The basic method (YES)");
 fprintf(f, "%s\n","# notes only GNUnet traffic and can be used to specify simple maximum");
 fprintf(f, "%s\n","# bandwidth usage of GNUnet.  Choose the basic method if you don't");
 fprintf(f, "%s\n","# want other network traffic to interfere with GNUnet's operation, but");
 fprintf(f, "%s\n","# still wish to constrain GNUnet's bandwidth usage, or if you can't");
 fprintf(f, "%s\n","# reliably measure the maximum capabilities of your connection.  YES");
 fprintf(f, "%s\n","# can be very useful if other applications are causing a lot of");
 fprintf(f, "%s\n","# traffic on your LAN.  In this case, you do not want to limit the");
 fprintf(f, "%s\n","# traffic that GNUnet can inflict on your WAN connection whenever your");
 fprintf(f, "%s\n","# high-speed LAN gets used (e.g. by NFS).");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The advanced bandwidth limitation (NO) measures total traffic over");
 fprintf(f, "%s\n","# the chosen interface (including traffic by other applications), and");
 fprintf(f, "%s\n","# allows gnunetd to participate if the total traffic is low enough.");
 fprintf(f, "%s\n","# Default is: BASICLIMITING = YES");
 fprintf(f, "%s\n","BASICLIMITING = YES");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Bandwidth limits in bytes per second. These denote the maximum");
 fprintf(f, "%s\n","# amounts GNUnet is allowed to use.");
 fprintf(f, "%s\n","# Defaults are: ");
 fprintf(f, "%s\n","# MAXNETUPBPSTOTAL	= 50000");
 fprintf(f, "%s\n","# MAXNETDOWNBPSTOTAL	= 50000");
 fprintf(f, "%s\n","MAXNETUPBPSTOTAL	= 50000");
 fprintf(f, "%s\n","MAXNETDOWNBPSTOTAL	= 50000");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Which CPU load can be tolerated (total, GNUnet will adapt if the");
 fprintf(f, "%s\n","# load goes up due to other processes). A value of 50 means that once");
 fprintf(f, "%s\n","# your 1 minute-load average goes over 50% non-idle, GNUnet will start");
 fprintf(f, "%s\n","# dropping packets until it goes under that threshold again.");
 fprintf(f, "%s\n","# Default is MAXCPULOAD		= 50");
 fprintf(f, "%s\n","MAXCPULOAD		= 50");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","###########################################");
 fprintf(f, "%s\n","# Options for the UDP transport layer.");
 fprintf(f, "%s\n","###########################################");
 fprintf(f, "%s\n","[UDP]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# To which port does GNUnet bind? Default is 2086 and there is usually");
 fprintf(f, "%s\n","# no reason to change that.");
 fprintf(f, "%s\n","PORT		= 2086");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# With this option, you can specify which networks you do NOT want to");
 fprintf(f, "%s\n","# connect to. Usually you will want to filter loopback (127.0.0.1,");
 fprintf(f, "%s\n","# misconfigured GNUnet hosts), virtual private networks, [add a class");
 fprintf(f, "%s\n","# C network here], 192.168.0.0, 172.16.0.0 and 10.0.0.0 (RFC");
 fprintf(f, "%s\n","# 1918). The format is IP/NETMASK where the IP is specified in");
 fprintf(f, "%s\n","# dotted-decimal and the netmask either in CIDR notation (/16) or in");
 fprintf(f, "%s\n","# dotted decimal (255.255.0.0). Several entries must be separated by a");
 fprintf(f, "%s\n","# semicolon, spaces are not allowed.  Notice that if your host is on a");
 fprintf(f, "%s\n","# private network like the above, you will have to configure your NAT");
 fprintf(f, "%s\n","# to allow incoming requests and you will want to modify this option.");
 fprintf(f, "%s\n","# The idea behind this option is not to discriminate against NAT users");
 fprintf(f, "%s\n","# but to ensure that hosts only attempt to connect to machines that");
 fprintf(f, "%s\n","# they have a chance to actually reach.  Of course, you could also use");
 fprintf(f, "%s\n","# it against known adversaries that have a small IP range at their");
 fprintf(f, "%s\n","# disposal :-) ");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Example (and default):");
 fprintf(f, "%s\n","# 127.0.0.1/8;172.16.0.0/12;192.168.0.0/16;10.0.0.0/255.0.0.0;");
 fprintf(f, "%s\n","BLACKLIST = 127.0.0.1/8;172.16.0.0/12;192.168.0.0/16;10.0.0.0/255.0.0.0;");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# The MTU to use. Do not use more than your OS");
 fprintf(f, "%s\n","# (and firewall) can support. Typically, your ");
 fprintf(f, "%s\n","# network-MTU - 28 is optimal, for ethernet, this");
 fprintf(f, "%s\n","# is 1472, the default. Do not use less than 1200.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The default is 1472, which is also used if you specify");
 fprintf(f, "%s\n","# nothing.");
 fprintf(f, "%s\n","MTU = 1472");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","###########################################");
 fprintf(f, "%s\n","# Options for the TCP transport layer.");
 fprintf(f, "%s\n","###########################################");
 fprintf(f, "%s\n","[TCP]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# To which port does GNUnet bind? Default is 2086 and there is usually");
 fprintf(f, "%s\n","# no reason to change that.  Make sure that this port does not");
 fprintf(f, "%s\n","# conflict with the port for GNUnet clients (section NETWORK), which");
 fprintf(f, "%s\n","# defaults to 2087.  ");
 fprintf(f, "%s\n","PORT = 2086");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# With this option, you can specify which networks you do NOT want to");
 fprintf(f, "%s\n","# connect to. Usually you will want to filter loopback (127.0.0.1,");
 fprintf(f, "%s\n","# misconfigured GNUnet hosts), virtual private networks, [add a class");
 fprintf(f, "%s\n","# C network here], 192.168.0.0, 172.16.0.0 and 10.0.0.0 (RFC");
 fprintf(f, "%s\n","# 1918). The format is IP/NETMASK where the IP is specified in");
 fprintf(f, "%s\n","# dotted-decimal and the netmask either in CIDR notation (/16) or in");
 fprintf(f, "%s\n","# dotted decimal (255.255.0.0). Several entries must be separated by a");
 fprintf(f, "%s\n","# semicolon, spaces are not allowed.  Notice that if your host is on a");
 fprintf(f, "%s\n","# private network like the above, you will have to configure your NAT");
 fprintf(f, "%s\n","# to allow incoming requests and you will want to modify this option.");
 fprintf(f, "%s\n","# The idea behind this option is not to discriminate against NAT users");
 fprintf(f, "%s\n","# but to ensure that hosts only attempt to connect to machines that");
 fprintf(f, "%s\n","# they have a chance to actually reach.  Of course, you could also use");
 fprintf(f, "%s\n","# it against known adversaries that have a small IP range at their");
 fprintf(f, "%s\n","# disposal :-)");
 fprintf(f, "%s\n","# Example (and default):");
 fprintf(f, "%s\n","# BLACKLIST = 127.0.0.1/8;192.168.0.0/16;10.0.0.0/255.0.0.0; ");
 fprintf(f, "%s\n","BLACKLIST = 127.0.0.1/8;192.168.0.0/16;10.0.0.0/255.0.0.0;");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# The MTU to use (TCP is stream oriented, so we are pretty free to");
 fprintf(f, "%s\n","# choose what we want, but note that larger MTUs mean more noise if");
 fprintf(f, "%s\n","# traffic is low). Do not use less than 1200.  Default is 1460.");
 fprintf(f, "%s\n","MTU = 1460");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","###############################################");
 fprintf(f, "%s\n","# Options for NAT transport");
 fprintf(f, "%s\n","###############################################");
 fprintf(f, "%s\n","[NAT]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Is this machine behind a NAT that does not allow");
 fprintf(f, "%s\n","# connections from the outside to the GNUnet port?");
 fprintf(f, "%s\n","# (if you can configure the NAT box to allow");
 fprintf(f, "%s\n","# direct connections from other peers, set this");
 fprintf(f, "%s\n","# to NO).  Set this only to YES if other peers");
 fprintf(f, "%s\n","# cannot contact you directly via TCP or UDP.");
 fprintf(f, "%s\n","# If you set this to YES, you should also set the");
 fprintf(f, "%s\n","# TCP port to '0' and disable UDP to indicate that you");
 fprintf(f, "%s\n","# cannot accept inbound connections.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Default: NO");
 fprintf(f, "%s\n","LIMITED = NO");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","##########################################");
 fprintf(f, "%s\n","# IPv6 transports, don't bother unless you");
 fprintf(f, "%s\n","# want to use IPv6.");
 fprintf(f, "%s\n","##########################################");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","[UDP6]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Default port is 2088 and MTU is 1452.");
 fprintf(f, "%s\n","PORT = 2088");
 fprintf(f, "%s\n","# BLACKLIST = ");
 fprintf(f, "%s\n","MTU = 1452");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","[TCP6]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Default port is 2088 and MTU is 1440.");
 fprintf(f, "%s\n","PORT = 2088");
 fprintf(f, "%s\n","# BLACKLIST = ");
 fprintf(f, "%s\n","MTU = 1440");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","[HTTP]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Default port is 1080 and MTU is 1400.");
 fprintf(f, "%s\n","PORT = 1080");
 fprintf(f, "%s\n","# BLACKLIST =");
 fprintf(f, "%s\n","MTU = 1400");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","###############################################");
 fprintf(f, "%s\n","# Options for SMTP transport");
 fprintf(f, "%s\n","###############################################");
 fprintf(f, "%s\n","[SMTP]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# E-mail address to use to receive messages.  Do not specify anything");
 fprintf(f, "%s\n","# if you do not want to allow SMTP as a receiver protocol; you can");
 fprintf(f, "%s\n","# still *send* email to establish connections in that case.  Example:");
 fprintf(f, "%s\n","# EMAIL = foo@bar.com");
 fprintf(f, "%s\n","# EMAIL =");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# MTU for the E-mail. How large should the E-mails be that we send");
 fprintf(f, "%s\n","# out? Default is 65536 (bytes).");
 fprintf(f, "%s\n","MTU = 65536");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Port of the SMTP server for outbound mail.  If not specified, the");
 fprintf(f, "%s\n","# TCP/SMTP entry from /etc/services is consulted.  Default is 25.");
 fprintf(f, "%s\n","PORT = 25");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Hostname of the SMTP server. Default is \"localhost\".");
 fprintf(f, "%s\n","SERVER = localhost");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Hostname of the sender host to use in the HELO message of the SMTP");
 fprintf(f, "%s\n","# protocol (not to be confused with the HELO in the GNUnet p2p");
 fprintf(f, "%s\n","# protocol). Pick a hostname that works for your SMTP server. This");
 fprintf(f, "%s\n","# hostname has nothing to do with the hostname of the SMTP server or");
 fprintf(f, "%s\n","# your E-mail sender address (though those names should work in most");
 fprintf(f, "%s\n","# cases). In fact, it often does not even have to exist as a real");
 fprintf(f, "%s\n","# machine. Example: \"myhost.example.com\"");
 fprintf(f, "%s\n","SENDERHOSTNAME = myhost.example.com");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Filter-line to use in the E-mail header. This filter will be");
 fprintf(f, "%s\n","# included in the GNUnet-generated E-mails and should be used to");
 fprintf(f, "%s\n","# filter out GNUnet traffic from the rest of your E-mail. Make sure");
 fprintf(f, "%s\n","# that the filter you choose is highly unlikely to occur in any other");
 fprintf(f, "%s\n","# message.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Examples:");
 fprintf(f, "%s\n","# FILTER = \"X-mailer: myGNUnetmail\"");
 fprintf(f, "%s\n","# FILTER = \"Subject: foobar5252\"");
 fprintf(f, "%s\n","FILTER = \"X-mailer: 590N\"");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Name of the pipe via which procmail sends the filtered E-mails to");
 fprintf(f, "%s\n","# the node.  Default is /tmp/gnunet.smtp");
 fprintf(f, "%s\n","PIPE = /tmp/gnunet.smtp");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","################################################");
 fprintf(f, "%s\n","# Options for anonymous filesharing (AFS).");
 fprintf(f, "%s\n","################################################");
 fprintf(f, "%s\n","[AFS]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# How much disk space (MB) is GNUnet allowed to use for anonymous file");
 fprintf(f, "%s\n","# sharing?  This does not take indexed files into account, only the");
 fprintf(f, "%s\n","# space directly used by GNUnet is accounted for.  GNUnet will gather");
 fprintf(f, "%s\n","# content from the network if the current space-consumption is below");
 fprintf(f, "%s\n","# the number given here (and if content migration is allowed below).");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# IMPORTANT:");
 fprintf(f, "%s\n","# Note that if you change the quota, you need to run gnunet-convert,");
 fprintf(f, "%s\n","# otherwise your databases will be inconsistent and gnunetd will");
 fprintf(f, "%s\n","# refuse to work.  Default is 1024 (1 GB)");
 fprintf(f, "%s\n","DISKQUOTA 	= 1024");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Which database type should be used for content? Valid types are");
 fprintf(f, "%s\n","# \"gdbm\", \"mysql\", \"tdb\" and \"directory\". Specified type must have");
 fprintf(f, "%s\n","# been available at compile time. \"directory\" is available on all");
 fprintf(f, "%s\n","# systems but typically uses more space and can also be slower.  mysql");
 fprintf(f, "%s\n","# will require some additional setup of the database.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Note that if you change the databaset type, you need to run");
 fprintf(f, "%s\n","# gnunet-convert, otherwise your databases will be");
 fprintf(f, "%s\n","# inconsistent (and gnunetd will refuse to work).  Default is gdbm.");
 fprintf(f, "%s\n","DATABASETYPE    = \"gdbm\"");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# What degree of receiver anonymity is required?  If set to 0, GNUnet");
 fprintf(f, "%s\n","# will try to download the file as fast as possible without any");
 fprintf(f, "%s\n","# additional slowdown by the anonymity code. Note that you will still");
 fprintf(f, "%s\n","# have a fair degree of anonymity depending on the current network");
 fprintf(f, "%s\n","# load and the power of the adversary. The download is still unlikely");
 fprintf(f, "%s\n","# to be terribly fast since the sender may have requested");
 fprintf(f, "%s\n","# sender-anonymity and since in addition to that, GNUnet will still do");
 fprintf(f, "%s\n","# the anonymous routing.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# This option can be used to limit requests further than that. In");
 fprintf(f, "%s\n","# particular, you can require GNUnet to receive certain amounts of");
 fprintf(f, "%s\n","# traffic from other peers before sending your queries. This way, you");
 fprintf(f, "%s\n","# can gain very high levels of anonymity - at the expense of much more");
 fprintf(f, "%s\n","# traffic and much higher latency. So set it only if you really");
 fprintf(f, "%s\n","# believe you need it.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The definition of ANONYMITY-RECEIVE is the following: ");
 fprintf(f, "%s\n","#  If the value v # is < 1000, it means that if GNUnet routes n bytes");
 fprintf(f, "%s\n","#  of messages from # foreign peers, it may originate n/v bytes of");
 fprintf(f, "%s\n","#  queries in the same # time-period.  The time-period is twice the");
 fprintf(f, "%s\n","#  average delay that GNUnet # deferrs forwarded queries.");
 fprintf(f, "%s\n","# ");
 fprintf(f, "%s\n","#  If the value v is >= 1000, it means that if GNUnet routes n bytes");
 fprintf(f, "%s\n","#  of QUERIES from at least (v % 1000) peers, it may originate");
 fprintf(f, "%s\n","#  n/v/1000 bytes of queries in the same time-period.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The default is 0 and this should be fine for most users. Also notice");
 fprintf(f, "%s\n","# that if you choose values above 1000, you may end up having no");
 fprintf(f, "%s\n","# throughput at all, especially if many of your fellow GNUnet-peers do");
 fprintf(f, "%s\n","# the same.");
 fprintf(f, "%s\n","ANONYMITY-RECEIVE = 0");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# You can also request a certain degree of anonymity for the files and");
 fprintf(f, "%s\n","# blocks that you are sharing. In this case, only a certain faction of");
 fprintf(f, "%s\n","# the traffic that you are routing will be allowed to be replies that");
 fprintf(f, "%s\n","# originate from your machine. Again, 0 means unlimited.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The semantics of ANONYMITY-SEND are equivalent to the semantics of");
 fprintf(f, "%s\n","# ANONYMITY-RECEIVE.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The default is 0 and this should be fine for most users.");
 fprintf(f, "%s\n","ANONYMITY-SEND = 0");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Should we participate in content migration?  If you say yes here,");
 fprintf(f, "%s\n","# GNUnet will migrate content to your server, and you will not be able");
 fprintf(f, "%s\n","# to control what data is stored on your machine.  This option has");
 fprintf(f, "%s\n","# advantages and disadvantages.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# If you activate it, you can claim for *all* the non-indexed (-n to");
 fprintf(f, "%s\n","# gnunet-insert) content that you did not know what it was even if an");
 fprintf(f, "%s\n","# adversary takes control of your machine.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# If you do not activate it, it is obvious that you have knowledge of");
 fprintf(f, "%s\n","# all the content that is hosted on your machine and thus can be");
 fprintf(f, "%s\n","# considered liable for it.  ");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# So if you think that the legal system in your country has gone");
 fprintf(f, "%s\n","# postal, you may want to set it to \"NO\" and make sure that the");
 fprintf(f, "%s\n","# content you put on your machine does not get you into too much");
 fprintf(f, "%s\n","# trouble if an adversary takes control of your machine.  If you think");
 fprintf(f, "%s\n","# that you're safe if you host content that you don't know anything");
 fprintf(f, "%s\n","# about (like an ISP) or that you don't have to fear prosecution");
 fprintf(f, "%s\n","# no-matter-what, turn it to YES, which will also improve GNUnet's");
 fprintf(f, "%s\n","# performance and thereby your results.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Note that as long as the adversary is not really powerful (e.g. can");
 fprintf(f, "%s\n","# not take control of your machine), GNUnet's build-in anonymity");
 fprintf(f, "%s\n","# mechanisms should protect you from being singled out easily.");
 fprintf(f, "%s\n","# ");
 fprintf(f, "%s\n","# Currently, activating active migration can cause some problems when");
 fprintf(f, "%s\n","# the database is getting full (gdbm reorganization can take very,");
 fprintf(f, "%s\n","# very long and make GNUnet look like it hangs for that time). Thus if");
 fprintf(f, "%s\n","# you turn it on, you may want to disable it after you hit the");
 fprintf(f, "%s\n","# quota. A better content management system should solve this problem");
 fprintf(f, "%s\n","# in the near future... [at the time of GNUnet 0.6.1c, the MySQL ");
 fprintf(f, "%s\n","# database module already works well even if the db is full.]");
 fprintf(f, "%s\n","# Default is YES.");
 fprintf(f, "%s\n","ACTIVEMIGRATION = YES");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Where to store the AFS related data (content, etc)?");
 fprintf(f, "%s\n","AFSDIR          = $GNUNETD_HOME/data/afs/");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Where to store indexed files (NEW!)");
 fprintf(f, "%s\n","# Note that you MUST not copy files directly to this");
 fprintf(f, "%s\n","# directory.  gnunet-insert (or gnunet-gtk) will copy");
 fprintf(f, "%s\n","# the files that you index to this directory.  With the");
 fprintf(f, "%s\n","# -l option you instead create a link (if gnunetd and");
 fprintf(f, "%s\n","# gnunet-insert run on the same machine) instead.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# The QUOTA option does NOT apply for this directory.");
 fprintf(f, "%s\n","# To limit how much can be placed in this directory");
 fprintf(f, "%s\n","# set the option INDEX-QUOTA.  Files that are merely");
 fprintf(f, "%s\n","# linked do not count towards the quota.");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# If you uncomment this option gnunetd will refuse");
 fprintf(f, "%s\n","# content indexing requests (insertion will still be");
 fprintf(f, "%s\n","# possible).");
 fprintf(f, "%s\n","#");
 fprintf(f, "%s\n","# Note that files indexed with GNUnet before Version");
 fprintf(f, "%s\n","# 0.6.2 were not moved/linked to this directory.  But that");
 fprintf(f, "%s\n","# should not cause any immediate problems (the files");
 fprintf(f, "%s\n","# will continue to be downloadable).  What will be");
 fprintf(f, "%s\n","# impossible is unindexing these files with");
 fprintf(f, "%s\n","# gnunet-delete and GNUnet >= 0.6.2. ");
 fprintf(f, "%s\n","# Default is $GNUNETD_HOME/data/shared/");
 fprintf(f, "%s\n","INDEX-DIRECTORY = $GNUNETD_HOME/data/shared/");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Indexing quota.  Default is 8192.");
 fprintf(f, "%s\n","INDEX-QUOTA = 8192");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","#######################################");
 fprintf(f, "%s\n","# Experimental GDBM options");
 fprintf(f, "%s\n","#######################################");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","[GDBM]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Use experimental settings for managing");
 fprintf(f, "%s\n","# free blocks in gdbm.  Default is YES!");
 fprintf(f, "%s\n","EXPERIMENTAL = YES");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# This option allows avoiding gdbm database reorganization");
 fprintf(f, "%s\n","# on startup.  It should definitely only be used together");
 fprintf(f, "%s\n","# with the experimental gdbm free blocks option.  Nevertheless,");
 fprintf(f, "%s\n","# the option has not been tested extensively yet, so to be");
 fprintf(f, "%s\n","# safe it should be set to 'YES' (do reorganize).  Default");
 fprintf(f, "%s\n","# is 'YES'.");
 fprintf(f, "%s\n","REORGANIZE = YES");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","#######################################");
 fprintf(f, "%s\n","# TESTBED (experimental!)");
 fprintf(f, "%s\n","#######################################");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","[TESTBED]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Where should we register the testbed service?");
 fprintf(f, "%s\n","# Default is \"http://www.ovmj.org/GNUnet/testbed/\"");
 fprintf(f, "%s\n","REGISTERURL = \"http://www.ovmj.org/GNUnet/testbed/\"");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Is the testbed operator allowed to load and");
 fprintf(f, "%s\n","# unload modules? (somewhat of a security risk!)");
 fprintf(f, "%s\n","# Default is NO.");
 fprintf(f, "%s\n","ALLOW_MODULE_LOADING = NO");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Where should file-uploads go?");
 fprintf(f, "%s\n","# Default is $GNUNETD_HOME/testbed");
 fprintf(f, "%s\n","UPLOAD-DIR = $GNUNETD_HOME/testbed");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Login-name for SSH-tunnel (for secure testbed");
 fprintf(f, "%s\n","# connections).  Without login name the testbed-server");
 fprintf(f, "%s\n","# will try to make a direct TCP connection to the");
 fprintf(f, "%s\n","# application port (default: 2087).");
 fprintf(f, "%s\n","# LOGIN = ");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","########################################");
 fprintf(f, "%s\n","# DHT (experimental)");
 fprintf(f, "%s\n","########################################");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","[DHT]");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Number of buckets to use (determines memory requirements)");
 fprintf(f, "%s\n","# Default (and maximum) is 160.");
 fprintf(f, "%s\n","BUCKETCOUNT = 160");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","# Amount of memory (in bytes) to use for the master table");
 fprintf(f, "%s\n","# (table that caches table-to-peer mappings).");
 fprintf(f, "%s\n","# Default is 65536.");
 fprintf(f, "%s\n","MASTER-TABLE-SIZE = 65536");
 fprintf(f, "%s\n","");
 fprintf(f, "%s\n","");
}

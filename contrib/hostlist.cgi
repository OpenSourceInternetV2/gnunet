#!/bin/sh
# This is a CGI script to generate the host list on-demand.
# by Michael Wensley, with minor improvements by Christian Grothoff
echo -ne "Content-Type: application/octet-stream\r\n\r\n"
cat /var/lib/GNUnet/data/hosts/*.{6,8,12,17,23,25}

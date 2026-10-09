#!/bin/sh

# Configure ARPs
echo 1 | tee /proc/sys/net/ipv4/conf/*/arp_ignore


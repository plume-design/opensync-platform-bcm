#!/bin/sh

# Increase udp conntrack timeout to facilitate collection of conntrack stats by FCM
echo 30 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout
echo 600 > /proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream

# Enable conntrack_helper
echo 1 > /proc/sys/net/netfilter/nf_conntrack_helper

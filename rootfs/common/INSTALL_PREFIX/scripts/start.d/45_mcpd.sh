#!/bin/sh

# mcpd should always be running and is expected
# to be started from /etc/init.d/mcpd.sh
# Instead of stopping and restarting
# the config is reset to empty and reloaded

cat /dev/null > /var/mcpd.conf
mcpctl reload


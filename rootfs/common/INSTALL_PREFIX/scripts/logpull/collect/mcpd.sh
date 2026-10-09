#!/bin/sh

. "$LOGPULL_LIB"

MCPD_CONFIG_FILE=/var/mcpd.conf

collect_mcpd_log()
{
        collect_cmd  /bin/mcpctl allinfo
        collect_file  $MCPD_CONFIG_FILE
}


collect_mcpd_log

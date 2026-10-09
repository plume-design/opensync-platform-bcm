#!/bin/sh
# {# jinja-parse #}

case "$1" in
	start)
		echo "Starting BCM debug_monitor..."

		# debug_monitor prerequisites
		mkdir -p /tmp/dm/
		mkdir -p {{INSTALL_PREFIX}}/log_archive/debug_monitor/

		debug_monitor {{INSTALL_PREFIX}}/log_archive/debug_monitor/ 2>&1 | logger -t debug_monitor &
		exit 0
		;;

	*)
		echo "$0: unrecognized or unsupported option $1"
		exit 1
		;;

esac

